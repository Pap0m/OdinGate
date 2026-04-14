// package NBD
package main

import "core:encoding/endian"
import "core:os"
import "core:net"
import "core:fmt"
import "core:c"

when ODIN_OS == .Linux {
	foreign import openssl { "system:ssl", "system:crypto" }
} else when ODIN_OS == .Windows {
	foreign import openssl "libssl.lib"
}

SSL_CTX :: struct {}
SSL     :: struct {}
SSL_METHOD :: struct {}

@(default_calling_convention="c")
foreign openssl {
	TLS_server_method :: proc() -> ^SSL_METHOD ---
	SSL_CTX_new :: proc(method: ^SSL_METHOD) -> ^SSL_CTX ---
	SSL_CTX_free :: proc(ctx: ^SSL_CTX) ---
	SSL_new :: proc(ctx: ^SSL_CTX) -> ^SSL ---
	SSL_free :: proc(ssl: ^SSL) ---
	SSL_set_fd :: proc(ssl: ^SSL, fd: c.int) -> c.int ---
	SSL_CTX_use_certificate_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_use_PrivateKey_file :: proc(ctx: ^SSL_CTX, file: cstring, type: c.int) -> c.int ---
	SSL_CTX_check_private_key :: proc(ctx: ^SSL_CTX) -> c.int ---
	SSL_accept :: proc(ssl: ^SSL) -> c.int ---
    SSL_read  :: proc(ssl: ^SSL, buf: rawptr, num: c.int) -> c.int ---
	SSL_write :: proc(ssl: ^SSL, buf: rawptr, num: c.int) -> c.int ---
}

SSL_FILETYPE_PEM : c.int : 1

Connection :: struct {
	socket: net.TCP_Socket,
	ssl_handle: ^SSL,
	is_tls: bool
}

NBD_MAGIC          : u64 : 0x4e42444d41474943
NBD_OPTS_MAGIC     : u64 : 0x49484156454F5054
NBD_REP_MAGIC      : u64 : 0x0003e889045565a9
// Request types
NBD_CMD_READ  : u16 : 0
NBD_CMD_WRITE : u16 : 1
NBD_CMD_DISC  : u16 : 2  // disconnect
NBD_CMD_FLUSH : u16 : 3
NBD_CMD_TRIM  : u16 : 4

// Define Server Flags
Server_Flag :: enum u16 {
    FIXED_NEWSTYLE = 0, // Bit 0
    NO_ZEROES      = 1, // Bit 1
}
Server_Flags :: bit_set[Server_Flag; u16]

// Define Client Flags
Client_Flag :: enum u32 {
    C_FIXED_NEWSTYLE = 0,
    C_NO_ZEROES      = 1,
}
Client_Flags :: bit_set[Client_Flag; u32]

Client_Opts :: enum u32 {
	// Old way to choose export
	NBD_OPT_EXPORT_NAME = 1,
	// Soft disconnect
	NBD_OPT_ABORT = 2,
	// List of available exports
	NBD_OPT_LIST = 3,
	// Switch to TLS
	NBD_OPT_STARTTLS = 4,
	// Query
	NBD_OPT_INFO = 5,
	// Select export and finish negotiation
	NBD_OPT_GO = 6,
	// Structured headers
	NBD_OPT_STRUCTURED_REPLY = 7
}

Server_Rep :: enum  u32 {
	// Success
	NBD_REP_ACK = 1,
	// Response for `LIST`
	NBD_REP_SERVER = 2,
	// Response for `INFO` or `GO`
	NBD_REP_INFO = 3,
	// Don't support that option
	NBD_REP_ERR_UNSUP = 0x80000001,
	// Don't allowed to do that
	NBD_REP_ERR_POLICY = 0x80000002,
	// Garbage data
	NBD_REP_ERR_INVALID = 0x80000003,
	// TLS is mandatory
	NBD_REP_ERR_TLS_REQ = 0x80000005,
	// Export name not found
	NBD_REP_ERR_UNKNOWN = 0x80000006,
	// Server is shutting down
	NBD_REP_ERR_SHUTDOWN = 0x80000007,
	// Invalid block size
	NBD_REP_ERR_BLOCK_SIZE = 0x80000008
}

send_be :: proc(conn: ^Connection, data: $T) -> bool {
	buffer : [size_of(T)]u8
    val := data

    when size_of(T) == 8 {
        endian.put_u64(buffer[:], .Big, u64(val))
    } else when size_of(T) == 4 {
        endian.put_u32(buffer[:], .Big, u32(val))
    } else when size_of(T) == 2 {
        endian.put_u16(buffer[:], .Big, u16(val))
    } else when size_of(T) == 1 {
        buffer[0] = u8(val)
    }

	bytes_sent: i32
    if conn.is_tls {
        bytes_sent = SSL_write(conn.ssl_handle, &buffer[0], size_of(T))
    } else {
        n, _ := net.send_tcp(conn.socket, buffer[:])
        bytes_sent = i32(n)
    }
    return bytes_sent == size_of(T)
}

read_exact :: proc(conn: ^Connection, buf: []u8) -> bool {
	if conn.is_tls {
        res := SSL_read(conn.ssl_handle, &buf[0], i32(len(buf)))
        return res == i32(len(buf))
    } else {
        n, err := net.recv_tcp(conn.socket, buf)
        return err == nil && n == len(buf)
    }
}

handle_handshake :: proc(conn: ^Connection, ctx: ^SSL_CTX) {
	// send magic numbers
	if !send_be(conn, NBD_MAGIC) || !send_be(conn, NBD_OPTS_MAGIC) {
		fmt.eprintln("Failed to send initial magics")
        return
	}
		
	// send server flags
	server_flags := Server_Flags{.FIXED_NEWSTYLE, .NO_ZEROES}
	if !send_be(conn, u16(transmute(u16)server_flags)) { 
	    fmt.eprintln("Failed to send server flags")
	    return
	}

	client_flags_buffer : [4]u8
	rev_err := read_exact(conn, client_flags_buffer[:])
	if !rev_err {
        fmt.eprintln("Failed to receive client flags")
        return
    }
    client_flags, _ := endian.get_u32(client_flags_buffer[:], .Big)
    fmt.printf("Client connected with flags: %8x\n", client_flags)

    // client supports Fixed Newstyle?
    if (client_flags & 1) == 0 {
    	fmt.eprintln("Client does not support fixed newstyle. Dropping.")
        return
    }

    // option negotiation
    handle_options(conn, ctx)
}

handle_options :: proc(conn: ^Connection, ctx: ^SSL_CTX) {
	for {
		Header :: struct #packed {
            magic: u64,
            opt:   u32,
            len:   u32,
        }

        head: Header
        header_buf := transmute([size_of(Header)]u8)head
        if !read_exact(conn, header_buf[:]) do break

        // Convert to Host Endian
        head.magic, _ = endian.get_u64(header_buf[0:8], .Big)
        head.opt, _   = endian.get_u32(header_buf[8:12], .Big)
        head.len, _   = endian.get_u32(header_buf[12:16], .Big)

        if head.magic != NBD_OPTS_MAGIC do break

        if head.len > 0 {
            payload := make([]u8, head.len)
            read_exact(conn, payload)
            // Process payload if needed
            delete(payload) 
        }

        fmt.printf("Received Option: %d (len: %d)\n", head.opt, head.len)

        // REQUIRE TLS only for options that are NOT:
        //   - STARTTLS (4): client is requesting the upgrade
        //   - ABORT    (2): client wants to disconnect gracefully
        //   - INFO     (5): nbd-client sends this after wrapping TCP in TLS externally
        //   - GO       (6): same – client already negotiated TLS at the TCP layer
        if !conn.is_tls && head.opt != 4 && head.opt != 2 && head.opt != 5 && head.opt != 6 {
            fmt.printf("Option %d rejected: TLS required\n", head.opt)
            send_reply(conn, head.opt, .NBD_REP_ERR_TLS_REQ)
            continue
        }
		
        switch head.opt {
        case 4: // NBD_OPT_STARTTLS
            fmt.println("Client requested TLS. Acknowledging...")
            send_reply(conn, head.opt, .NBD_REP_ACK)
            
            if start_tls_handshake(conn, ctx) {
                fmt.println("--- Connection is now ENCRYPTED ---")
            } else {
                return 
            }

        case 5: // NBD_OPT_INFO
		    fmt.println("Client requested INFO. Sending export info...")
		    // send_export_info(conn, head.opt)
		    // loop continues, client can send more options

		case 6: // NBD_OPT_GO
		    fmt.println("Client requested GO. Entering transmission...")
		    // send_export_info(conn, head.opt)
		    // handle_transmission(conn, buff)
		    return

        case 2: // ABORT
            send_reply(conn, head.opt, .NBD_REP_ACK)
            return

        case:
            fmt.printf("Option %d not implemented. Sending UNSUP.\n", head.opt)
            send_reply(conn, head.opt, .NBD_REP_ERR_UNSUP)
        }
	}
}

start_tls_handshake :: proc(con: ^Connection, ctx: ^SSL_CTX) -> bool {
	// create ssl object
	s := SSL_new(ctx)
	if s == nil do return false

	/// bind socket fd to ssl
	fd := c.int(con.socket)
	SSL_set_fd(s, fd)


	// perform the handshake
	if SSL_accept(s) <= 0 {
		fmt.println("TLS Handshake failed")
        SSL_free(s)
        return false
	}

	con.ssl_handle = s
	con.is_tls = true
	fmt.println("TLS Handshake successful!")
	return true
}

send_reply :: proc(conn: ^Connection, opt: u32, reply_type: Server_Rep) {
    // Reply Header: Magic(8), Opt(4), ReplyType(4), DataLen(4)
    send_be(conn, NBD_REP_MAGIC)
    send_be(conn, opt)
    send_be(conn, reply_type)
    send_be(conn, u32(0)) // No data for basic ACK
}

run_nbd_server :: proc() {
	method := TLS_server_method()
	global_ssl_ctx := SSL_CTX_new(method)
	defer SSL_CTX_free(global_ssl_ctx)

	if SSL_CTX_use_certificate_file(global_ssl_ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 do return 
    if SSL_CTX_use_PrivateKey_file(global_ssl_ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 do return

	// reference: https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
	// A client who wants to use the new style negotiation SHOULD connect on the IANA-reserved port for NBD, 10809
	// NOTE: Only use Newstyle Negotiation
	endpoint := net.Endpoint{ net.IP4_Address{127, 0, 0, 1}, 10809 }
	listener, err := net.listen_tcp(endpoint)
	if err != nil {
		fmt.eprintln("Error starting server: ", err)
		os.exit(1)
	}
	defer net.close(listener)

	// reference: https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
	// to eliminate artificial delays caused by waiting for an ACK 
	// response when a large message payload spans multiple network packets
	err = net.set_option(listener, .TCP_Nodelay, true)
	if err != nil {
		fmt.eprintln("Error setting TCP_Nodelay: ", err)
		os.exit(1)
	}

	fmt.println("Server listening on ", net.address_to_string(endpoint.address), ":", endpoint.port, sep = "")

	for {
		client_socket, _, accept_err := net.accept_tcp(listener)
		if accept_err != nil {
			fmt.eprintln("Error accepting connection: ", accept_err)
			continue
		}
		conn := Connection{
			socket = client_socket,
			ssl_handle = nil,
			is_tls = false
		}

		handle_handshake(&conn, global_ssl_ctx)

		// cleanup
		if conn.ssl_handle != nil do SSL_free(conn.ssl_handle)
		net.close(conn.socket)
	}
}



main :: proc() {
	run_nbd_server()
}
