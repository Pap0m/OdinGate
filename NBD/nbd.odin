// package NBD
package main

import "core:encoding/endian"
import "core:os"
import "core:net"
import "core:fmt"
import "core:c"

// --- OpenSSL Foreign Imports ---
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

// --- NBD Constants & Magics ---
NBD_MAGIC          : u64 : 0x4e42444d41474943 // 'NBDMAGIC'
NBD_OPTS_MAGIC     : u64 : 0x49484156454F5054 // 'IHAVEOPT'
NBD_REP_MAGIC      : u64 : 0x0003e889045565a9 // Negotiation phase magic
NBD_REQUEST_MAGIC  : u32 : 0x25609513         // Transmission request magic
NBD_REPLY_MAGIC    : u32 : 0x67446698         // Transmission reply magic

// --- Enums & Bitsets ---
NBD_Opt :: enum u32 {
    EXPORT_NAME      = 1,
    ABORT            = 2,
    LIST             = 3,
    STARTTLS         = 5,
    INFO             = 6,
    GO               = 7,
    STRUCTURED_REPLY = 8,
}

Server_Rep :: enum u32 {
    ACK             = 1,
    SERVER          = 2,
    INFO            = 3,
    ERR_UNSUP       = 0x80000001,
    ERR_POLICY      = 0x80000002,
    ERR_INVALID     = 0x80000003,
    ERR_TLS_REQ     = 0x80000005,
    ERR_UNKNOWN     = 0x80000006,
    ERR_SHUTDOWN    = 0x80000007,
    ERR_BLOCK_SIZE  = 0x80000008,
}

NBD_Cmd :: enum u16 {
    READ  = 0,
    WRITE = 1,
    DISC  = 2,
    FLUSH = 3,
}

Transmission_Error :: enum u32 {
    NONE    = 0,
    EPERM   = 1,
    EIO     = 5,
    ENOMEM  = 12,
    EINVAL  = 22,
    ENOSPC  = 28,
}

Transmission_Flag :: enum u16 {
    HAS_FLAGS = 0, // Bit 0
    READ_ONLY = 1, // Bit 1
}
Transmission_Flags :: bit_set[Transmission_Flag; u16]

Server_Flag :: enum u16 {
    FIXED_NEWSTYLE = 0,
    NO_ZEROES      = 1,
}
Server_Flags :: bit_set[Server_Flag; u16]

NBD_INFO_EXPORT : u16 : 0

// --- Core Structures ---
Connection :: struct {
	socket: net.TCP_Socket,
	ssl_handle: ^SSL,
	is_tls: bool,
}

Negotiation_Reply :: struct {
    opt:  NBD_Opt,
    type: Server_Rep,
}

Transmission_Reply :: struct {
    error:  Transmission_Error,
    cookie: u64,
}

Reply_Data :: union {
    Negotiation_Reply,
    Transmission_Reply,
}

// --- Protocol Helpers ---

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

// Generic reply handler for both Negotiation and Transmission phases
send_reply :: proc(conn: ^Connection, reply: Reply_Data, data: []u8 = nil) -> bool {
	switch r in reply {
    case Negotiation_Reply:
        // Negotiation Header: Magic(8), Opt(4), ReplyType(4), DataLen(4)
        if !send_be(conn, NBD_REP_MAGIC)        do return false
        if !send_be(conn, u32(r.opt))           do return false
        if !send_be(conn, u32(r.type))          do return false
        if !send_be(conn, u32(len(data)))       do return false

    case Transmission_Reply:
        // Simple Transmission Header: Magic(4), Error(4), Cookie(8)
        if !send_be(conn, NBD_REPLY_MAGIC)      do return false
        if !send_be(conn, u32(r.error))         do return false
        if !send_be(conn, r.cookie)             do return false
    }

    if len(data) > 0 {
        bytes_sent: i32
        if conn.is_tls {
            bytes_sent = SSL_write(conn.ssl_handle, &data[0], i32(len(data)))
        } else {
            n, _ := net.send_tcp(conn.socket, data)
            bytes_sent = i32(n)
        }
        return bytes_sent == i32(len(data))
    }
    return true
}

// --- Handshake & Options Phase ---

handle_handshake :: proc(conn: ^Connection, ctx: ^SSL_CTX) {
    // Initial Handshake Magics
	if !send_be(conn, NBD_MAGIC) || !send_be(conn, NBD_OPTS_MAGIC) {
        return
	}
	
    // Server Flags: FIXED_NEWSTYLE and NO_ZEROES
	server_flags := Server_Flags{.FIXED_NEWSTYLE, .NO_ZEROES}
	if !send_be(conn, u16(transmute(u16)server_flags)) { 
	    return
	}

    // Receive Client Flags
	client_flags_buffer : [4]u8
	if !read_exact(conn, client_flags_buffer[:]) do return
    
    client_flags, _ := endian.get_u32(client_flags_buffer[:], .Big)
    if (client_flags & 1) == 0 {
        fmt.println("Client does not support fixed newstyle.")
        return
    }

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

        head.magic, _ = endian.get_u64(header_buf[0:8], .Big)
        head.opt, _   = endian.get_u32(header_buf[8:12], .Big)
        head.len, _   = endian.get_u32(header_buf[12:16], .Big)

        if head.magic != NBD_OPTS_MAGIC do break
        
        opt := NBD_Opt(head.opt)
        fmt.printf("Received Option: %d (len: %d)\n", head.opt, head.len)

        // Read and discard option data for now (or handle specifically if needed)
        if head.len > 0 {
            temp_buf := make([]u8, head.len)
            defer delete(temp_buf)
            read_exact(conn, temp_buf)
        }

        // Enforce TLS if required
        if !conn.is_tls && opt != .STARTTLS && opt != .ABORT && opt != .INFO && opt != .GO {
            send_reply(conn, Negotiation_Reply{opt = opt, type = .ERR_TLS_REQ})
            continue
        }
		
        #partial switch opt {
		case .STARTTLS:
            fmt.println("Client requested TLS. Acknowledging...")
		    send_reply(conn, Negotiation_Reply{opt = .STARTTLS, type = .ACK})
		    start_tls_handshake(conn, ctx)

		case .INFO, .GO:
		    if !conn.is_tls {
		        send_reply(conn, Negotiation_Reply{opt = opt, type = .ERR_TLS_REQ})
		    } else {
                fmt.println("Handling GO/INFO export info")
		        send_export_info(conn, opt)
		        if opt == .GO {
                    fmt.println("Entering transmission phase...")
                    handle_transmission(conn)
                    return 
                }
		    }

		case .ABORT:
		    send_reply(conn, Negotiation_Reply{opt = .ABORT, type = .ACK})
		    return
        
        case:
            send_reply(conn, Negotiation_Reply{opt = opt, type = .ERR_UNSUP})
		}
	}
}

send_export_info :: proc(conn: ^Connection, opt: NBD_Opt) {
    // Layout for NBD_INFO_EXPORT: u16 (type), u64 (size), u16 (transmission flags)
    info_buffer: [12]u8
    size_bytes : u64 = 1024 * 1024 * 1024 // 1GB Dummy Disk
    flags := Transmission_Flags{.HAS_FLAGS, .READ_ONLY}

    endian.put_u16(info_buffer[0:2],  .Big, NBD_INFO_EXPORT)
    endian.put_u64(info_buffer[2:10], .Big, size_bytes)
    endian.put_u16(info_buffer[10:12],.Big, transmute(u16)flags)

    // Send the INFO detail
    send_reply(conn, Negotiation_Reply{opt = opt, type = .INFO}, info_buffer[:])
    // Send final ACK to transition phases
    send_reply(conn, Negotiation_Reply{opt = opt, type = .ACK})
}

// --- Transmission Phase ---

handle_transmission :: proc(conn: ^Connection) {
	for {
        // NBD Standard Request Header is exactly 28 bytes
		Header :: struct #packed {
            magic:  u32,  // 0:4
            flags:  u16,  // 4:6
            type:   u16,  // 6:8
            cookie: u64,  // 8:16
            offset: u64,  // 16:24
            len:    u32,  // 24:28
        }

        head: Header
        header_buf := transmute([size_of(Header)]u8)head
        if !read_exact(conn, header_buf[:]) do break

        head.magic, _  = endian.get_u32(header_buf[0:4], .Big)
        head.flags, _  = endian.get_u16(header_buf[4:6], .Big)
        head.type, _   = endian.get_u16(header_buf[6:8], .Big)
        head.cookie, _ = endian.get_u64(header_buf[8:16], .Big)
        head.offset, _ = endian.get_u64(header_buf[16:24], .Big)
        head.len, _    = endian.get_u32(header_buf[24:28], .Big)

        if head.magic != NBD_REQUEST_MAGIC do break
        fmt.println("Here")

        #partial switch NBD_Cmd(head.type) {
        case .READ:
            fmt.printf("READ: offset %d, len %d\n", head.offset, head.len)
            // Example READ response (zeros)
            data := make([]u8, head.len)
            defer delete(data)
            send_reply(conn, Transmission_Reply{error = .NONE, cookie = head.cookie}, data)

        case .WRITE:
            fmt.printf("WRITE: offset %d, len %d\n", head.offset, head.len)
            // Consume the write data
            data := make([]u8, head.len)
            defer delete(data)
            read_exact(conn, data)
            send_reply(conn, Transmission_Reply{error = .NONE, cookie = head.cookie})

        case .DISC:
            fmt.println("Client disconnected.")
            return

        case .FLUSH:
            send_reply(conn, Transmission_Reply{error = .NONE, cookie = head.cookie})
        }
	}
}

// --- Boilerplate & Server Logic ---

start_tls_handshake :: proc(conn: ^Connection, ctx: ^SSL_CTX) -> bool {
	s := SSL_new(ctx)
	if s == nil do return false
	SSL_set_fd(s, c.int(conn.socket))

	if SSL_accept(s) <= 0 {
        SSL_free(s)
        return false
	}

	conn.ssl_handle = s
	conn.is_tls = true
    fmt.println("TLS Handshake successful!")
	return true
}

run_nbd_server :: proc() {
	method := TLS_server_method()
	global_ssl_ctx := SSL_CTX_new(method)
	defer SSL_CTX_free(global_ssl_ctx)

	if SSL_CTX_use_certificate_file(global_ssl_ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 do return 
    if SSL_CTX_use_PrivateKey_file(global_ssl_ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 do return

	endpoint := net.Endpoint{ net.IP4_Address{127, 0, 0, 1}, 10809 }
	listener, err := net.listen_tcp(endpoint)
	if err != nil do os.exit(1)
	defer net.close(listener)

	net.set_option(listener, .TCP_Nodelay, true)
	fmt.printf("Server listening on %v:%d\n", endpoint.address, endpoint.port)

	for {
		client_socket, _, accept_err := net.accept_tcp(listener)
		if accept_err != nil do continue
		
        conn := Connection{socket = client_socket, ssl_handle = nil, is_tls = false}
		handle_handshake(&conn, global_ssl_ctx)

		if conn.ssl_handle != nil do SSL_free(conn.ssl_handle)
		net.close(conn.socket)
	}
}

main :: proc() {
	run_nbd_server()
}
