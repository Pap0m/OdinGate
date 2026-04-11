package main

import "core:fmt"
import "core:mem"
import "Blockchain"

Token :: struct {
    id:    uint,
    data:  uint,
    owner: string,
}

// custom user function
token_to_bytes :: proc(t: ^Token, allocator:= context.allocator) -> []byte {
	context.allocator = allocator
	result := make([dynamic]byte)

	// Convert fields to byte slices
    id_bytes := mem.ptr_to_bytes(&t.id, size_of(t.id))
    data_bytes := mem.ptr_to_bytes(&t.data, size_of(t.data))
    owner_bytes := transmute([]byte)t.owner

    // Append slices
    append(&result, ..id_bytes)
    append(&result, ..data_bytes)
    append(&result, ..owner_bytes)

	return result[:]
}

get_id :: proc(t: ^Token) -> uint {
	return t.id
}

Token_Block :: Blockchain.Block(Token, uint)

// simple wrappers
make_token_block :: proc(allocator := context.allocator) -> Token_Block {
    return Blockchain.make_block(Token, uint, allocator)
}

main :: proc() {
	block := make_token_block();
	defer Blockchain.delete_block(&block)

	Blockchain.add_transactions(&block, 
	    Token{id = 1,  owner = "Alice"},
	    Token{id = 2,  owner = "Bob"},
	    Token{id = 3,  owner = "Charlie"},
	    Token{id = 4,  owner = "Dan"},
	    Token{id = 5,  owner = "Eve"},
	    Token{id = 6,  owner = "Frank"},
	    Token{id = 7,  owner = "Grace"},
	    Token{id = 8,  owner = "Heidi"},
	    Token{id = 9,  owner = "Ivan"},
	    Token{id = 10, owner = "Judy"},
	    Token{id = 11, owner = "Mallory"},
	    Token{id = 12, owner = "Niaj"},
	    Token{id = 13, owner = "Olivia"},
	    Token{id = 14, owner = "Peggy"},
	    Token{id = 15, owner = "Sybil"},
	    Token{id = 16, owner = "Trent"},
	    Token{id = 17, owner = "Victor"},
	    Token{id = 18, owner = "Walter"},
	    Token{id = 19, owner = "Xavier"},
	    Token{id = 20, owner = "Yolanda"},
	)

	Blockchain.seal(&block, token_to_bytes, get_id)

	proof: [][]byte = Blockchain.get_proof(&block, 15)
}
