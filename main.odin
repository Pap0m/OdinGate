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

	Blockchain.add_transactions(&block, Token{id = 1, owner = "Nick"}, Token{id = 2, owner = "Some"})
	Blockchain.add_transaction(&block, Token{id = 3, owner = "Odin"})

	Blockchain.seal(&block, token_to_bytes, get_id)

	// proof: [][]byte = Blockchain.get_proof(&block, 2)
	
	fmt.printfln("Timestamp: %v", block.timestamp)
	fmt.printfln("Transaction Count: %v", len(block.transactions))
}
