package Blockchain

import "core:testing"
import "core:slice"
import "core:crypto/hash"

Token :: struct {
	id:    uint,
	owner: string,
}

token_to_bytes :: proc(t: ^Token, allocator := context.allocator) -> []byte {
	return slice.clone(slice.bytes_from_ptr(t, size_of(Token)), allocator)
}

get_id :: proc(t: ^Token) -> uint {
	return t.id
}

@(test)
test_single_block_verification :: proc(t: ^testing.T) {
	b := make_block(Token, uint)
	defer delete_block(&b)

	add_transactions(&b, Token{1, "Alice"}, Token{2, "Bob"})
	seal(&b, token_to_bytes, get_id)

	proof, ok := get_proof(&b, 1)
	testing.expect(t, ok, "Proof generation failed")
	
	testing.expect(t, verify_proof(&b, 1, proof), "Valid proof failed verification")
}

@(test)
test_odd_number_transactions :: proc(t: ^testing.T) {
	b := make_block(Token, uint)
	defer delete_block(&b)

	// Merkle trees require even leaves; seal() should duplicate the last node
	add_transactions(&b, Token{1, "Alice"}, Token{2, "Bob"}, Token{3, "Charlie"})
	seal(&b, token_to_bytes, get_id)

	proof, ok := get_proof(&b, 3)
	testing.expect(t, ok)
	testing.expect(t, verify_proof(&b, 3, proof), "Failed to verify duplicated leaf in odd-count tree")
}

@(test)
test_chain_traversal :: proc(t: ^testing.T) {
	b1 := make_block(Token, uint)
	defer delete_block(&b1)
	add_transaction(&b1, Token{100, "Genesis"})
	seal(&b1, token_to_bytes, get_id)

	b2 := make_block(Token, uint)
	defer delete_block(&b2)
	b2.prev_block = &b1 
	add_transaction(&b2, Token{200, "Second"})
	seal(&b2, token_to_bytes, get_id)

	proof, _ := get_proof(&b1, 100)
	testing.expect(t, verify_transaction_in_chain(&b2, 100, proof), "Search failed to traverse to previous block")
}

@(test)
test_tamper_resistance :: proc(t: ^testing.T) {
	b := make_block(Token, uint)
	defer delete_block(&b)

	add_transaction(&b, Token{1, "Alice"})
	seal(&b, token_to_bytes, get_id)

	// Simulate unauthorized data modification after the block is sealed
	b.transactions[0].owner = "EVIL_HACKER"
	
	context.allocator = context.temp_allocator
	defer free_all(context.temp_allocator)

	tampered_bytes := token_to_bytes(&b.transactions[0])
	tampered_leaf := hash.hash_bytes(.SHA256, tampered_bytes)
	
	is_intact := slice.equal(tampered_leaf, b.tree_levels[0][0])
	testing.expect(t, !is_intact, "Tampered data went undetected")
}

@(test)
test_invalid_proof_fails :: proc(t: ^testing.T) {
	b := make_block(Token, uint)
	defer delete_block(&b)
	add_transactions(&b, Token{1, "A"}, Token{2, "B"})
	seal(&b, token_to_bytes, get_id)

	context.allocator = context.temp_allocator
	defer free_all(context.temp_allocator)

	fake_proof := make([][]byte, 1)
	fake_proof[0] = make([]byte, 32) 
	
	testing.expect(t, !verify_proof(&b, 1, fake_proof), "Garbage proof should not verify")
}
