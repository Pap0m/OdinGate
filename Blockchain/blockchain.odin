package Blockchain

import "core:encoding/base64"
import "core:mem"
import "core:fmt"
import "core:time"
import "core:crypto/hash"

Block :: struct($T: typeid, $K: typeid) {
	prev_block: ^Block(T, K),
	prev_hash: []byte,
	transactions: [dynamic]T,
	tree_levels: [dynamic][dynamic]string,
	tx_indices: map[K]uint, // Map id => index level
	merkle_root: string,
	timestamp: i64,
}

make_block :: proc($T: typeid, $K: typeid, allocator := context.allocator) -> Block(T, K) {
	return Block(T, K) {
		prev_hash      = nil,
		transactions   = make([dynamic]T, allocator),
		tree_levels    = make([dynamic][dynamic]string, allocator),
		tx_indices     = make(map[K]uint, 16, allocator),
		timestamp      = time.to_unix_nanoseconds(time.now()),
		// merkle_root is empty until we `seal` the block
	}
}

delete_block :: proc(block: ^Block($T, $K)) {
	delete(block.transactions)
	delete(block.merkle_root)
	delete(block.tx_indices)

	for rows in block.tree_levels {
		// clean up all the rows of the matrix container
        for s in rows do delete(s) // each encoded string needs freeing
    	delete(rows)
	}
    // later clean up the actual matrix
    delete(block.tree_levels)
}

// add data to the block
add_transaction :: proc(block: ^Block($T, $K), tx: T) {
	append(&block.transactions, tx)
}
// add data to the block
add_transactions :: proc(block: ^Block($T, $K), txs: ..T) {
	append(&block.transactions, ..txs)
}


// run the merkle algorithm and save the final hash
seal :: proc(block: ^Block($T, $K), serialize: proc(data: ^T, allocator := context.allocator) -> []byte, get_id: proc(^T) -> K) {
	// check that the lenght of `transactions` are even
	if len(block.transactions) <= 0  do return 

	// initialize level 0
	level_0 := make([dynamic]string)

	// fill level - and idex map
	for &tx, i in block.transactions {
		// use the context allocator to ensure we get a fresh copy
		bytes: []byte = serialize(&tx, context.temp_allocator)

		hash_bytes: []byte = hash.hash_bytes(.SHA256, bytes)

		// encode allocates new memory
		hash_encoded: string = base64.encode(hash_bytes)
		append(&level_0, hash_encoded)

		// Map the custom ID type to the index
        block.tx_indices[get_id(&tx)] = uint(i)
	}
	append(&block.tree_levels, level_0)

	// build the rest of levels
	current_level := 0
	for len(block.tree_levels[current_level]) > 1 {
		next_level := make([dynamic]string)
		prev_level := block.tree_levels[current_level]			

		for i := 0; i < len(prev_level); i += 2 {
			
		}
	}

	
}

// request a merkle proof
get_proof :: proc(block: ^Block($T, $K), tx_index: uint) -> [][]byte {
	// fetch sibling hashes for a specific transaction
    return nil
}
