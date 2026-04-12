package Blockchain

import "core:slice"
import "core:crypto/hash"
import "core:time"

Block :: struct($T: typeid, $K: typeid) {
	prev_block:   ^Block(T, K),
	prev_hash:    []byte,
	transactions: [dynamic]T,
	/*
		Example:
		|----TxA----|----TxB----|----TxC----|----TxD----|
		[[[H(TxA)],   [H(TxB)],   [H(TxC)],   [H(TxD)]  ],
		[       [H(TxAB)],              [H(TxCD)]       ],
		[                  [H(TxABDC)]                 ]]		
	*/
	tree_levels:  [dynamic][dynamic][]byte,
	tx_indices:   map[K]uint, // Map id => index level
	merkle_root:  []byte,
	timestamp:    i64,
}

make_block :: proc($T: typeid, $K: typeid, allocator := context.allocator) -> Block(T, K) {
	return Block(T, K) {
		prev_hash    = nil,
		transactions = make([dynamic]T, allocator),
		tree_levels  = make([dynamic][dynamic][]byte, allocator),
		tx_indices   = make(map[K]uint, 16, allocator),
		timestamp    = time.to_unix_nanoseconds(time.now()),
		// merkle_root is empty until we `seal` the block
	}
}

delete_block :: proc(block: ^Block($T, $K)) {
	delete(block.transactions)
	delete(block.tx_indices)
	delete(block.merkle_root)

	for level in block.tree_levels {
		// level in [dynamic][]byte
		for h in level {
			// h is a []byte created by slice.clone()
			delete(h)
		}
		// now delete the level dynamic array
		delete(level)
	}
	// delete the outer container
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
seal :: proc(
	block: ^Block($T, $K),
	serialize: proc(data: ^T, allocator := context.allocator) -> []byte,
	get_id: proc(_: ^T) -> K, allocator := context.allocator
) {
	// check that the lenght of `transactions` are even
	if len(block.transactions) <= 0 do return

	// initialize level 0
	level_0 := make([dynamic][]byte)

	// fill level - and idex map
	for &tx, i in block.transactions {
		// use the context allocator to ensure we get a fresh copy
		bytes: []byte = serialize(&tx, allocator)

		hash_bytes: []byte = hash.hash_bytes(.SHA256, bytes)

		append(&level_0, slice.clone(hash_bytes))

		// Map the custom ID type to the index
		block.tx_indices[get_id(&tx)] = uint(i)
	}
	append(&block.tree_levels, level_0)

	// build the rest of levels
	current_level: int = 0
	for len(block.tree_levels[current_level]) > 1 {
		next_level := make([dynamic][]byte)
		prev_level := block.tree_levels[current_level]

		for i := 0; i < len(prev_level); i += 2 {
			left_node: []byte = prev_level[i]
			right_node: []byte = left_node // Set the default

			// verify if the left node have a sibling
			if i + 1 < len(prev_level) do right_node = prev_level[i + 1]

			// Hash( left_node + right_node )
			combined_nodes := make([]byte, len(left_node) + len(right_node), allocator)
			copy(combined_nodes[:len(left_node)], left_node)
			copy(combined_nodes[len(left_node):], right_node)

			parent_hash: []byte = hash.hash_bytes(.SHA256, combined_nodes)

			// add hash parents to the next level
			append(&next_level, slice.clone(parent_hash)) 
		}

		// here it finished to process the level
		// so now the next level is pushed into the tree
		append(&block.tree_levels, next_level)

		// go to next level tree
		current_level += 1
	}

	// the 0 pos array level, always be placed the root hash
	root_hash := block.tree_levels[len(block.tree_levels) - 1][0]

	// clone it so `block.merkle_root` has its own memory
	block.merkle_root = slice.clone(root_hash)
}

// request a merkle proof
get_proof :: proc(block: ^Block($T, $K), id: K, allocator := context.temp_allocator) -> (proof: [][]byte, ok: bool) {
	idx, found := block.tx_indices[id]
	if !found do return nil, false

	tree_height := len(block.tree_levels) - 1
	if tree_height <= 0 do return nil, true
	// fetch sibling hashes for a specific transaction
	result := make([][]byte, tree_height, allocator)

	// current transaction
	current_idx := int(idx)
	for level_idx := 0; level_idx < len(block.tree_levels) - 1; level_idx += 1 {
		level := block.tree_levels[level_idx]

		sibling_idx := current_idx % 2 == 0 ? current_idx + 1 : current_idx - 1

		// if the level has an odd number of nodes, 
		// the last node might be its own sibling
		source_hash: []byte
		if sibling_idx < len(level) {
			source_hash = level[sibling_idx]
		} else {
			source_hash = level[current_idx]
		}

		result[level_idx] = slice.clone(source_hash, allocator)

		// move up to the parent's index in the next level
		current_idx /= 2
	}

	return result, true
}

