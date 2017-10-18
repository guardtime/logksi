#!/bin/bash

export KSI_CONF=test/test.cfg

cp -r test/resource/logsignatures/all_hashes.logsig test/out
cp -r test/resource/logfiles/all_hashes test/out
cp -r test/resource/logsignatures/record_hash_out_of_block.logsig test/out
cp -r test/resource/logsignatures/tree_hash_out_of_block.logsig test/out
cp -r test/resource/logsignatures/record_hashes_not_stored_in_first_block.logsig test/out
cp -r test/resource/logsignatures/record_hashes_not_stored_in_second_block.logsig test/out
cp -r test/resource/logsignatures/tree_hashes_not_stored_in_first_block.logsig test/out
cp -r test/resource/logsignatures/tree_hashes_not_stored_in_second_block.logsig test/out
cp -r test/resource/logsignatures/record_hash_missing_for_first_record.logsig test/out
cp -r test/resource/logsignatures/record_hash_missing_for_second_record.logsig test/out
cp -r test/resource/logsignatures/record_hash_missing_for_last_record.logsig test/out
cp -r test/resource/logsignatures/tree_hash_missing_for_first_record.logsig test/out
cp -r test/resource/logsignatures/tree_hash_1_missing_for_second_record.logsig test/out
cp -r test/resource/logsignatures/tree_hash_2_missing_for_second_record.logsig test/out
cp -r test/resource/logsignatures/tree_hash_missing_for_last_record.logsig test/out
cp -r test/resource/logsignatures/hashes_missing_for_first_record.logsig test/out
cp -r test/resource/logsignatures/hashes_missing_for_last_record.logsig test/out
cp -r test/resource/logsignatures/record_hash_missing_for_metarecord.logsig test/out
cp -r test/resource/logsignatures/tree_hash_missing_for_metarecord.logsig test/out
cp -r test/resource/logsignatures/record_hash_too_many.logsig test/out
cp -r test/resource/logsignatures/tree_hash_too_many_perfect_tree.logsig test/out
cp -r test/resource/logsignatures/tree_hash_final.logsig test/out
cp -r test/resource/logsignatures/tree_hash_final_wrong.logsig test/out
cp -r test/resource/logsignatures/tree_hashes_final_too_many.logsig test/out
cp -r test/resource/logsignatures/tree_hashes_final_too_few.logsig test/out
cp -r test/resource/logsignatures/tree_hashes_final_all_present.logsig test/out

@test "verify all hashes" {
	run ./src/logksi verify test/out/all_hashes -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Warning: Block no.   1: all final tree hashes are missing." ]]
}

@test "insert missing hashes" {
	run ./src/logksi sign test/out/all_hashes -o test/out/no_missing_hashes.logsig -d --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify no missing hashes" {
	run ./src/logksi verify test/out/all_hashes test/out/no_missing_hashes.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: interpreting tree hash no.   5 as a final hash... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify record hash out of block" {
	run ./src/logksi verify test/out/all_hashes test/out/record_hash_out_of_block.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "record hash without preceding block header found." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hash out of block" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hash_out_of_block.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "tree hash without preceding block header found." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify record hashes not stored in first block" {
	run ./src/logksi verify test/out/all_hashes test/out/record_hashes_not_stored_in_first_block.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ " Error: Block no.   1: all record hashes missing." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify record hashes not stored in second block" {
	run ./src/logksi verify test/out/all_hashes test/out/record_hashes_not_stored_in_second_block.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   2: missing record hash for logline no.    4." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hashes not stored in first block" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hashes_not_stored_in_first_block.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: all tree hashes missing." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hashes not stored in second block" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hashes_not_stored_in_second_block.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   2: missing tree hash(es) for logline no.    4." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify record hash missing for first record" {
	run ./src/logksi verify test/out/all_hashes test/out/record_hash_missing_for_first_record.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: missing record hash for logline no.    1." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify record hash missing for second record" {
	run ./src/logksi verify test/out/all_hashes test/out/record_hash_missing_for_second_record.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: missing record hash for logline no.    2." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify record hash missing for last record" {
	run ./src/logksi verify test/out/all_hashes test/out/record_hash_missing_for_last_record.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: missing record hash for logline no.    3." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hash missing for first record" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hash_missing_for_first_record.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: missing tree hash for logline no.    1." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hash 1 missing for second record" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hash_1_missing_for_second_record.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: tree hashes not equal for logline no.    2" ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hash 2 missing for second record" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hash_2_missing_for_second_record.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: missing tree hash(es) for logline no.    2." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hash missing for last record" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hash_missing_for_last_record.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: missing tree hash(es) for logline no.    3." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify hashes missing for first record" {
	run ./src/logksi verify test/out/all_hashes test/out/hashes_missing_for_first_record.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: record hashes not equal for logline no.    1." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify hashes missing for last record" {
	run ./src/logksi verify test/out/all_hashes test/out/hashes_missing_for_last_record.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: missing record hash for logline no.    3." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify record hash missing for metarecord" {
	run ./src/logksi verify test/out/all_hashes test/out/record_hash_missing_for_metarecord.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   9: missing record hash for metarecord with index   0." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hash missing for metarecord" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hash_missing_for_metarecord.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   9: missing tree hash(es) for logline no.   24." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify record hash too many" {
	run ./src/logksi verify test/out/all_hashes test/out/record_hash_too_many.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: expected 3 record hashes, but found 4." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hash too many perfect tree" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hash_too_many_perfect_tree.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   9: missing record hash for logline no.   25." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hash final" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hash_final.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: interpreting tree hash no.   5 as a final hash... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify tree hash final wrong" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hash_final_wrong.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Block no.   1: interpreting tree hash no.   5 as a final hash." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hashes final too many" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hashes_final_too_many.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Block no.   1: interpreting tree hash no.   5 as a final hash... ok." ]]
	[[ "$output" =~ "Error: Block no.   1: unexpected final tree hash no.   6." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hashes final too few" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hashes_final_too_few.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Block no.  13: interpreting tree hash no.  27 as a final hash... ok." ]]
	[[ "$output" =~ "Error: Block no.  13: found   1 final tree hashes instead of   3." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify tree hashes final all present" {
	run ./src/logksi verify test/out/all_hashes test/out/tree_hashes_final_all_present.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.  13: interpreting tree hash no.  27 as a final hash... ok." ]]
	[[ "$output" =~ "Block no.  13: interpreting tree hash no.  28 as a final hash... ok." ]]
	[[ "$output" =~ "Block no.  13: interpreting tree hash no.  29 as a final hash... ok." ]]
	[[ "$output" =~ "Block no.  13: all final tree hashes are present." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

