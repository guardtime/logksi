#!/bin/bash

export KSI_CONF=test/test.cfg

cp -r test/resource/logsignatures/treehash_testset/* test/out
cp -r test/resource/logfiles/treehash? test/out

# There are 8 files in each set.
# File 1: 4 data records, 1 metarecord
# File 2: 5 data records, 1 metarecord
# File 3: 6 data records, 1 metarecord
# File 4: 7 data records, 1 metarecord
# File 5: 5 data records
# File 6: 6 data records
# File 7: 7 data records
# File 8: 8 data records

@test "final hashes: integrate record hashes(NO), tree hashes(NO)" {
	run ./src/logksi integrate test/out/none_1 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/none_2 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/none_3 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/none_4 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/none_5 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/none_6 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/none_7 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/none_8 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "final hashes: verify record hashes(NO), tree hashes(NO)" {
	run ./src/logksi verify test/out/treehash1 test/out/none_1.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash2 test/out/none_2.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash3 test/out/none_3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash4 test/out/none_4.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash5 test/out/none_5.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash6 test/out/none_6.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash7 test/out/none_7.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash8 test/out/none_8.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "final hashes: integrate record hashes(YES), tree hashes(NO)" {
	run ./src/logksi integrate test/out/rec_1 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/rec_2 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/rec_3 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/rec_4 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/rec_5 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/rec_6 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/rec_7 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi integrate test/out/rec_8 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "final hashes: verify record hashes(YES), tree hashes(NO)" {
	run ./src/logksi verify test/out/treehash1 test/out/rec_1.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash2 test/out/rec_2.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash3 test/out/rec_3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash4 test/out/rec_4.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash5 test/out/rec_5.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash6 test/out/rec_6.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash7 test/out/rec_7.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/treehash8 test/out/rec_8.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "final hashes: integrate record hashes(NO), tree hashes(YES), final hashes(NO)" {
	run ./src/logksi integrate test/out/tree_1 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi integrate test/out/tree_2 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi integrate test/out/tree_3 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi integrate test/out/tree_4 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/tree_5 -ddd --force-overwrite
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no. 1: incomplete block is closed without a metarecord." ]]
	run ./src/logksi integrate test/out/tree_6 -ddd --force-overwrite
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no. 1: incomplete block is closed without a metarecord." ]]
	run ./src/logksi integrate test/out/tree_7 -ddd --force-overwrite
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no. 1: incomplete block is closed without a metarecord." ]]
	run ./src/logksi integrate test/out/tree_8 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: verify record hashes(NO), tree hashes(YES), final hashes(NO)" {
	run ./src/logksi verify test/out/treehash1 test/out/tree_1.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi verify test/out/treehash2 test/out/tree_2.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi verify test/out/treehash3 test/out/tree_3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi verify test/out/treehash4 test/out/tree_4.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash5 test/out/tree_5.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "File does not exist." ]]
	run ./src/logksi verify test/out/treehash6 test/out/tree_6.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "File does not exist." ]]
	run ./src/logksi verify test/out/treehash7 test/out/tree_7.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "File does not exist." ]]
	run ./src/logksi verify test/out/treehash8 test/out/tree_8.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: integrate record hashes(NO), tree hashes(YES), final hashes(INSERT)" {
	run ./src/logksi integrate test/out/tree_1 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/tree_2 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/tree_3 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/tree_4 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/tree_5 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no. 1: incomplete block is closed without a metarecord." ]]
	run ./src/logksi integrate test/out/tree_6 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no. 1: incomplete block is closed without a metarecord." ]]
	run ./src/logksi integrate test/out/tree_7 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no. 1: incomplete block is closed without a metarecord." ]]
	run ./src/logksi integrate test/out/tree_8 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: verify record hashes(NO), tree hashes(YES), final hashes(INSERTED)" {
	run ./src/logksi verify test/out/treehash1 test/out/tree_1.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash2 test/out/tree_2.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash3 test/out/tree_3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash4 test/out/tree_4.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash5 test/out/tree_5.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "File does not exist." ]]
	run ./src/logksi verify test/out/treehash6 test/out/tree_6.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "File does not exist." ]]
	run ./src/logksi verify test/out/treehash7 test/out/tree_7.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "File does not exist." ]]
	run ./src/logksi verify test/out/treehash8 test/out/tree_8.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: integrate record hashes(NO), tree hashes(YES), final hashes(YES)" {
	run ./src/logksi integrate test/out/final_tree_1 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_tree_2 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_tree_3 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_tree_4 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_tree_5 -ddd --force-overwrite
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no. 1: incomplete block is closed without a metarecord." ]]
	run ./src/logksi integrate test/out/final_tree_6 -ddd --force-overwrite
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no. 1: incomplete block is closed without a metarecord." ]]
	run ./src/logksi integrate test/out/final_tree_7 -ddd --force-overwrite
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no. 1: tree hashes not equal." ]]
	run ./src/logksi integrate test/out/final_tree_8 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: verify record hashes(NO), tree hashes(YES), final hashes(YES)" {
	run ./src/logksi verify test/out/treehash1 test/out/final_tree_1.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash2 test/out/final_tree_2.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash3 test/out/final_tree_3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash4 test/out/final_tree_4.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash5 test/out/final_tree_5.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "File does not exist." ]]
	run ./src/logksi verify test/out/treehash6 test/out/final_tree_6.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "File does not exist." ]]
	run ./src/logksi verify test/out/treehash7 test/out/final_tree_7.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "File does not exist." ]]
	run ./src/logksi verify test/out/treehash8 test/out/final_tree_8.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: integrate record hashes(YES), tree hashes(YES), final hashes(NO)" {
	run ./src/logksi integrate test/out/rec_tree_1 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi integrate test/out/rec_tree_2 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi integrate test/out/rec_tree_3 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi integrate test/out/rec_tree_4 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/rec_tree_5 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi integrate test/out/rec_tree_6 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi integrate test/out/rec_tree_7 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi integrate test/out/rec_tree_8 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: verify record hashes(YES), tree hashes(YES), final hashes(NO)" {
	run ./src/logksi verify test/out/treehash1 test/out/rec_tree_1.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi verify test/out/treehash2 test/out/rec_tree_2.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi verify test/out/treehash3 test/out/rec_tree_3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi verify test/out/treehash4 test/out/rec_tree_4.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash5 test/out/rec_tree_5.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi verify test/out/treehash6 test/out/rec_tree_6.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi verify test/out/treehash7 test/out/rec_tree_7.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	run ./src/logksi verify test/out/treehash8 test/out/rec_tree_8.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: integrate record hashes(YES), tree hashes(YES), final hashes(INSERT)" {
	run ./src/logksi integrate test/out/rec_tree_1 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/rec_tree_2 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/rec_tree_3 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/rec_tree_4 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/rec_tree_5 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/rec_tree_6 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/rec_tree_7 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/rec_tree_8 -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: verify record hashes(YES), tree hashes(YES), final hashes(INSERTED)" {
	run ./src/logksi verify test/out/treehash1 test/out/rec_tree_1.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash2 test/out/rec_tree_2.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash3 test/out/rec_tree_3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash4 test/out/rec_tree_4.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash5 test/out/rec_tree_5.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash6 test/out/rec_tree_6.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash7 test/out/rec_tree_7.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash8 test/out/rec_tree_8.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: integrate record hashes(YES), tree hashes(YES), final hashes(YES)" {
	run ./src/logksi integrate test/out/final_rec_tree_1 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_rec_tree_2 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_rec_tree_3 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_rec_tree_4 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_rec_tree_5 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_rec_tree_6 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_rec_tree_7 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi integrate test/out/final_rec_tree_8 -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

@test "final hashes: verify record hashes(YES), tree hashes(YES), final hashes(YES)" {
	run ./src/logksi verify test/out/treehash1 test/out/final_rec_tree_1.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash2 test/out/final_rec_tree_2.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash3 test/out/final_rec_tree_3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash4 test/out/final_rec_tree_4.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash5 test/out/final_rec_tree_5.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash6 test/out/final_rec_tree_6.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash7 test/out/final_rec_tree_7.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	run ./src/logksi verify test/out/treehash8 test/out/final_rec_tree_8.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
}

