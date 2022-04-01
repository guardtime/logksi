#!/bin/bash

export KSI_CONF=test/test.cfg

cp test/resource/logfiles/treehash1 test/out/create_log_1
cp test/resource/logfiles/treehash2 test/out/create_log_2


# block_count, rec_hash_count, meta_rec_count, ih, oh
f_summary_of_logfile_short () {
	 echo "(Summary of logfile:).( . Count of blocks:             $1).( . Count of record hashes:      $2).( . Count of meta-records:       $3).( . Input hash:  $4).( . Output hash: $5)"
}

@test "create new logsig: from two files one by one (in/out hash from/to file)" {
	run ./src/logksi create test/out/create_log_1 --seed test/resource/random/seed_aa --blk-size 16 -o test/out/create_log_1_T1.logsig --output-hash test/out/create_log_1_T1.logsig.outhash -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run cat test/out/create_log_1_T1.logsig.outhash
	[[ "$output" =~ (Log file).*(test\/out\/create_log_1).*(Last leaf from log signature).*(test\/out\/create_log_1_T1.logsig).*(SHA-256:20c46e471b9c26c192797aff00f2ad8633500a365c64f0fd4177df0b34498552) ]]

	run ./src/logksi create test/out/create_log_2 --seed test/resource/random/seed_aa --blk-size 16 -o test/out/create_log_2_T1.logsig --input-hash test/out/create_log_1_T1.logsig.outhash --output-hash test/out/create_log_2_T1.logsig.outhash -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
	
	run cat test/out/create_log_2_T1.logsig.outhash
	[[ "$output" =~ (Log file).*(test\/out\/create_log_2).*(Last leaf from log signature).*(test\/out\/create_log_2_T1.logsig).*(SHA-256:44883d33f25a470c6fd0c9d6bb5404fe8762ef85a4b27cd901695919ac7afe98) ]]

	run ./src/logksi verify test/out/create_log_1 test/out/create_log_1_T1.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run ./src/logksi verify test/out/create_log_2 test/out/create_log_2_T1.logsig --input-hash test/out/create_log_1_T1.logsig.outhash -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}

# @SKIP_MEMORY_TEST
@test "create new logsig: from two files one by one (in/out hash from/to pipe)" {
	run bash -c "./src/logksi create test/out/create_log_1 --seed test/resource/random/seed_aa --blk-size 16 -o test/out/create_log_1_T2.logsig --output-hash - -dd | ./src/logksi create test/out/create_log_2 --seed test/resource/random/seed_aa --blk-size 16 -o test/out/create_log_2_T2.logsig --input-hash - --output-hash - -dd > test/out/create_log_2_T2.logsig.outhash"
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]

	run cat test/out/create_log_2_T2.logsig.outhash
	[[ "$output" =~ (Log file).*(test\/out\/create_log_2).*(Last leaf from log signature).*(test\/out\/create_log_2_T2.logsig).*(SHA-256:44883d33f25a470c6fd0c9d6bb5404fe8762ef85a4b27cd901695919ac7afe98) ]]

	run ./src/logksi verify test/out/create_log_1 test/out/create_log_1_T2.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run ./src/logksi verify test/out/create_log_2 test/out/create_log_2_T2.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}

@test "create new logsig: input hash from cmd" {
	run ./src/logksi create test/out/create_log_2 --seed test/resource/random/seed_aa --blk-size 16 -o test/out/create_log_2_T3.logsig --input-hash SHA-256:20c46e471b9c26c192797aff00f2ad8633500a365c64f0fd4177df0b34498552 -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
	
	run ./src/logksi verify test/out/create_log_2 test/out/create_log_2_T3.logsig --input-hash SHA-256:20c46e471b9c26c192797aff00f2ad8633500a365c64f0fd4177df0b34498552 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}

@test "create new logsig: from two files in sequence (after --)" {
	run ./src/logksi create -dd --seed test/resource/random/seed_aa --blk-size 16 --force-overwrite -- test/out/create_log_1 test/out/create_log_2
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]

	run ./src/logksi verify -dd -- test/out/create_log_1 test/out/create_log_2
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}

@test "create new logsig: from two files in sequence (<logfile> and after --)" {
	run ./src/logksi create test/out/create_log_1 -dd --seed test/resource/random/seed_aa --blk-size 16 --force-overwrite -- test/out/create_log_2
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]

	run ./src/logksi verify -dd -- test/out/create_log_1 test/out/create_log_2
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}
