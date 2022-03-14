#!/bin/bash

mkdir -p test/out/sigdir-create-static-file
mkdir -p test/out/empty-log-files
mkdir -p test/out/log_file_sequence_overwrite_one
mkdir -p test/out/new-line-sig

cp test/resource/logfiles/all_hashes test/out/large_log
cp test/resource/logfiles/treehash1 test/out/records_4
cp test/resource/logfiles/treehash2 test/out/records_5
cp test/resource/logfiles/treehash1 test/out/log_file_sequence_overwrite_one/records_4
cp test/resource/logfiles/treehash2 test/out/log_file_sequence_overwrite_one/records_5

echo "" > test/out/empty-log-files/empty-new-line
printf "" > test/out/empty-log-files/empty-totally

echo "dummy sig" > test/out/create_dummy.logsig
echo "dummy log" > test/out/create_dummy
echo "dummy sig 2" > test/out/sigdir-create-static-file/create_dummy.logsig
echo "dummy sig 5" > test/out/log_file_sequence_overwrite_one/records_5.logsig


export KSI_CONF=test/test.cfg
# block_count, rec_hash_count, meta_rec_count, ih, oh
f_summary_of_logfile_short () {
	 echo "(Summary of logfile:).( . Count of blocks:             $1).( . Count of record hashes:      $2).( . Count of meta-records:       $3).( . Input hash:  $4).( . Output hash: $5)"
}

@test "create new logsig: from totally empty file" {
	run ./src/logksi create test/out/empty-log-files/empty-totally --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: {Mr}" ]]

	run src/logksi verify test/out/empty-log-files/empty-totally -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 0 1 "SHA-256:000000.*000000" "SHA-256:cb7b6b.*305bbf"` ]]
}

@test "create new logsig: from file with 1 empty line" {
	run ./src/logksi create test/out/empty-log-files/empty-new-line --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: {rMr}" ]]

	run src/logksi verify test/out/empty-log-files/empty-new-line -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 1 1 "SHA-256:000000.*000000" "SHA-256:3670e8.*886ef9"` ]]
}

@test "create new logsig: from file with 3 empty lines linux line ending" {
	run ./src/logksi create test/resource/logfiles/linux-new-line-3_empty-line --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes -ddd --sig-dir test/out/empty-log-files
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: {rrrMr}" ]]

	run src/logksi verify test/resource/logfiles/linux-new-line-3_empty-line --sig-dir test/out/empty-log-files -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 3 1 "SHA-256:000000.*000000" "SHA-256:9df569.*e9aff0"` ]]
}

@test "create new logsig: from file with 3 empty lines mac line ending" {
	run ./src/logksi create test/resource/logfiles/mac-new-line-3_empty-line --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes -ddd --sig-dir test/out/empty-log-files
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: {rrrMr}" ]]

	run src/logksi verify test/resource/logfiles/mac-new-line-3_empty-line --sig-dir test/out/empty-log-files -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 3 1 "SHA-256:000000.*000000" "SHA-256:9df569.*e9aff0"` ]]
}

@test "create new logsig: from file with 3 empty lines win line ending" {
	run ./src/logksi create test/resource/logfiles/win-new-line-3_empty-line --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes -ddd --sig-dir test/out/empty-log-files
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: {rrrMr}" ]]

	run src/logksi verify test/resource/logfiles/win-new-line-3_empty-line --sig-dir test/out/empty-log-files -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 3 1 "SHA-256:000000.*000000" "SHA-256:9df569.*e9aff0"` ]]
}

@test "create new logsig: try to overwrite existing" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 5 -o test/out/create_dummy.logsig -d
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error:).*(Overwriting of existing log signature file).*(test\/out\/create_dummy.logsig).*(not allowed) ]]
	[[ "$output" =~ (Run).*(logksi create).*(with).*(--force-overwrite) ]]

	run cat test/out/create_dummy.logsig
	[[ "$output" =~ "dummy sig" ]]
}

@test "create new logsig: overwrite existing but fail" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 5 -o test/out/create_dummy.logsig -ddd -S http://this_url_doe_not_exist --aggr-key plahh --aggr-user plahh --force-overwrite
	[ "$status" -eq 5 ]
	[[ "$output" =~ (Error: Could not sign tree root).*(Network error) ]]

	run cat test/out/create_dummy.logsig
	[[ "$output" =~ "dummy sig" ]]
}

@test "create new logsig: overwrite existing" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 5 -o test/out/create_dummy.logsig -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/records_4 test/out/create_dummy.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create new logsig: try to overwrite existing with --sig-dir next to log file" {
	run ./src/logksi create test/out/create_dummy --seed test/resource/random/seed_aa --blk-size 5 --sig-dir test/out -ddd
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error:).*(Overwriting of existing log signature file).*(test\/out\/create_dummy.logsig).*(not allowed) ]]
	[[ "$output" =~ (Run).*(logksi create).*(with).*(--force-overwrite) ]]

	run ./src/logksi create test/out/create_dummy --seed test/resource/random/seed_aa --blk-size 5 --sig-dir test/out/ -ddd
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error:).*(Overwriting of existing log signature file).*(test\/out\/create_dummy.logsig).*(not allowed) ]]
	[[ "$output" =~ (Run).*(logksi create).*(with).*(--force-overwrite) ]]

	run cat test/out/create_dummy.logsig
	[[ "$output" =~ "dummy sig" ]]
}

@test "create new logsig: try to overwrite existing with --sig-dir separate from log file" {
	run ./src/logksi create test/out/create_dummy --seed test/resource/random/seed_aa --blk-size 5 --sig-dir test/out/sigdir-create-static-file -ddd
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error:).*(Overwriting of existing log signature file).*(test\/out\/sigdir-create-static-file\/create_dummy.logsig).*(not allowed) ]]
	[[ "$output" =~ (Run).*(logksi create).*(with).*(--force-overwrite) ]]

	run ./src/logksi create test/out/create_dummy --seed test/resource/random/seed_aa --blk-size 5 --sig-dir test/out/sigdir-create-static-file/ -ddd
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error:).*(Overwriting of existing log signature file).*(test\/out\/sigdir-create-static-file\/create_dummy.logsig).*(not allowed) ]]
	[[ "$output" =~ (Run).*(logksi create).*(with).*(--force-overwrite) ]]

	run cat test/out/sigdir-create-static-file/create_dummy.logsig
	[[ "$output" =~ "dummy sig 2" ]]
}

@test "create new logsig: overwrite existing with --sig-dir next to log file" {
	run ./src/logksi create test/out/create_dummy --seed test/resource/random/seed_aa --blk-size 5 --sig-dir test/out -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/create_dummy --sig-dir test/out -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 1 1 "SHA-256:000000.*000000" "SHA-256:92eb3e.*8e41d5"` ]]
}

@test "create new logsig: overwrite existing with --sig-dir separate from log file" {
	run ./src/logksi create test/out/create_dummy --seed test/resource/random/seed_aa --blk-size 5 --sig-dir test/out/sigdir-create-static-file -ddd --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/create_dummy --sig-dir test/out/sigdir-create-static-file -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 1 1 "SHA-256:000000.*000000" "SHA-256:92eb3e.*8e41d5"` ]]
}

@test "create new logsig: 1 full block with meta record" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes -o test/out/records_4_3.logsig  -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: {rrrrMr}" ]]
	run ./src/logksi verify test/out/records_4 test/out/records_4_3.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create new logsig: 1 full block and 1 meta block" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 4 --keep-record-hashes -o test/out/records_4_1.logsig  -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: {rrrr}" ]]
	[[ "$output" =~ "Block no.   2: {Mr}" ]]
	run ./src/logksi verify test/out/records_4 test/out/records_4_1.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 2 4 1 "SHA-256:000000.*000000" "SHA-256:85792c.*26c153"` ]]
}

@test "create new logsig: 1 full block + 1 partially full block with meta record" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 3 --keep-record-hashes -o test/out/records_4_2.logsig  -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: {rrr}" ]]
	[[ "$output" =~ "Block no.   2: {rMr}" ]]
	run ./src/logksi verify test/out/records_4 test/out/records_4_2.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 2 4 1 "SHA-256:000000.*000000" "SHA-256:2f4519.*1da19c"` ]]
}

@test "create new logsig: without record and tree hashes" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 5 -o test/out/records_4_no_hashes.logsig  -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: {}" ]]
	run ./src/logksi verify test/out/records_4 test/out/records_4_no_hashes.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create new logsig: with only tree hashes" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 5 -o test/out/records_4_only_tree_hashes.logsig --keep-tree-hashes -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: {.........}" ]]
	run ./src/logksi verify test/out/records_4 test/out/records_4_only_tree_hashes.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create new logsig: with record and tree hashes" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 5 -o test/out/records_4_record_and_tree_hashes.logsig --keep-tree-hashes --keep-record-hashes -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "Block no.   1: {r.r..r.r...Mr..}" ]]
	run ./src/logksi verify test/out/records_4 test/out/records_4_record_and_tree_hashes.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create new logsig: not default algorithm" {
	run ./src/logksi create test/out/records_4 --seed test/resource/random/seed_aa --blk-size 5 -o test/out/records_4_not_default_hash_algo.logsig -H SHA2-512 -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-512:000000.*000000" "SHA-512:88fffc.*e0fbc5"` ]]
}

@test "create new logsig: from large log file" {
	run ./src/logksi create test/out/large_log --seed test/resource/random/seed_aa --blk-size 1024 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 2 1414 1 "SHA-256:000000.*000000" "SHA-256:6c293e.*9bc0ea"` ]]
	run ./src/logksi verify test/out/large_log -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 2 1414 1 "SHA-256:000000.*000000" "SHA-256:6c293e.*9bc0ea"` ]]
}

@test "create: verify metarecord" {
	run ./src/logksi verify test/out/records_4 test/out/records_4_record_and_tree_hashes.logsig --hex-to-str -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: Meta-record key  : 'com.guardtime.blockCloseReason'." ]]
	[[ "$output" =~ "Block no.   1: Meta-record value: 'Block closed due to file closure.\00'." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

# @SKIP_MEMORY_TEST
@test "create: log from stdin (no input file to activate stdin read)"  {
	run bash -c "cat test/out/records_4 | ./src/logksi create --blk-size 5 --seed test/resource/random/seed_aa -dd -o test/out/records_4_from_stdin_1"
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run ./src/logksi verify -dd test/out/records_4 test/out/records_4_from_stdin_1
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

# @SKIP_MEMORY_TEST
@test "create: log from stdin (no input file to activate stdin read) + empty --"  {
	run bash -c "cat test/out/records_4 | ./src/logksi create --blk-size 5 --seed test/resource/random/seed_aa -dd -o test/out/records_4_from_stdin_2 --"
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run ./src/logksi verify -dd test/out/records_4 test/out/records_4_from_stdin_2
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

# @SKIP_MEMORY_TEST
@test "create: log from stdin (--log-from-stdin)"  {
	run bash -c "cat test/out/records_4 | ./src/logksi create --log-from-stdin --blk-size 5 --seed test/resource/random/seed_aa -dd -o test/out/records_4_from_stdin_3"
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run ./src/logksi verify -dd test/out/records_4 test/out/records_4_from_stdin_3
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create new logsig: try to overwrite one (no actions with prev. files should be taken)" {
	run src/logksi create -dd --blk-size 16 --seed test/resource/random/seed_aa -- test/out/log_file_sequence_overwrite_one/records_*
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error:).*(Overwriting of existing log signature file).*(test\/out\/log_file_sequence_overwrite_one\/records_5.logsig).*(not allowed) ]]
	[[ "$output" =~ (Run).*(logksi create).*(with).*(--force-overwrite) ]]

	run test -f test/out/log_file_sequence_overwrite_one/records_4.logsig
	[ "$status" -ne 0 ]

	run cat test/out/log_file_sequence_overwrite_one/records_5.logsig
	[[ "$output" =~ "dummy sig 5" ]]
}

@test "create new logsig: try -- and -o with only 1 log file" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes -o test/out/records_4_4.logsig  -d -- test/out/records_4
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	run ./src/logksi verify test/out/records_4 test/out/records_4_4.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create new logsig: try linux new line" {
	run ./src/logksi create test/resource/logfiles/linux-new-line --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes --sig-dir test/out/new-line-sig  -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:ff09e8.*34a36a"` ]]
	run ./src/logksi verify test/resource/logfiles/linux-new-line --sig-dir test/out/new-line-sig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:ff09e8.*34a36a"` ]]
}

@test "create new logsig: try mac new line" {
	run ./src/logksi create test/resource/logfiles/mac-new-line --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes --sig-dir test/out/new-line-sig  -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:ff09e8.*34a36a"` ]]
	run ./src/logksi verify test/resource/logfiles/mac-new-line --sig-dir test/out/new-line-sig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:ff09e8.*34a36a"` ]]
}

@test "create new logsig: try win new line" {
	run ./src/logksi create test/resource/logfiles/win-new-line --seed test/resource/random/seed_aa --blk-size 5 --keep-record-hashes --sig-dir test/out/new-line-sig  -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:ff09e8.*34a36a"` ]]
	run ./src/logksi verify test/resource/logfiles/win-new-line --sig-dir test/out/new-line-sig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:ff09e8.*34a36a"` ]]
}

@test "create new logsig: from long long lines (from 50 .. 120000 char)" {
	run ./src/logksi create test/resource/logfiles/long-log-lines --sig-dir test/out/ --seed test/resource/random/seed_aa --blk-size 1024 -d --keep-record-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 6 1 "SHA-256:000000.*000000" "SHA-256:bf50f4.*e8a84b"` ]]
	run ./src/logksi verify test/resource/logfiles/long-log-lines --sig-dir test/out/ -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 6 1 "SHA-256:000000.*000000" "SHA-256:bf50f4.*e8a84b"` ]]
}
