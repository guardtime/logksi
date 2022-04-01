#!/bin/bash

export KSI_CONF=test/test.cfg


# block_count, rec_hash_count, meta_rec_count, ih, oh
f_summary_of_logfile_short () {
	 echo "(Summary of logfile:).( . Count of blocks:             $1).( . Count of record hashes:      $2).( . Count of meta-records:       $3).( . Input hash:  $4).( . Output hash: $5)"
}

mkdir -p test/out/log_file_list
mkdir -p test/out/log_file_list_sig1
mkdir -p test/out/log_file_list_sig_overwrite_all
mkdir -p test/out/log_file_list_sig_overwrite_one

cp test/resource/logfiles/treehash1 test/out/log_file_list/records_4
cp test/resource/logfiles/treehash2 test/out/log_file_list/records_5
echo  "test/out/log_file_list/records_4 test/out/log_file_list/records_5" > test/out/log_file_list_ok1

echo "dummy sig 4" > test/out/log_file_list_sig_overwrite_all/records_4.logsig
echo "dummy sig 5" > test/out/log_file_list_sig_overwrite_all/records_5.logsig
echo "dummy sig 5" > test/out/log_file_list_sig_overwrite_one/records_5.logsig


@test "create log-file-list: try to overwrite one (no actions with prev. files should be taken)" {
	run src/logksi create --log-file-list test/out/log_file_list_ok1 --sig-dir test/out/log_file_list_sig_overwrite_one -dd --blk-size 16 --seed test/resource/random/seed_aa
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error:).*(Overwriting of existing log signature file).*(test\/out\/log_file_list_sig_overwrite_one\/records_5.logsig).*(not allowed) ]]
	[[ "$output" =~ (Run).*(logksi create).*(with).*(--force-overwrite) ]]

	run test -f test/out/log_file_list_sig_overwrite_one/records_4.logsig
	[ "$status" -ne 0 ]

	run cat test/out/log_file_list_sig_overwrite_one/records_5.logsig
	[[ "$output" =~ "dummy sig 5" ]]
}

@test "create log-file-list: try to overwrite all" {
	run src/logksi create --log-file-list test/out/log_file_list_ok1 --sig-dir test/out/log_file_list_sig_overwrite_all -dd --blk-size 16 --seed test/resource/random/seed_aa
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error:).*(Overwriting of existing log signature file).*(test\/out\/log_file_list_sig_overwrite_all\/records_4.logsig).*(not allowed) ]]
	[[ "$output" =~ (Run).*(logksi create).*(with).*(--force-overwrite) ]]

	run cat test/out/log_file_list_sig_overwrite_all/records_4.logsig
	[[ "$output" =~ "dummy sig 4" ]]

	run cat test/out/log_file_list_sig_overwrite_all/records_5.logsig
	[[ "$output" =~ "dummy sig 5" ]]
}

@test "create log-file-list: overwrite existing (all)" {
	run src/logksi create --log-file-list test/out/log_file_list_ok1 --sig-dir test/out/log_file_list_sig_overwrite_all -dd --blk-size 16 --seed test/resource/random/seed_aa --force-overwrite
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
	
	run ./src/logksi verify --log-file-list test/out/log_file_list_ok1 --sig-dir test/out/log_file_list_sig_overwrite_all -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}

@test "create log-file-list: store to sig-dir" {
	run src/logksi create --log-file-list test/out/log_file_list_ok1 --sig-dir test/out/log_file_list_sig1 -dd --blk-size 16 --seed test/resource/random/seed_aa
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
	
	run ./src/logksi verify --log-file-list test/out/log_file_list_ok1 --sig-dir test/out/log_file_list_sig1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}
