#!/bin/bash

export KSI_CONF=test/test.cfg

mkdir -p test/out/state
mkdir -p test/out/state/sigdir_A
mkdir -p test/out/state/sigdir_B
mkdir -p test/out/state/sigdir_C
mkdir -p test/out/state/sigdir_D
mkdir -p test/out/state/sigdir_E
mkdir -p test/out/state/invalid-state_files
cp test/resource/logfiles/treehash1 test/out/state/logfile_1A
cp test/resource/logfiles/treehash2 test/out/state/logfile_2A
cp test/resource/logfiles/treehash1 test/out/state/logfile_1B
cp test/resource/logfiles/treehash2 test/out/state/logfile_2B

cp test/resource/state_file/invalid-hash-03-alg.state test/out/state/invalid-state_files/
cp test/resource/state_file/invalid-hash-7e-alg.state test/out/state/invalid-state_files/
cp test/resource/state_file/missing-bytes.state test/out/state/invalid-state_files/
cp test/resource/state_file/sha1.state test/out/state/invalid-state_files/
cp test/resource/state_file/too-many-bytes.state test/out/state/invalid-state_files/
cp test/resource/state_file/unknown-magic-1.state test/out/state/invalid-state_files/
cp test/resource/state_file/unknown-magic-2.state test/out/state/invalid-state_files/
cp test/resource/state_file/wrong-algo-size.state test/out/state/invalid-state_files/
cp test/resource/state_file/no-digest.state test/out/state/invalid-state_files/
cp test/resource/state_file/no-digest-and-len.state test/out/state/invalid-state_files/
cp test/resource/state_file/only-magic-and-algo.state test/out/state/invalid-state_files/
cp test/resource/state_file/only-magic.state test/out/state/invalid-state_files/



export KSI_CONF=test/test.cfg
# block_count, rec_hash_count, meta_rec_count, ih, oh
f_summary_of_logfile_short () {
	 echo "(Summary of logfile:).( . Count of blocks:             $1).( . Count of record hashes:      $2).( . Count of meta-records:       $3).( . Input hash:  $4).( . Output hash: $5)"
}




@test "create with state file: use --input-hash to initialize new state file (1 log file)"  {
	run src/logksi create test/out/state/logfile_2A --blk-size 16 --seed test/resource/random/seed_aa --state --sig-dir test/out/state/sigdir_E --input-hash SHA-256:20c46e471b9c26c192797aff00f2ad8633500a365c64f0fd4177df0b34498552 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]

	run xxd -p -c 100 test/out/state/sigdir_E/logfile_2A.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(01)(20)(44883d33f25a470c6fd0c9d6bb5404fe8762ef85a4b27cd901695919ac7afe98) ]]

	run ./src/logksi verify test/out/state/logfile_2A --sig-dir test/out/state/sigdir_E -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}

@test "create with state file: default state files" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state -- test/out/state/logfile_1A
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run xxd -p -c 100 test/out/state/logfile_1A.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(01)(20)(20c46e471b9c26c192797aff00f2ad8633500a365c64f0fd4177df0b34498552) ]]

	run ./src/logksi verify test/out/state/logfile_1A -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create with state file: default state files name 2 logs with simulated log rotation" {
	run cp test/resource/logfiles/treehash1 test/out/state/logfile_rotation
	[ "$status" -eq 0 ]

	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 16 -d --state test/out/state/logfile_rotation
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run xxd -p -c 100 test/out/state/logfile_rotation.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(01)(20)(20c46e471b9c26c192797aff00f2ad8633500a365c64f0fd4177df0b34498552) ]]



	run \cp test/resource/logfiles/treehash2 test/out/state/logfile_rotation
	[ "$status" -eq 0 ]

	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 16 -d --force-overwrite --state test/out/state/logfile_rotation
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]

	run xxd -p -c 100 test/out/state/logfile_rotation.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(01)(20)(44883d33f25a470c6fd0c9d6bb5404fe8762ef85a4b27cd901695919ac7afe98) ]]

	run ./src/logksi verify test/out/state/logfile_rotation -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}

@test "create with state file: explicit state file name with 2 inputs" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 16 -d --state --state-file-name test/out/state/logfile_1B_2B.state -- test/out/state/logfile_1B test/out/state/logfile_2B
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]

	run test -f test/out/state/logfile_1B.state
	[ "$status" -ne 0 ]
	run test -f test/out/state/logfile_2B.state
	[ "$status" -ne 0 ]

	run xxd -p -c 100 test/out/state/logfile_1B_2B.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(01)(20)(44883d33f25a470c6fd0c9d6bb5404fe8762ef85a4b27cd901695919ac7afe98) ]]

	run ./src/logksi verify -d -- test/out/state/logfile_1B test/out/state/logfile_2B
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-256:20c46e.*498552" "SHA-256:44883d.*7afe98"` ]]
}

@test "create with state file: --state with --sig-dir" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --sig-dir test/out/state/sigdir_A -- test/out/state/logfile_1A
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run xxd -p -c 100 test/out/state/sigdir_A/logfile_1A.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(01)(20)(20c46e471b9c26c192797aff00f2ad8633500a365c64f0fd4177df0b34498552) ]]

	run ./src/logksi verify --sig-dir test/out/state/sigdir_A test/out/state/logfile_1A -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create with state file: --state with --sig-dir and --state-file-name" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --sig-dir test/out/state/sigdir_B --state-file-name test/out/state/logfile_1A_sig_dir_escape.state -- test/out/state/logfile_1A
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]

	run xxd -p -c 100 test/out/state/logfile_1A_sig_dir_escape.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(01)(20)(20c46e471b9c26c192797aff00f2ad8633500a365c64f0fd4177df0b34498552) ]]

	run ./src/logksi verify --sig-dir test/out/state/sigdir_B test/out/state/logfile_1A -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-256:000000.*000000" "SHA-256:20c46e.*498552"` ]]
}

@test "create with state file: new state with -H SHA-512" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 16 -d -H sha512 -o test/out/state/dont_care_1.logsig --state --state-file-name test/out/state/sha512.state -- test/out/state/logfile_1A
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 4 1 "SHA-512:000000.*000000" "SHA-512:88fffc.*e0fbc5"` ]]

	run xxd -p -c 100 test/out/state/sha512.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(05)(40)(88fffc8a82c342ce65b687e117fedc45953bbf302505525ffd359e16a293a9accd1f0dab2dda7b0a1d13b1b97f2d950cfbd2c70b6075d987b00c37a339e0fbc5) ]]
}

@test "create with state file: check if hash algorithm is taken from the state file" {
	run cp test/resource/state_file/sha512.state test/out/state/sigdir_C/logfile_2A.state
	[ "$status" -eq 0 ]

	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 16 -d --sig-dir test/out/state/sigdir_C --state -- test/out/state/logfile_2A
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-512:88fffc.*e0fbc5" "SHA-512:7dfdef.*51720f"` ]]

	run xxd -p -c 100 test/out/state/sigdir_C/logfile_2A.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(05)(40)(7dfdefc806e963852521dc0db8baba24917716ac8cbdee8f5bb32e2211735f0bba8e74c3193950109df581a74e488f81b81fd09ac908879f9e3c62566951720f) ]]

	run ./src/logksi verify -d --sig-dir test/out/state/sigdir_C -- test/out/state/logfile_2A
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-512:88fffc.*e0fbc5" "SHA-512:7dfdef.*51720f"` ]]
}

@test "create with state file: override has algorithm from state file with -H SHA-384" {
	run cp test/resource/state_file/sha512.state test/out/state/sigdir_D/logfile_2A.state
	[ "$status" -eq 0 ]

	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 16 -d -H sha384 --sig-dir test/out/state/sigdir_D --state -- test/out/state/logfile_2A
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-512:88fffc.*e0fbc5" "SHA-384:85a286.*23245c"` ]]

	run xxd -p -c 100 test/out/state/sigdir_D/logfile_2A.state
	[ "$status" -eq 0 ]
	[[ "$output" =~ (4b5349535441543130)(04)(30)(85a28666547c49f16411169cfd0a64e18d1a54e46649316c9807225698dacfdaec26e37c99051c104102ee5d4523245c) ]]

	run ./src/logksi verify -d --sig-dir test/out/state/sigdir_D -- test/out/state/logfile_2A
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 1 5 1 "SHA-512:88fffc.*e0fbc5" "SHA-384:85a286.*23245c"` ]]
}

@test "create with state file: invalid hash algorithm in state" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state-file-name test/out/state/invalid-state_files/invalid-hash-03-alg.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 10 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(invalid-hash-03-alg.state).*(The hash algorithm ID is invalid) ]]
	
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state-file-name test/out/state/invalid-state_files/invalid-hash-7e-alg.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 10 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(invalid-hash-7e-alg.state).*(The hash algorithm ID is invalid) ]]
}

@test "create with state file: not trusted hash algorithm in state file" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state-file-name test/out/state/invalid-state_files/sha1.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 10 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(sha1.state).*(The hash algorithm is not trusted) ]]
}

@test "create with state file: invalid magic bytes" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --state-file-name test/out/state/invalid-state_files/unknown-magic-1.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 4 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(unknown-magic-1.state).*(Invalid input data format) ]]

	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --state-file-name test/out/state/invalid-state_files/unknown-magic-2.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 4 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(unknown-magic-2.state).*(Invalid input data format) ]]
}

@test "create with state file: missing bytes from the end of digest" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --state-file-name test/out/state/invalid-state_files/missing-bytes.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 1 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(missing-bytes.state).*(Unexpected end of file) ]]
}

@test "create with state file: the size of the digest does not match with the algorithm" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --state-file-name test/out/state/invalid-state_files/wrong-algo-size.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 4 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(wrong-algo-size.state).*(Invalid input data format) ]]
}

@test "create with state file: trailing bytes after state file" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --state-file-name test/out/state/invalid-state_files/too-many-bytes.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 4 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(too-many-bytes.state).*(Invalid input data format) ]]
}

@test "create with state file: missing mandatory components" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --state-file-name test/out/state/invalid-state_files/only-magic-and-algo.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 1 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(only-magic-and-algo.state).*(Unexpected end of file) ]]

	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --state-file-name test/out/state/invalid-state_files/no-digest-and-len.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 1 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(no-digest-and-len.state).*(Unexpected end of file) ]]

	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --state-file-name test/out/state/invalid-state_files/no-digest.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 1 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(no-digest.state).*(Unexpected end of file) ]]
}

@test "create with state file: only magic" {
	run ./src/logksi create --seed test/resource/random/seed_aa --blk-size 5 -d --state --state-file-name test/out/state/invalid-state_files/only-magic.state --force-overwrite -o test/out/state/dummy.logsig -- test/out/state/logfile_1A
	[ "$status" -eq 1 ]
	[[ "$output" =~ (Error).*(Unable to open state file).*(only-magic.state).*(Unexpected end of file) ]]
}
