#!/bin/bash

export KSI_CONF=test/test.cfg

echo plahh > test/out/dummy_state_cmd_1
echo plahh > test/out/dummy_state_cmd_2
echo plahh > test/out/dummy_state_cmd_1.state
echo "test/out/dummy_state_cmd_1 test/out/dummy_state_cmd_2" > test/out/dummy_state_cmd_logfile_list
mkdir -p test/out/dummy_dir


@test "create with state CMD: try to use automatically generated name with 2 inputs"  {
	run src/logksi create test/out/dummy_state_cmd_1 --blk-size 4 --seed test/resource/random/seed_aa --state -- test/out/dummy_state_cmd_2
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error:).*(In case of multiple log files --state-file-name <file> has to be used) ]]

	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --state -- test/out/dummy_state_cmd_1 test/out/dummy_state_cmd_2
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error:).*(In case of multiple log files --state-file-name <file> has to be used) ]]
	
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --state --log-file-list test/out/dummy_state_cmd_logfile_list
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error:).*(In case of multiple log files --state-file-name <file> has to be used) ]]
}

@test "create with state CMD: try to use --input-hash with existing state file"  {
	run src/logksi create test/out/dummy_state_cmd_1 --blk-size 4 --seed test/resource/random/seed_aa --state --input-hash SHA-256:20c46e471b9c26c192797aff00f2ad8633500a365c64f0fd4177df0b34498552
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error:).*(As state file .test.out.dummy_state_cmd_1.state. exists it is not possible to use --input-hash) ]]
}