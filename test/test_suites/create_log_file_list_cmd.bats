#!/bin/bash

export KSI_CONF=test/test.cfg

echo A log line > test/out/dummy
mkdir -p test/out/dummy_dir
echo test/out/dummy > test/out/dummy-log-file-list

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: try to use one not existing log files from log file list"  {
	run bash -c "echo test/out/this_file_does_not_exist | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list -"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'test\/out\/this_file_does_not_exist\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Unable to include input log files from log file list).*(<stdin>) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: try to use multiple not existing log files from log file list"  {
	run bash -c "echo test/out/this_file_does_not_exist_1 test/out/this_file_does_not_exist_2 | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list -"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'test\/out\/this_file_does_not_exist_1\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'test\/out\/this_file_does_not_exist_2\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Unable to include input log files from log file list).*(<stdin>) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: try to use directory in log files list"  {
	run bash -c "echo test/out/dummy_dir | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list -"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'test\/out\/dummy_dir\').*(can not be a directory) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Unable to include input log files from log file list).*(<stdin>) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: use empty lines in log files list (must be ignored)"  {
	run bash -c "printf '\n\n \n  test/out/this_file_does_not_exist  \n\n  \n' | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list -"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'test\/out\/this_file_does_not_exist\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Unable to include input log files from log file list).*(<stdin>) ]]

	run bash -c "printf '\n\n \n  test/out/this_file_does_not_exist  \n\n  \n' | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter new-line"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'test\/out\/this_file_does_not_exist\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Unable to include input log files from log file list).*(<stdin>) ]]

	run bash -c "printf '\n\n \n  test/out/this_file_does_not_exist  \n\n  \n' | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter space"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'test\/out\/this_file_does_not_exist\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Unable to include input log files from log file list).*(<stdin>) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: try to use - and -- in log file list (must be handled as files)"  {
	run bash -c "printf '\-\n\-\-\n' | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list -"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'-\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'--\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Unable to include input log files from log file list).*(<stdin>) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: default delimiter (space) handles spaces"  {
	run bash -c "echo aa bb cc | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list -"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'aa\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: delimiter new line handles spaces"  {
	run bash -c "echo aa bb cc | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter new-line"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'aa bb cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: delimiter space handles spaces"  {
	run bash -c "echo aa bb cc | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter space"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'aa\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: double quote handles spaces"  {
	run bash -c "echo \\\"aa bb\\\" cc | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter space"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'aa bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: single quote handles spaces"  {
	run bash -c "echo \'aa bb\' cc | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter space"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'aa bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: backslash handles spaces"  {
	run bash -c "echo aa\\\\ bb cc | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter space"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'aa bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: custom delimiter"  {
	run bash -c "echo aa bb:cc | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter :"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'aa bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: custom delimiter, several empty"  {
	run bash -c "echo ::aa bb:cc:: | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter :"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'aa bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: custom delimiter, leading white space"  {
	run bash -c "echo :  aa bb:cc:  : | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter :"
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'aa bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list <stdin>).*(\'\').*(does not exist) ]]
}


@test "create log-file-list CMD test: mac line endings"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list test/resource/log_file_list/osx-line-end
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/osx-line-end).*(\'aa\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/osx-line-end).*(\'bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/osx-line-end).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/osx-line-end).*(\'\').*(does not exist) ]]

	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list test/resource/log_file_list/osx-line-end --log-file-list-delimiter new-line
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/osx-line-end).*(\'aa bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/osx-line-end).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/osx-line-end).*(\'\').*(does not exist) ]]
}

@test "create log-file-list CMD test: win line endings"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list test/resource/log_file_list/windoes-line-end
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/windoes-line-end).*(\'aa\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/windoes-line-end).*(\'bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/windoes-line-end).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/windoes-line-end).*(\'\').*(does not exist) ]]

	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list test/resource/log_file_list/windoes-line-end --log-file-list-delimiter new-line
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/windoes-line-end).*(\'aa bb\').*(does not exist) ]]
	[[ "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/windoes-line-end).*(\'cc\').*(does not exist) ]]
	[[ ! "$output" =~ (Error).*(Log file).*(from --log-file-list test\/resource\/log_file_list\/windoes-line-end).*(\'\').*(does not exist) ]]
}

# @SKIP_MEMORY_TEST
@test "create log-file-list CMD test: try to use invalid delimiter"  {
	run bash -c "echo aa bb cc | src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list - --log-file-list-delimiter ::"
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Invalid delimiter).*(Only \'new-line\', \'space\' or one of).*(is supported).*(--log-file-list-delimiter \'::\') ]]
}

@test "create log-file-list CMD test: try to use --log-file-list with other log file inputs"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list test/out/dummy-log-file-list --log-from-stdin
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Maybe you want to:).*( Create from log file list) ]]
	[[ "$output" =~ (Maybe you want to:).*( Create from file) ]]
	[[ "$output" =~ (Maybe you want to:).*( Create from stdin) ]]

	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list test/out/dummy-log-file-list -- test/out/dummy
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Maybe you want to:).*( Create from log file list) ]]
	[[ "$output" =~ (Maybe you want to:).*( Create from file) ]]
	[[ "$output" =~ (Maybe you want to:).*( Create from stdin) ]]

	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list test/out/dummy-log-file-list test/out/dummy
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Maybe you want to:).*( Create from log file list) ]]
	[[ "$output" =~ (Maybe you want to:).*( Create from file) ]]
	[[ "$output" =~ (Maybe you want to:).*( Create from stdin) ]]
}

@test "create log-file-list CMD test: try to use --log-file-list with -o"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-file-list test/out/dummy-log-file-list -o test/out/create-dummy-with-o.logsig
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error).*(It is not possible to specify explicit output signature file name for log file list) ]]
}
