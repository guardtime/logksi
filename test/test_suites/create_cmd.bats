#!/bin/bash

export KSI_CONF=test/test.cfg

cp test/resource/logs_and_signatures/unsigned test/out/dummy_cmd
mkdir -p test/out/dummy_dir


@test "create CMD test: stdin and file input (input) 1"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-from-stdin test/out/dummy_cmd
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Maybe you want to: Create from stdin).*(--seed -S --log-from-stdin one or more of).*(--max-lvl --blk-size) ]]
}

@test "create CMD test: stdin and file input (after --) 2"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa --log-from-stdin -- test/out/dummy_cmd test/out/dummy_cmd
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Maybe you want to: Create from stdin).*(--seed -S --log-from-stdin one or more of).*(--max-lvl --blk-size) ]]
}

@test "create CMD test: try to use invalid stdout combination" {
	run src/logksi create test/out/dummy_cmd --seed test/resource/random/seed_aa --blk-size 4 -o - -d --log - --output-hash -
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Multiple different simultaneous outputs to stdout).*(--log -, --output-hash -, -o -) ]]

	run src/logksi create test/out/dummy_cmd --seed test/resource/random/seed_aa --blk-size 4 -o - -d --output-hash -
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (--output-hash -, -o -)." ]]
}

@test "create CMD test: try to use invalid stdin combination" {
	run src/logksi create test/out/dummy_cmd --blk-size 4 --seed - --input-hash -
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Multiple different simultaneous inputs from stdin).*(--input-hash -, --seed -) ]]

	run src/logksi create --blk-size 4 --seed - --log-from-stdin
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Multiple different simultaneous inputs from stdin).*(--seed -, --log-from-stdin) ]]

	run src/logksi create --blk-size 4 --seed - --input-hash - --log-file-list -
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Multiple different simultaneous inputs from stdin).*(--input-hash -, --seed -, --log-file-list -) ]]
}

@test "create CMD test: try to use invalid stdin combination (no input file)" {
	run src/logksi create --blk-size 4 --seed -
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Multiple different simultaneous inputs from stdin).*(--seed -, --log-from-stdin) ]]

	run src/logksi create --blk-size 4 --seed - --
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Multiple different simultaneous inputs from stdin).*(--seed -, --log-from-stdin) ]]

	run src/logksi create --blk-size 4 --input-hash - --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Multiple different simultaneous inputs from stdin).*(--input-hash -, --log-from-stdin) ]]
}

@test "create CMD test: try to use create without block size" {
	run src/logksi create test/out/dummy_cmd --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ "You have to define at least one of the flag(s) '--max-lvl', '--blk-size'" ]]
}

@test "create CMD test: try to use too large max-lvl"  {
	run src/logksi create test/out/dummy_cmd --max-lvl 256 --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Tree depth out of range).*(max-lvl).*('256') ]]
}

@test "create CMD test: try to use negative max-lvl"  {
	run src/logksi create test/out/dummy_cmd --max-lvl -5 --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Tree depth out of range).*(max-lvl).*('-5') ]]
}

@test "create CMD test: try to use invalid max-lvl"  {
	run src/logksi create test/out/dummy_cmd --max-lvl zzz --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Invalid integer).*(max-lvl).*('zzz') ]]

	run src/logksi create test/out/dummy_cmd --max-lvl -z --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Invalid integer).*(max-lvl).*('-z') ]]

	run src/logksi create test/out/dummy_cmd --max-lvl --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Parameter must have value).*(max-lvl).*('') ]]
}

@test "create CMD test: try to use blk-size 0"  {
	run src/logksi create test/out/dummy_cmd --blk-size 0 --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Integer value is too small).*(blk-size).*('0') ]]
}

@test "create CMD test: try to use blk-size larger than provided by max-lvl"  {
	run src/logksi create test/out/dummy_cmd --max-lvl 8 --blk-size 257 --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(257).*(as tree level).*(8).*(results tree with).*(256).*(leafs) ]]

	run src/logksi create test/out/dummy_cmd --max-lvl 15 --blk-size 65535 --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(65535).*(as tree level).*(15).*(results tree with).*(32768).*(leafs) ]]

	run src/logksi create test/out/dummy_cmd --max-lvl 31 --blk-size 4294967295 --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(4294967295).*(as tree level).*(31).*(results tree with).*(2147483648).*(leafs) ]]
}

@test "create CMD test: try to use blk-size larger than provided by --apply-remote-conf" {
	run src/logksi create test/out/dummy_cmd --blk-size 4294967295 --seed test/resource/random/seed_aa -S file://test/resource/server/ok_aggr_conf.tlv --apply-remote-conf
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(4294967295).*(as tree level).*(17).*(results tree with).*(131072).*(leafs) ]]
}

@test "create CMD test: override --apply-remote-conf with --max-lvl" {
	run src/logksi create test/out/dummy_cmd --blk-size 4294967295 --seed test/resource/random/seed_aa -S file://test/resource/server/ok_aggr_conf.tlv --max-lvl 8 --apply-remote-conf
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(4294967295).*(as tree level).*(8).*(results tree with).*(256).*(leafs) ]]

run src/logksi create test/out/dummy_cmd --blk-size 4294967295 --seed test/resource/random/seed_aa -S file://test/resource/server/ok_aggr_conf.tlv --apply-remote-conf --max-lvl 8
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(4294967295).*(as tree level).*(8).*(results tree with).*(256).*(leafs) ]]
}

@test "create CMD test: override --max-lvl from conf file with --apply-remote-conf" {
	run src/logksi create test/out/dummy_cmd --blk-size 4294967295 --seed test/resource/random/seed_aa --conf test/resource/conf/max-lvl-5.cfg
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(4294967295).*(as tree level).*(5).*(results tree with).*(32).*(leafs) ]]
	
	run src/logksi create test/out/dummy_cmd --blk-size 4294967295 --seed test/resource/random/seed_aa --conf test/resource/conf/max-lvl-5.cfg --apply-remote-conf
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(4294967295).*(as tree level).*(17).*(results tree with).*(131072).*(leafs) ]]
}

@test "create CMD test: override --max-lvl from conf file with --max-lvl on cmd" {
	run src/logksi create test/out/dummy_cmd --blk-size 4294967295 --seed test/resource/random/seed_aa --conf test/resource/conf/max-lvl-5.cfg --max-lvl 8
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(4294967295).*(as tree level).*(8).*(results tree with).*(256).*(leafs) ]]
}

@test "create CMD test: try to use blk-size larger than provided by --apply-remote-conf" {
	run src/logksi create test/out/dummy_cmd --blk-size 4294967295 --seed test/resource/random/seed_aa -S file://test/resource/server/ok_aggr_conf.tlv --apply-remote-conf
	[ "$status" -eq 3 ]
	[[ "$output" =~ (It is not possible to use blk-size).*(4294967295).*(as tree level).*(17).*(results tree with).*(131072).*(leafs) ]]
}

@test "create CMD test: try to use only one not existing input file"  {
	run src/logksi create i_do_not_exist do_not_exist2 --blk-size 4 --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(<logfile>).*(i_do_not_exist) ]]
}

@test "create CMD test: try to use two not existing input files"  {
	run src/logksi create i_do_not_exist i_do_not_exist2 --blk-size 4 --seed test/resource/random/seed_aa
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(<logfile>).*(i_do_not_exist) ]]
	[[ "$output" =~ (File does not exist).*(Parameter).*(<logfile>).*(i_do_not_exist2) ]]
}

@test "create CMD test: try to use multiple not existing log files after -- 1"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa -- i_do_not_exist2
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(-- \'i_do_not_exist2) ]]
}

@test "create CMD test: try to use multiple not existing log files after -- 2"  {
	run src/logksi create i_do_not_exist --blk-size 4 --seed test/resource/random/seed_aa -- i_do_not_exist2
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(<logfile>).*(i_do_not_exist) ]]
	[[ "$output" =~ (File does not exist).*(Parameter).*(-- \'i_do_not_exist2) ]]
}

@test "create CMD test: try to use multiple not existing log files after -- 3"  {
	run src/logksi create i_do_not_exist --blk-size 4 --seed test/resource/random/seed_aa -- i_do_not_exist2 i_do_not_exist3
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(<logfile>).*(i_do_not_exist) ]]
	[[ "$output" =~ (File does not exist).*(Parameter).*(-- \'i_do_not_exist2) ]]
	[[ "$output" =~ (File does not exist).*(Parameter).*(-- \'i_do_not_exist3) ]]
}

@test "create CMD test: two inputs"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa test/out/dummy_cmd test/out/dummy_cmd
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Only one log file is required, but there are 2!).*(Additional info).*(Suggestion:  To create log signature from multiple log files see parameter --.) ]]
}

@test "create CMD test: try to use both -o and --sig-dir"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa test/out/dummy_cmd -o test/out/dummy_o_and_sig_dir.logsig --sig-dir test/out
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Both -o and --sig-dir can not be used simultaneously!) ]]

	run test -f test/out/dummy_o_and_sig_dir.logsig
	[ "$status" -ne 0 ]
}

@test "create CMD test: try to store multiple log signatures with -o"  {
	run ./src/logksi create test/out/dummy_cmd -dd --seed test/resource/random/seed_aa --blk-size 16 -o test/out/plah_x -- test/out/dummy_cmd
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error).*(It is not possible to specify explicit output signature file name for multiple input log signature files) ]]
	[[ "$output" =~ (Suggestion).*(To store log signature files with automatically generated names to specified directory see parameter --sig-dir) ]]

	run ./src/logksi create -dd --seed test/resource/random/seed_aa --blk-size 16 -o test/out/plah_x -- test/out/dummy_cmd test/out/dummy_cmd
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error).*(It is not possible to specify explicit output signature file name for multiple input log signature files) ]]
	[[ "$output" =~ (Suggestion).*(To store log signature files with automatically generated names to specified directory see parameter --sig-dir) ]]
}

@test "create CMD test: try to use invalid input hash 1"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa test/out/dummy_cmd --input-hash plahh
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist.).*(from).*(CMD).*(--input-hash).*(plahh) ]]
}

@test "create CMD test: try to use invalid input hash 2"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa test/out/dummy_cmd --input-hash sha256:aabb
	[ "$status" -eq 4 ]
	[[ "$output" =~ (Error: Unable to extract input hash value!) ]]
}

@test "create CMD test: input file - is not interpreted as stdin"  {
	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa -d -
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(from).*('CMD').*([<]logfile[>]).*('-') ]]

	run src/logksi create --blk-size 4 --seed test/resource/random/seed_aa -d -- -
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(from).*('CMD').*([-][-]).*('-') ]]
}
