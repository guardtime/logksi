#!/bin/bash

export KSI_CONF=test/test.cfg
echo dummy string > test/out/dummy.logsig
cp -r test/resource/logsignatures/signed.logsig.parts test/out/dummy.logsig.parts

@test "integrate CMD test: try to use invalid stdout combination 1" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o - --log -
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (-o -, --log -)." ]]
	[ "$status" -eq 3 ]
}

@test "integrate CMD test: try to use invalid stdout combination 2" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o - --out-log -
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (-o -, --out-log -)." ]]
	[ "$status" -eq 3 ]
}

@test "integrate CMD test: try to use log signature parts that do not exist" {
	run ./src/logksi integrate i_do_not_exist
	[[ "$output" =~ "Error: Unable to find input blocks file i_do_not_exist.logsig.parts/blocks.dat" ]]
	[ "$status" -eq 6 ]
}

@test "integrate CMD test: try to write into existing file 1" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.logsig
	[[ "$output" =~ (Error).*(Overwriting of existing log signature file).*(dummy.logsig).*(Run .logksi integrate. with .--force-overwrite. to force overwriting) ]]
	[ "$status" -eq 9 ]
	run cat test/out/dummy.logsig
	[[ "$output" =~ "dummy string" ]]
}

@test "integrate CMD test: try to write into existing file 2" {
	run ./src/logksi integrate test/out/dummy
	[[ "$output" =~ (Error).*(Overwriting of existing log signature file).*(dummy.logsig).*(Run .logksi integrate. with .--force-overwrite. to force overwriting) ]]
	[ "$status" -eq 9 ]
	run cat test/out/dummy.logsig
	[[ "$output" =~ "dummy string" ]]
}