#!/bin/bash

export KSI_CONF=test/test.cfg

cp -r test/resource/logsignatures/signed.logsig.parts test/out

@test "integrate signed.parts" {
	run ./src/logksi integrate test/out/signed -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed.logsig
	[ "$status" -eq 0 ]
}

@test "integrate signed.parts to output signed2.logsig" {
	run ./src/logksi integrate test/out/signed -o test/out/signed2.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed2.logsig
	[ "$status" -eq 0 ]
}

@test "try integrating signed.parts again" {
	run chmod 0444 test/out/signed.logsig
	run ./src/logksi integrate test/out/signed -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ " Error: overwriting of existing output log signature" ]]
	run test -f test/out/signed.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/signed.logsig.bak
	[ "$status" -ne 0 ]
	run chmod 0777 test/out/signed.logsig
}

@test "integrate signed.parts (again) to stdout" {
	run bash -c "./src/logksi integrate test/out/signed -d -o - > test/out/signed2_stdout.logsig"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed2_stdout.logsig
	[ "$status" -eq 0 ]
	run diff test/out/signed2.logsig test/out/signed2_stdout.logsig
	[ "$status" -eq 0 ]
}

cp -r test/resource/logsignatures/unsigned.logsig.parts test/out

@test "integrate unsigned.parts" {
	run ./src/logksi integrate test/out/unsigned -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/unsigned.logsig
	[ "$status" -eq 0 ]
}

cp test/resource/logsignatures/synchronous.logsig test/out

@test "integrate synchronous.logsig" {
	run chmod 0444 test/out/synchronous.logsig
	run ./src/logksi integrate test/out/synchronous -d
	[ "$status" -eq 0 ]
	run test -f test/out/synchronous.logsig.bak
	[ "$status" -ne 0 ]
	run chmod 0777 test/out/synchronous.logsig
}

