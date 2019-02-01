#!/bin/bash

export KSI_CONF=test/test.cfg

cp -r test/resource/logsignatures/signed.logsig.parts test/out

@test "integrate signed.parts" {
	run ./src/logksi integrate test/out/signed -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed.logsig
	[ "$status" -eq 0 ]
}

@test "integrate signed.parts to output signed2.logsig" {
	run ./src/logksi integrate test/out/signed -o test/out/signed2.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed2.logsig
	[ "$status" -eq 0 ]
}

@test "integrate signed.parts to output signed_all_final_hashes.logsig" {
	run ./src/logksi integrate test/out/signed -o test/out/signed_all_final_hashes.logsig -ddd --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed_all_final_hashes.logsig
	[ "$status" -eq 0 ]
}

@test "try integrating signed.parts again" {
	run chmod 0444 test/out/signed.logsig
	run ./src/logksi integrate test/out/signed -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ " Error: Overwriting of existing log signature" ]]
	run test -f test/out/signed.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/signed.logsig.bak
	[ "$status" -ne 0 ]
	run chmod 0777 test/out/signed.logsig
}

@test "integrate signed.parts to output overwritten.logsig" {
	run ./src/logksi integrate test/out/signed -o test/out/overwritten.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/overwritten.logsig
	[ "$status" -eq 0 ]
}

@test "integrate signed.parts to output overwritten.logsig, force overwriting and insert missing hashes" {
	run ./src/logksi integrate test/out/signed -o test/out/overwritten.logsig -ddd --force-overwrite --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/overwritten.logsig
	[ "$status" -eq 0 ]
}

@test "integrate signed.parts (again) to stdout" {
	run bash -c "./src/logksi integrate test/out/signed -ddd -o - > test/out/integrated_stdout.logsig"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/integrated_stdout.logsig
	[ "$status" -eq 0 ]
	run diff test/out/signed2.logsig test/out/integrated_stdout.logsig
	[ "$status" -eq 0 ]
}

cp -r test/resource/logsignatures/unsigned.logsig.parts test/out

@test "integrate unsigned.parts" {
	run ./src/logksi integrate test/out/unsigned -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/unsigned.logsig
	[ "$status" -eq 0 ]
}

@test "integrate unsigned.parts to output unsigned_all_final_hashes.logsig" {
	run ./src/logksi integrate test/out/unsigned -o test/out/unsigned_all_final_hashes.logsig -ddd --insert-missing-hashes
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/unsigned_all_final_hashes.logsig
	[ "$status" -eq 0 ]
}

cp test/resource/logsignatures/synchronous.logsig test/out

@test "integrate synchronous.logsig" {
	run chmod 0444 test/out/synchronous.logsig
	run ./src/logksi integrate test/out/synchronous -ddd
	[ "$status" -eq 0 ]
	run test -f test/out/synchronous.logsig.bak
	[ "$status" -ne 0 ]
	run chmod 0777 test/out/synchronous.logsig
}

@test "integrate log signature where blocks.dat contains corrupted meta-data record" {
	run src/logksi integrate test/resource/logsignatures/nok-corrupted-metadata -o test/out/dummy.logsig --force-overwrite -d
	[ "$status" -eq 4 ]
	[[ "$output" =~ (Error:).*(Block no. 4).*(Unable to get TLV 911.02.01).*(Meta record key) ]]
}
