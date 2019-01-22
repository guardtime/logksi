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

@test "integrate invalid log signature file that contains only magic byte" {
	run ./src/logksi integrate test/resource/logsignatures/nok-logsig-only-magick --force-overwrite -o test/out/dummy.logsig -d
	[[ "$output" =~ (Error).*(Block no).*(1).*(unable to parse KSI signature in signatures file).*(Error).*(Block no).*(1).*(unexpected end of signatures file) ]]
	[ "$status" -eq 4 ]
}

@test "integrate invalid log signature file that is empty" {
	run ./src/logksi integrate test/resource/logsignatures/nok-logsig-empty-file --force-overwrite -o test/out/dummy.logsig -d
		[[ "$output" =~ (Error).*(Unable to parse signature file).*(Error).*(Log signature file identification magic number not found) ]]
	[ "$status" -eq 4 ]
}

@test "integrate invalid log signature file that has a missing mandatory TLV" {
	run ./src/logksi integrate test/resource/logsignatures/nok-logsig-missing-mandatory-tlv --force-overwrite -o test/out/dummy.logsig -d
		[[ "$output" =~ (Error).*(unable to parse KSI signature in signatures file).*(Error).*(Mandatory element missing).*(0x800).*(0x801).*(0x3) ]]
	[ "$status" -eq 4 ]
}

@test "integrate invalid log signature file that has corrupted TLV structure 1" {
	run src/logksi integrate test/resource/logsignatures/nok-logsig-invalid-tlv-encoding-1 --force-overwrite -o test/out/dummy.ksig -d
		[[ "$output" =~ (Error).*(unable to parse KSI signature in signatures file).*(Error).*(Failed to read nested TLV) ]]
	[ "$status" -eq 4 ]
}

@test "integrate invalid log signature file that has corrupted TLV structure 2" {
	run src/logksi integrate test/resource/logsignatures/nok-logsig-invalid-tlv-encoding-2 --force-overwrite -o test/out/dummy.ksig -d
		[[ "$output" =~ (Error).*(unable to parse KSI signature in signatures file).*(Error).*(incomplete data found in signatures file) ]]
	[ "$status" -eq 4 ]
}