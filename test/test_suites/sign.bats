#!/bin/bash

export KSI_CONF=test/test.cfg

@test "sign already signed signed.logsig, identical backup is not created and original file is not modified" {
	run cp test/out/signed.logsig test/out/tmp.signed.logsig
	[ "$status" -eq 0 ]
	run ./src/logksi sign test/out/signed -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ ! "$output" =~ "creating missing KSI signature" ]]
	run test -f test/out/signed.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/signed.logsig.bak
	[ "$status" -ne 0 ]
	run diff test/out/signed.logsig test/out/tmp.signed.logsig
	[ "$status" -eq 0 ]
}

@test "sign already signed signed2.logsig to output explicitly specified output signed3.logsig" {
	run ./src/logksi sign test/out/signed2 -o test/out/signed3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ ! "$output" =~ "creating missing KSI signature" ]]
	run test -f test/out/signed3.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/signed2.logsig.bak
	[ "$status" -ne 0 ]
}

# @SKIP_MEMORY_TEST
@test "sign from standard input" {
	run bash -c "cat test/out/unsigned.logsig | ./src/logksi sign --sig-from-stdin -o test/out/signed_from_stdin.logsig -ddd"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "creating missing KSI signature" ]]
	run test -f test/out/signed_from_stdin.logsig
	[ "$status" -eq 0 ]
}

# @SKIP_MEMORY_TEST
@test "sign already signed signed2.logsig to stdout" {
	run bash -c "./src/logksi sign test/out/signed2 -ddd -o - > test/out/signed_stdout.logsig"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ ! "$output" =~ "creating missing KSI signature" ]]
	run test -f test/out/signed_stdout.logsig
	[ "$status" -eq 0 ]
	run diff test/out/signed3.logsig test/out/signed_stdout.logsig
	[ "$status" -eq 0 ]
}

@test "sign unsigned.logsig" {
	run ./src/logksi sign test/out/unsigned -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	[[ "$output" =~ "creating missing KSI signature" ]]
	run test -f test/out/unsigned.logsig
	[ "$status" -eq 0 ]
}

@test "sign and check if backup is really backup" {
	run cp  test/resource/logs_and_signatures/only-1-unsigned test/out/
	run cp  test/resource/logs_and_signatures/only-1-unsigned.logsig test/out/
	run ./src/logksi sign test/out/only-1-unsigned -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Count of resigned blocks:    1" ]]
	run test -f test/out/only-1-unsigned.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/only-1-unsigned.logsig.bak
	[ "$status" -eq 0 ]
	run diff test/resource/logs_and_signatures/only-1-unsigned.logsig test/out/only-1-unsigned.logsig.bak
	[ "$status" -eq 0 ]
	run diff test/resource/logs_and_signatures/only-1-unsigned.logsig test/out/only-1-unsigned.logsig
	[ "$status" -ne 0 ]
}

@test "Try to sign excerpt file." {
	run src/logksi sign test/resource/excerpt/log-ok.excerpt -d
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Signing... failed." ]]
	[[ "$output" =~ "Signing of excerpt file not possible! Only log signature file can be signed." ]]
}