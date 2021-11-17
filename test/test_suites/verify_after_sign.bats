#!/bin/bash

export KSI_CONF=test/test.cfg

cp test/resource/logfiles/signed test/out/signed4

@test "verify signed.logsig" {
	run ./src/logksi verify --ver-int test/out/signed -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed4 and signed3.logsig" {
	run ./src/logksi verify --ver-int test/out/signed4 test/out/signed3.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify unsigned.logsig" {
	run ./src/logksi verify --ver-int test/out/unsigned -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "Verify only-1-unsigned.logsig." {
	run ./src/logksi verify --ver-int test/out/only-1-unsigned test/out/only-1-unsigned.logsig -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}