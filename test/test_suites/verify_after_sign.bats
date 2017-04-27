#!/bin/bash

export KSI_CONF=test/test.cfg

cp test/resource/logfiles/signed test/out/signed4

@test "verify signed.logsig" {
	run ./src/logksi verify test/out/signed -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed4 and signed3.logsig" {
	run ./src/logksi verify test/out/signed4 test/out/signed3.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify unsigned.logsig" {
	run ./src/logksi verify test/out/unsigned -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}
