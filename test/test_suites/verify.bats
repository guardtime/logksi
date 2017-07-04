#!/bin/bash

export KSI_CONF=test/test.cfg

@test "verify unsigned.logsig" {
	run ./src/logksi verify test/out/unsigned -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify unsigned.logsig internally" {
	run ./src/logksi verify --ver-int test/out/unsigned -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify unsigned.logsig against calendar" {
	run ./src/logksi verify --ver-cal test/out/unsigned -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify unsigned.logsig against key" {
	run ./src/logksi verify --ver-key test/out/unsigned -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "try verifying unsigned.logsig against signed logfile" {
	run ./src/logksi verify test/out/signed test/out/unsigned.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify compressed log from stdin" {
	run bash -c "zcat test/resource/logfiles/secure.gz | ./src/logksi verify test/resource/logsignatures/secure.logsig --stdin -d"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

