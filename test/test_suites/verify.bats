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
	[[ "$output" =~ "Failed to verify logline no. 1:" ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify compressed log from stdin" {
	run bash -c "zcat < test/resource/logfiles/secure.gz | ./src/logksi verify test/resource/logsignatures/secure.logsig --log-from-stdin -d"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "CDM test: use invalid stdin combination" {
	run src/logksi verify --log-from-stdin --input-hash - test/resource/interlink/ok-testlog-interlink-1.logsig
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous inputs from stdin (--input-hash -, --log-from-stdin)" ]]
}

@test "CDM test: use invalid stdout combination" {
	run src/logksi verify  test/resource/interlink/ok-testlog-interlink-1 --log - --output-hash -
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (--log -, --output-hash -)." ]]
}
