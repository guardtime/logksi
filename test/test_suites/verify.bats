#!/bin/bash

export KSI_CONF=test/test.cfg

@test "verify unsigned.logsig" {
	run ./src/logksi verify test/out/unsigned -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify unsigned.logsig internally" {
	run ./src/logksi verify --ver-int test/out/unsigned -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify unsigned.logsig against calendar" {
	run ./src/logksi verify --ver-cal test/out/unsigned -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify unsigned.logsig against key" {
	run ./src/logksi verify --ver-key test/out/unsigned -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify unsigned-repared.logsig WITHOUT --ignore-desc-block-time" {
	run ./src/logksi verify test/resource/logfiles/unsigned test/resource/logsignatures/unsigned-repared.logsig
	[ "$status" -eq 6 ]
	[[ "$output" =~ .*(Error).*(Block no).*(17).*(1540303365).*(in file).*(unsigned).*(is more recent than).*(block no).*(18).*(1517928940).* ]]
	[[ "$output" =~ .*(Error).*(Block no).*(25).*(1540303366).*(in file).*(unsigned).*(is more recent than).*(block no).*(26).*(1517928947).* ]]
}

@test "try verifying unsigned.logsig against signed logfile" {
	run ./src/logksi verify test/out/signed test/out/unsigned.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Failed to verify logline no. 1:" ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify compressed log from stdin" {
	run bash -c "zcat < test/resource/logfiles/secure.gz | ./src/logksi verify test/resource/logsignatures/secure.logsig --log-from-stdin -ddd"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "warn about consecutive blocks that has same signing time. " {
	run src/logksi verify test/resource/logfiles/unsigned test/resource/logsignatures/unsigned-same-sign-time.logsig --ignore-desc-block-time --warn-same-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ .*(Warning).*(Block).*(1).*(and).*(2).*(in file).*(unsigned).*(has same signing time).*(1540389597).* ]]
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
