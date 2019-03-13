#!/bin/bash

export KSI_CONF=test/test.cfg

@test "verify log_repaired.logsig" {
	run ./src/logksi verify test/resource/logs_and_signatures/log_repaired -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify log_repaired.logsig internally" {
	run ./src/logksi verify --ver-int test/resource/logs_and_signatures/log_repaired -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify log_repaired.logsig against calendar" {
	run ./src/logksi verify --ver-cal test/resource/logs_and_signatures/log_repaired -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify log_repaired.logsig against key" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify log_repaired.logsig WITHOUT --ignore-desc-block-time" {
	run ./src/logksi verify test/resource/logs_and_signatures/log_repaired
	[ "$status" -eq 6 ]
	[[ "$output" =~ .*(Error).*(Block no).*(17).*(1540303365).*(in file).*(log_repaired).*(is more recent than).*(block no).*(18).*(1517928940).* ]]
	[[ "$output" =~ .*(Error).*(Block no).*(25).*(1540303366).*(in file).*(log_repaired).*(is more recent than).*(block no).*(26).*(1517928947).* ]]
}

@test "try verifying log_repaired.logsig against signed logfile" {
	run ./src/logksi verify test/resource/logs_and_signatures/signed test/resource/logs_and_signatures/log_repaired.logsig -ddd
	[ "$status" -ne 0 ]
	[[ "$output" =~ "failed to verify logline no. 1:" ]]
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
