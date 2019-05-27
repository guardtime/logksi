#!/bin/bash

export KSI_CONF=test/test.cfg

@test "verify log record --time-diff: block 1 and 2 ok (exact match), block 3 nok" {
	run ./src/logksi verify test/resource/logs_and_signatures/totally-resigned -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 340d19H58M59
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... ok.).*(Verifying block no.   3... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 3 do not fit into time window).*(Block time window).*(340d 20:18:48).*(Expected time window).*(340d 19:58:59)  ]]
	[[ "$output" =~ (Error: Verification FAILED and was stopped).*(Error: Log lines in block 3 do not fit into time window.)  ]]
}

@test "verify log record --time-diff: block 1 nok (first line do not match)" {
	run ./src/logksi verify test/resource/logs_and_signatures/totally-resigned -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 340d19H58M58
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 1 do not fit into time window).*(Block time window).*(340d 19:58:59).*(Expected time window).*(340d 19:58:58)  ]]
}

@test "verify log record --time-diff: all blocks ok (last block contains only meta-record and is passed)" {
	run ./src/logksi verify test/resource/logs_and_signatures/totally-resigned -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 340d20H18M48
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... ok.).*(Verifying block no.   3... ok.).*(Verifying block no.   4... ok.) ]]
}

@test "verify log record --time-diff: specify negative diff where actual value is positive" {
	run ./src/logksi verify test/resource/logs_and_signatures/totally-resigned -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -340d19H58M59
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 1 do not fit into time window).*(Block time window).*(340d 19:58:59).*(Expected time window).*(-340d 19:58:59)  ]]
}

##
# Note that these tests use log file that has abnormal time difference between KSI signature and timestamp embedded into log lines.
# The KSI signature seems to be created before the loglines - it is probably the cause of invalid machine system clock.
# To still apply the verification for log record time, use negative --time-diff value.
##

@test "verify log record with negative --time-diff: block 1 ok (exact match), block 2 nok" {
	run ./src/logksi verify test/resource/logs_and_signatures/signed -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H24M01
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 2 do not fit into time window).*(Block time window).*(-78d 23:24:11).*(Expected time window).*(-78d 23:24:01)  ]]
}

@test "verify log record with negative --time-diff: block 1 nok (last line do not match)" {
	run ./src/logksi verify test/resource/logs_and_signatures/signed -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H24M00
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 1 do not fit into time window).*(Block time window).*(-78d 23:24:01).*(Expected time window).*(-78d 23:24:00)  ]]
}

@test "verify log record with negative --time-diff: all blocks ok (last block contains only meta-record and is passed)" {
	run ./src/logksi verify test/resource/logs_and_signatures/signed -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H24M19
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... ok.).*(Verifying block no.   3... ok.).*(Verifying block no.   4... ok.) ]]
}

@test "verify log record where all the log lines in block 1 are more recent than KSI signature" {
	run ./src/logksi verify test/resource/logs_and_signatures/signed -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 80d
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.) ]]
	[[ "$output" =~ (Error: All the log lines in block 1 are more recent than KSI signature.).*(Signing time.*1517928882).*(Time extracted from most recent log line.*1524752323) ]]
	[[ "$output" =~ (Error: Verification FAILED and was stopped).*(Error: All the log lines in block 1 are more recent than KSI signature) ]]
}


##
# Note that following 6 tests contain a hack. As there was not log files available containing log lines
# that are not in chronological order, the existing log file is changed. Expected hash failure is passed
# with --use-stored-hash-on-fail. Because of that every verification ends with error (2 of them should be OK).
##

@test "verify log record where some (NOT ALL) of the log lines in block 2 are more recent than KSI signature" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-higher-and-lower-from-ksig test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail  -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 80d
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   2... failed.) ]]
	[[ "$output" =~ (Error: Some of the log lines in block 2 are more recent than KSI signature.).*(Signing time.*1517928883).*(Time extracted from most recent log line.*1517928900) ]]
}

@test "verify log record where some (NOT ALL) of the log lines in block 2 are more recent than KSI signature: verify both directions with failure in block 2 and 3" {
	# Positive time window in block 2 OK, negative failing.
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-higher-and-lower-from-ksig test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail  -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 80d,-1
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   2... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 2 do not fit into time window).*(Block time window).*(-00:00:17 - 00:35:50).*(Expected time window).*(-00:00:01 - 80d 00:00:00)  ]]

	# Positive and negative time window in block 2 OK, but block 3 negative time window failing.
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-higher-and-lower-from-ksig test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail  -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 80d,-17
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   3... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 3 do not fit into time window).*(Block time window).*(-23:24:19).*(Expected time window).*(-00:00:17 - 80d 00:00:00)  ]]

	# Negative time window OK, positive failing in block 1.
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-higher-and-lower-from-ksig test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail  -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 1d,-17
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 1 do not fit into time window).*(Block time window).*(1d 00:36:37).*(Expected time window).*(-00:00:17 - 1d 00:00:00)  ]]
}

@test "verify log record where some (NOT ALL) of the log lines in block 2 are more recent than KSI signature: verify both directions with success" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-higher-and-lower-from-ksig test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail  -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 80d,-23H24M19
	[ "$status" -eq 6 ]
	[[ ! "$output" =~ (do not fit in expected time window) ]]
	[[ "$output" =~ (Error: 9 hash comparison failures found) ]]
}

@test "verify that log records in log file are in chronological order: line 2 is more recent than line 3" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed test/resource/log_rec_time/log-line-embedded-date-changed.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: Log line 2 in block 1 is more recent than log line 3).*(Time for log line 2).*(1524752330).*(Time for log line 3).*(1524752323) ]]
	[[ ! "$output" =~ "unable to calculate hash of logline no" ]]
}

@test "verify that log records in log file are in chronological order: use --time-disordered with too small value" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed test/resource/log_rec_time/log-line-embedded-date-changed.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail --time-disordered 6
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: Log line 2 in block 1 is more recent than log line 3).*(Time for log line 2).*(1524752330).*(Time for log line 3).*(1524752323) ]]
}

@test "verify that log records in log file are in chronological order: fix failure with --time-disordered minimum value" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed test/resource/log_rec_time/log-line-embedded-date-changed.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail --time-disordered 7
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: 1 hash comparison failures found) ]]
	[[ ! "$output" =~ (Error: Block no. 1: Log line 2).*(1524752330).*(is more recent than log line 3).*(1524752323) ]]
}

@test "verify that log records in log file are in chronological order: test between blocks" {
	run src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed-in-end-of-block-1 test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: Log line 3 in block 2 is more recent than log line 4).*(Time for log line 3).*(1524752334).*(Time for log line 4).*(1524752333) ]]
}

##
# Similar tests for excerpt files.
# Verify that log records fit into time window.
##

@test "verify log record in excerpt file with negative --time-diff: block 1 ok (exact match), block 2 nok" {
	run ./src/logksi verify test/resource/excerpt/log-ok.excerpt -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H44M21
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 2 do not fit into time window).*(Block time window).*(-78d 23:45:19).*(Expected time window).*(-78d 23:44:21)  ]]
}

@test "verify log record in excerpt file with negative --time-diff: block 1 nok (last line do not match)" {
	run ./src/logksi verify test/resource/excerpt/log-ok.excerpt -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H44M20
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 1 do not fit into time window).*(Block time window).*(-78d 23:44:21).*(Expected time window).*(-78d 23:44:20)  ]]
}

@test "verify log record in excerpt file with negative --time-diff: everything ok" {
	run ./src/logksi verify test/resource/excerpt/log-ok.excerpt -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H45M20
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... ok.) ]]
	[[ ! "$output" =~ (do not fit in expected time window)  ]]
}

##
# Verify the chronological order.
##

@test "verify that log records in log excerpt file are in chronological order: line 2 is more recent than line 1" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed.excerpt test/resource/log_rec_time/log-line-embedded-date-changed.excerpt.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Failed to verify logline no. 1" ]]
	[[ "$output" =~ (Error: Log line 1 in block 1 is more recent than log line 2).*(Time for log line 1).*(1524753601).*(Time for log line 2).*(1524753597) ]]
	[[ ! "$output" =~ "unable to calculate hash of logline no" ]]
}

@test "verify that log records in log excerpt file are in chronological order: use --time-disordered with too small value" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed.excerpt test/resource/log_rec_time/log-line-embedded-date-changed.excerpt.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail --time-disordered 3
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Failed to verify logline no. 1" ]]
	[[ "$output" =~ (Error: Log line 1 in block 1 is more recent than log line 2).*(Time for log line 1).*(1524753601).*(Time for log line 2).*(1524753597) ]]
}

@test "verify that log records in log excerpt file are in chronological order: use --time-disordered" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed.excerpt test/resource/log_rec_time/log-line-embedded-date-changed.excerpt.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail --time-disordered 4
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: 1 hash comparison failures found" ]]
	[[ ! "$output" =~ (Error: Block no. 2: Log line 3).*(1524753717).*(is more recent than log line 4).*(1524753656) ]]
}

@test "verify that log records in log excerpt file are in chronological order: test between blocks" {
	run src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed-in-end-of-block-1.excerpt test/resource/log_rec_time/log-line-embedded-date-changed.excerpt.logsig --use-stored-hash-on-fail -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: Log line 2 in block 2 is more recent than log line 3).*(Time for log line 2).*(1524753717).*(Time for log line 3).*(1524753656) ]]
}