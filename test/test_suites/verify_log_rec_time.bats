#!/bin/bash

export KSI_CONF=test/test.cfg

@test "verify log record --time-diff: block 1 and 2 ok (exact match), block 3 nok" {
	run ./src/logksi verify test/resource/logs_and_signatures/totally-resigned -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 340d19H58M59
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... ok.).*(Verifying block no.   3... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 3)..(340d 20:18:48)..(do not fit in expected time window)..(340d 19:58:59)  ]]	
}

@test "verify log record --time-diff: block 1 nok (first line do not match)" {
	run ./src/logksi verify test/resource/logs_and_signatures/totally-resigned -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 340d19H58M58
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 1)..(340d 19:58:59)..(do not fit in expected time window)..(340d 19:58:58)  ]]	
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
	[[ "$output" =~ (Error: Log lines in block 1)..(340d 19:58:21)..(do not fit in expected time window)..(-340d 19:58:59)  ]]	
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
	[[ "$output" =~ (Error: Log lines in block 2)..(-78d 23:24:11)..(do not fit in expected time window)..(-78d 23:24:01)  ]]	
}

@test "verify log record with negative --time-diff: block 1 nok (last line do not match)" {
	run ./src/logksi verify test/resource/logs_and_signatures/signed -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H24M00
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 1)..(-78d 23:24:01)..(do not fit in expected time window)..(-78d 23:24:00)  ]]	
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
	[[ "$output" =~ (Error: All the log lines in block 1 are more recent than KSI signature.).*(KSI Signature.*1517928882).*(The most recent log line.*1524752323) ]]
}

@test "verify log record where some (NOT ALL) of the log lines in block 2 are more recent than KSI signature" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-higher-and-lower-from-ksig test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail  -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 80d
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   2... failed.) ]]
	[[ "$output" =~ (Error: Some of the log lines in block 2 are more recent than KSI signature.).*(KSI Signature.*1517928883).*(The most recent log line.*1517928900) ]]
}

##
# Note that following 6 tests contain a hack. As there was not log files available containing log lines
# that are not in chronological order, the existing log file is changed. Expected hash failure is passed
# with --use-stored-hash-on-fail. Because of that every verification ends with error (2 of them should be OK).
##

@test "verify that log records in log file are in chronological order: line 2 is more recent than line 3" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed test/resource/log_rec_time/log-line-embedded-date-changed.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: Block no. 1: Log line 2).*(1524752330).*(is more recent than log line 3).*(1524752323) ]]
	[[ ! "$output" =~ "unable to calculate hash of logline no" ]]
}

@test "verify that log records in log file are in chronological order: use --time-permit-disordered-records with too small value" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed test/resource/log_rec_time/log-line-embedded-date-changed.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail --time-permit-disordered-records 6
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: Block no. 1: Log line 2).*(1524752330).*(is more recent than log line 3).*(1524752323) ]]
}

@test "verify that log records in log file are in chronological order: fix failure with --time-permit-disordered-records minimum value" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed test/resource/log_rec_time/log-line-embedded-date-changed.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail --time-permit-disordered-records 7
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: 1 hash comparison failures found) ]]
	[[ ! "$output" =~ (Error: Block no. 1: Log line 2).*(1524752330).*(is more recent than log line 3).*(1524752323) ]]
}

@test "verify that log records in log file are in chronological order: test between blocks" {
	run src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed-in-end-of-block-1 test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: Block no. 2: Log line 3).*(1524752334).*(is more recent than log line 4).*(1524752333) ]]
}

##
# Similar tests for excerpt files.
# Verify that log records fit into time window.
##

@test "verify log record in excerpt file with negative --time-diff: block 1 ok (exact match), block 2 nok" {
	run ./src/logksi verify test/resource/excerpt/log-ok.excerpt -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H44M21
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 2)..(-78d 23:45:19)..(do not fit in expected time window)..(-78d 23:44:21)  ]]	
}

@test "verify log record in excerpt file with negative --time-diff: block 1 nok (last line do not match)" {
	run ./src/logksi verify test/resource/excerpt/log-ok.excerpt -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H44M20
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.) ]]
	[[ "$output" =~ (Error: Log lines in block 1)..(-78d 23:44:21)..(do not fit in expected time window)..(-78d 23:44:20)  ]]	
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
	[[ "$output" =~ (Error: Block no. 1: Log line 1).*(1524753601).*(is more recent than log line 2).*(1524753597) ]]
	[[ ! "$output" =~ "unable to calculate hash of logline no" ]]
}

@test "verify that log records in log excerpt file are in chronological order: use --time-permit-disordered-records with too small value" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed.excerpt test/resource/log_rec_time/log-line-embedded-date-changed.excerpt.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail --time-permit-disordered-records 3
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Failed to verify logline no. 1" ]]
	[[ "$output" =~ (Error: Block no. 1: Log line 1).*(1524753601).*(is more recent than log line 2).*(1524753597) ]]
}

@test "verify that log records in log excerpt file are in chronological order: use --time-permit-disordered-records" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed.excerpt test/resource/log_rec_time/log-line-embedded-date-changed.excerpt.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail --time-permit-disordered-records 4
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: 1 hash comparison failures found" ]]
	[[ ! "$output" =~ (Error: Block no. 2: Log line 3).*(1524753717).*(is more recent than log line 4).*(1524753656) ]]
}

@test "verify that log records in log excerpt file are in chronological order: test between blocks" {
	run src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed-in-end-of-block-1.excerpt test/resource/log_rec_time/log-line-embedded-date-changed.excerpt.logsig --use-stored-hash-on-fail -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (Error: Block no. 2: Log line 2).*(1524753717).*(is more recent than log line 3).*(1524753656) ]]
}