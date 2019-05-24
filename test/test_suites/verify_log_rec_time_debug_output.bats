#!/bin/bash

export KSI_CONF=test/test.cfg


##
# Collection of helper functions that generate logksi debug output structures.
##

# block_num sigtime hin hout line_info <extension>
f_summary_of_block () {
	echo "(Summary of block $1:).( . Sig time:    $2).( . Input hash:  $3).( . Output hash: $4).( . Line[s]?:[ ]{23,24}$5)$6"
}

# block_num sigtime hin hout lo l1 dl
f_summary_of_block_ok_only_metadata () {
	f_summary_of_block $1 ".$2..*UTC.00.00" $3 $4 "n/a" ".( . Count of meta-records:       1)"
}

# block_num sigtime hin hout lo l1 dl first_rec_time last_rec_time duration
f_summary_of_block_rec_time_check_ok () {
	f_summary_of_block $1 ".$2..*UTC.00.00" $3 $4 "$5 - $6 .$7." ".( . First record time:           .$8.*UTC.00.00).( . Last record time:            .$9.*UTC.00.00).( . Block duration:              ${10})"
}

# block_count, fail_count, rec_hash_count, meta_rec_count, hash_fail_count, first_rec_time, last_rec_time, duration, ih, oh
f_summary_of_logfile_failure_with_log_rec_check () {
	 echo "(Summary of logfile:).( . Count of blocks:             $1).( . Count of failures:           $2).( . Count of record hashes:      $3).( . Count of meta-records:       $4).( . Count of hash failures:      $5).( . First record time:           .$6.*UTC.00:00).( . Last record time:            .$7.*UTC.00:00).( . Log file duration:           $8).( . Input hash:  $9).( . Output hash: ${10})"
}

# block_num, sigtime, hin, hout, lo, l1, dl, first_rec_time, last_rec_time, duration, hash_fail
f_summary_of_block_rec_time_check_hash_fail () {
	f_summary_of_block $1 ".$2..*UTC.00.00" $3 $4 "$5 - $6 .$7." ".( . First record time:           .$8.*UTC.00.00).( . Last record time:            .$9.*UTC.00.00).( . Block duration:              ${10}).( . Count of hash failures:      ${11})"
}

# block_num hin hout lo l1 dl first_rec_time last_rec_time duration
f_summary_of_block_rec_time_check_unsigned_block () {
	f_summary_of_block $1 ".unsigned." $2 $3 "$4 - $5 .$6." ".( . First record time:           .$7.*UTC.00.00).( . Last record time:            .$8.*UTC.00.00).( . Block duration:              $9)"
}

# block, line_0, line_1, line_0_time, line_0_time
f_failed_logl_more_recent () {
	echo "( x Error: Log line $2 in block $1 is more recent than log line $3:).(   . Time for log line $2: .$4.*UTC.00:00).(   . Time for log line $3: .$5.*UTC.00:00)"
}

##
# Some more common predefined test structures.
##

summary_of_logfile_1_sig_fail_with_log_rec_check=`f_summary_of_logfile_failure_with_log_rec_check 4 1 9 1 1 1524752285 1524752343  "00:00:58" "SHA-512:7f3dea.*ee3141" "SHA-512:f7f5b4.*b2b596"`
summary_of_block_1_with_logrec_time_check_hash_fail=`f_summary_of_block_rec_time_check_hash_fail 1 1517928882 "SHA-512:7f3dea.*ee3141" "SHA-512:20cfea.*88944a" 1 3 3 1524752285 1524752330 "00:00:45" 1` 
summary_of_block_2_with_logrec_time_check_ok=`f_summary_of_block_rec_time_check_ok 2 1517928883 "SHA-512:20cfea.*88944a" "SHA-512:9c1ea0.*42e444" 4 6 3 1524752333 1524752334 "00:00:01"` 
summary_of_block_3_with_logrec_time_check_ok=`f_summary_of_block_rec_time_check_ok 3 1517928884 "SHA-512:9c1ea0.*42e444" "SHA-512:1dfeae.*43e987" 7 9 3 1524752336 1524752343 "00:00:07"` 
summary_of_block_4_with_logrec_time_check_ok=`f_summary_of_block_ok_only_metadata 4 1517928885 "SHA-512:1dfeae.*43e987" "SHA-512:f7f5b4.*b2b596" `
summary_of_block_2_with_logrec_time_check_unsigned_block=`f_summary_of_block_rec_time_check_unsigned_block 2 "SHA-512:20cfea.*88944a" "SHA-512:9c1ea0.*42e444" 4 6 3 1524752333 1524752334 "00:00:01"`  
err_l2_morerecent_l3=`f_failed_logl_more_recent 1 2 3 1524752330 1524752323`
##
# Actual tests.
##

@test "verify that log records in log file are in chronological order: check if file summary is correct, debug level 1" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed test/resource/log_rec_time/log-line-embedded-date-changed.logsig -d --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed.)..( x Error: Failed to verify logline no. 2:).*(   . Using stored hash to continue.)..$err_l2_morerecent_l3 ]]
	[[ ! "$output" =~ "unable to calculate hash of logline no" ]]
}

@test "verify that log records in log file are in chronological order: check if file summary is correct, debug level 2" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-changed test/resource/log_rec_time/log-line-embedded-date-changed.logsig -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d --use-stored-hash-on-fail --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... failed.)..( x Error: Failed to verify logline no. 2:).*(   . Using stored hash to continue.)..$err_l2_morerecent_l3..$summary_of_block_1_with_logrec_time_check_hash_fail..(Verifying block no.   2... ok.)..$summary_of_block_2_with_logrec_time_check_ok..(Verifying block no.   3... ok.)..$summary_of_block_3_with_logrec_time_check_ok..(Verifying block no.   4... ok.)..$summary_of_block_4_with_logrec_time_check_ok...$summary_of_logfile_1_sig_fail_with_log_rec_check ]]
}

@test "check that log file and block summary with duration 0 is printed without '-'" {
	run ./src/logksi verify --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 5S -dd test/resource/interlink/ok-testlog-interlink-1
	[ "$status" -eq 0 ]
	[[ "$output" =~ ( . Block duration:              00:00:00).*( . Log file duration:           00:00:00) ]]
}

@test "check that block summary is printed correctly when block is unsigned" {
	run src/logksi verify test/resource/logs_and_signatures/only-1-unsigned --continue-on-fail -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -80d
	[ "$status" -eq 6 ]
	[[ "$output" =~ $summary_of_block_2_with_logrec_time_check_unsigned_block ]]
}

@test "check that block time window is printed without double -" {
	run ./src/logksi verify test/resource/logs_and_signatures/signed -ddd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -78d23H24M01
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Block no.   1: block time window:  -78d 23:24:01" ]]
}
