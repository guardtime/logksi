#!/bin/bash

export KSI_CONF=test/test.cfg


##
# Collection of helper functions that generate logksi debug output structures.
##

# block_num sigtime hin hout line_info <extension>
f_summary_of_block () {
	echo "(Summary of block $1:).( . Sig time:    $2).( . Input hash:  $3).( . Output hash: $4).( . Line[s]?:[ ]{23,24}$5)$6"
}

# block_num sigtime hin hout l0 l1 dl hash_fail_count
f_summary_of_block_hash_fail () {
	echo "(Summary of block $1:).( . Sig time:    $2).( . Input hash:  $3).( . Output hash: $4).( . Line[s]?:[ ]{23,24}$5 - $6 .$7.).( . Count of hash failures:      $8)"
}

# block_num sigtime hin hout lo l1 dl
f_summary_of_block_ok_only_metadata () {
	f_summary_of_block $1 ".$2..*UTC.00.00" $3 $4 "n/a" ".( . Count of meta-records:       1)"
	#echo "(Summary of block 4:).( . Sig time:    .1517928885..*UTC.00.00).( . Input hash:  SHA-512:1dfeae.*43e987).( . Output hash: SHA-512:f7f5b4.*b2b596).( . Line[s]?:[ ]{23,24}n.a)"
}

# block_num sigtime hin hout lo l1 dl
f_summary_of_block_ok () {
	f_summary_of_block $1 ".$2..*UTC.00.00" $3 $4 "$5 - $6 .$7."
}

# lnum logline hin hout
f_failed_to_ver_log_line () {
	echo "( x Error: Failed to verify logline no. $1:).(   . Logline:).(     .$2..).(   . Record hash computed from logline:).(     $3).(   . Record hash stored in log signature file:).(     $4)"
}

 # block_count, rec_hash_count, meta_rec_count, hash_fail_count, ih, oh
 f_summary_of_logfile_hash_fail () {
	 echo "(Summary of logfile:).( . Count of blocks:             $1).( . Count of record hashes:      $2).( . Count of meta-records:       $3).( . Count of hash failures:      $4).( . Input hash:  $5).( . Output hash: $6)"
 }
 
# block_count, fail_count, rec_hash_count, meta_rec_count, ih, oh
f_summary_of_logfile_failure () {
	 echo "(Summary of logfile:).( . Count of blocks:             $1).( . Count of failures:           $2).( . Count of record hashes:      $3).( . Count of meta-records:       $4).( . Input hash:  $5).( . Output hash: $6)"
 }

#block_num0, block_num1, h1, h2
f_internal_interlink_error () {
	echo "( x Error: Output hash of block $1 differs from input hash of block $2:).(   . Last hash computed from previous block data:).(     $3).(   . Input hash stored in current block header:).(     $4).(   . Verification is continued. Failure may be caused by the error in the previous block $1. Using input hash of the current block instead.)"
}


##
# Some more common predefined test structures.
##

err_logline_4_verification=`f_failed_to_ver_log_line 4 "Corrupted logline" "SHA-512:cb8a8f.*8bf39c" "SHA-512:6c0d5e.*229741"`
err_interlink_2_3=`f_internal_interlink_error 2 3 "SHA-512:20cfea.*88944a" "SHA-512:9c1ea0.*42e444"`
summary_of_logfile_2hf=`f_summary_of_logfile_hash_fail 4 9 1 2 "SHA-512:7f3dea.*ee3141" "SHA-512:f7f5b4.*b2b596"`
summary_of_logfile_1hf=`f_summary_of_logfile_hash_fail 4 9 1 1 "SHA-512:7f3dea.*ee3141" "SHA-512:f7f5b4.*b2b596"`
summary_of_logfile_1_sig_fail=`f_summary_of_logfile_failure 4 1 9 1 "SHA-512:7f3dea.*ee3141" "SHA-512:f7f5b4.*b2b596"`

summary_of_block_1_ok=`f_summary_of_block_ok 1 1517928882 "SHA-512:7f3dea.*ee3141" "SHA-512:20cfea.*88944a" 1 3 3`
summary_of_block_2_ok=`f_summary_of_block_ok 2 1517928883 "SHA-512:20cfea.*88944a" "SHA-512:9c1ea0.*42e444" 4 6 3`
summary_of_block_3_ok=`f_summary_of_block_ok 3 1517928884 "SHA-512:9c1ea0.*42e444" "SHA-512:1dfeae.*43e987" 7 9 3`
summary_of_block_2_ok_1_hash_fail="$summary_of_block_2_ok.( . Count of hash failures:      1)"

summary_of_block_3_expected_in_hash_fail=`f_summary_of_block_hash_fail 3 "".1517928884..*UTC.00.00"" "SHA-512:9c1ea0.*42e444" "SHA-512:1dfeae.*43e987" 7 9 3 1`
summary_of_block_4_ok=`f_summary_of_block_ok_only_metadata 4 1517928885 "SHA-512:1dfeae.*43e987" "SHA-512:f7f5b4.*b2b596" `


##
# Actual tests.
##

@test "Debug output for continuated verification: Log line nr.4 modified. Rec. hash present. Debug lvl 1." {
	run src/logksi verify test/resource/continue-verification/log-line-4-changed test/resource/continue-verification/log-ok.logsig -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed.)..$err_logline_4_verification..( x Error: Skipping block 2!) ]]
	[[ "$output" =~ ( x Error: Skipping block 2!)..$err_interlink_2_3..(Summary of logfile:) ]]
	[[ "$output" =~ $summary_of_logfile_2hf ]]
}

@test "Debug output for continuated verification: Log line nr.4 modified. Rec. hash present. Debug lvl 2." {
	run src/logksi verify test/resource/continue-verification/log-line-4-changed test/resource/continue-verification/log-ok.logsig -dd --continue-on-fail
	[ "$status" -eq 6 ]
	
	[[ "$output" =~ (Verifying block no.   1... ok.)..$summary_of_block_1_ok..(Verifying block no.   2... failed.) ]]
	[[ "$output" =~ (Verifying block no.   2... failed.)..$err_logline_4_verification..( x Error: Skipping block 2!) ]]
	[[ "$output" =~ ( x Error: Skipping block 2!)..`f_summary_of_block_hash_fail 2 ".no signature data available." "SHA-512:20cfea.*88944a" ".not valid value." 4 6 3 1`..(Verifying block no.   3... ok.) ]]
	[[ "$output" =~ (Verifying block no.   3... ok.)..$err_interlink_2_3..$summary_of_block_3_expected_in_hash_fail..(Verifying block no.   4... ok.) ]]
	[[ "$output" =~ (Verifying block no.   4... ok.)..$summary_of_block_4_ok...(Summary of logfile:) ]]
	[[ "$output" =~ $summary_of_logfile_2hf ]]
}

@test "Debug output for continuated verification: Log line nr.4 modified. Block 2 is computed with stored hash with success. Debug lvl 1." {
	run src/logksi verify test/resource/continue-verification/log-line-4-changed test/resource/continue-verification/log-ok.logsig --use-stored-hash-on-fail -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed.)..$err_logline_4_verification.(   . Using stored hash to continue.).. ]]
	[[ "$output" =~ $summary_of_logfile_1hf ]]
}

@test "Debug output for continuated verification: Log line nr.4 modified. Block 2 is computed with stored hash with success. Debug lvl 2." {
	run src/logksi verify test/resource/continue-verification/log-line-4-changed test/resource/continue-verification/log-ok.logsig --use-stored-hash-on-fail -dd --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... ok.)..$summary_of_block_1_ok..(Verifying block no.   2... failed.) ]]
	[[ "$output" =~ (Verifying block no.   2... failed.)..$err_logline_4_verification.(   . Using stored hash to continue.)..$summary_of_block_2_ok_1_hash_fail..(Verifying block no.   3... ok.) ]]
	[[ "$output" =~ (Verifying block no.   3... ok.)..$summary_of_block_3_ok..(Verifying block no.   4... ok.)..$summary_of_block_4_ok...$summary_of_logfile_1hf ]]
}

#@test "Log line nr.4 modified. Rec. hash present. Block 2 is computed with stored hash with success. Debug lvl 3." {
#	run src/logksi verify test/resource/continue-verification/log-line-4-changed test/resource/continue-verification/log-ok.logsig --use-stored-hash-on-fail -ddd --continue-on-fail
#	[[ "$output" =~ "Block no.   3: processing block header... ok."  ]]
#}

@test "Debug output for continuated verification: Wrong KSI signature for block 2. Debug lvl 1." {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-sig-no2-wrong.logsig -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed.)..( x Error: Verification of block 2 KSI signature failed!)..( x Error: Skipping block 2!)..$summary_of_logfile_1_sig_fail ]]
}

@test "Debug output for continuated verification: Wrong KSI signature for block 2. Debug lvl 2." {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-sig-no2-wrong.logsig -dd --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... ok.)..$summary_of_block_1_ok..(Verifying block no.   2... failed.) ]]
	[[ "$output" =~ (Verifying block no.   2... failed.)..( x Error: Verification of block 2 KSI signature failed!) ]]
	[[ "$output" =~ ( x Error: Skipping block 2!)..`f_summary_of_block 2 ".no signature data available." "SHA-512:20cfea.*88944a" "SHA-512:9c1ea0.*42e444" "(4 - 6 .3.)"` ]]
	[[ "$output" =~ (Verifying block no.   3... ok.)..$summary_of_block_3_ok..(Verifying block no.   4... ok.)..$summary_of_block_4_ok...$summary_of_logfile_1_sig_fail ]]
}

@test "Debug output for continuated verification: Verify signatures that contains unsigned blocks." {
	run ./src/logksi verify test/resource/logs_and_signatures/unsigned -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed.)..( x Error: Block 5 is unsigned!)..( x Error: Skipping block 5!)..( x Error: Block 6 is unsigned!)..( x Error: Skipping block 6!).*( x Error: Block 25 is unsigned!)..( x Error: Skipping block 25!) ]]

	[[ "$output" =~ (Summary of logfile:).( . Count of blocks:             30).( . Count of failures:           1).( . Count of record hashes:      88).( . Count of meta-records:       1).( . Input hash:  SHA-512:dd4e87.*e2b137).( . Output hash: SHA-512:7f5a17.*cd7827) ]]
	[[ "$output" =~ (2[\)]).*(Error: Verification FAILED but was continued for further analysis)  ]]
}


