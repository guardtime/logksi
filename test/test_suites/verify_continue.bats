#!/bin/bash

export KSI_CONF=test/test.cfg


@test "Log line nr.4 modified. Rec. hashes present. Block 2 is skipped. Block 3 input hash do not match but verification is continued." {
	run src/logksi verify test/resource/continue-verification/log-line-4-changed test/resource/continue-verification/log-ok.logsig  -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed.).*(Error: Failed to verify logline no. 4:).*(Error: Output hash of block 2 differs from input hash of block 3).*(Verification is continued. Failure may be caused by the error in the previous block 2. Using input hash of the current block instead.).*(Count of hash failures:      2) ]]
	[[ ! "$output" =~ (Error: Skipping block 1)  ]]	
	[[ "$output" =~ (Error: Skipping block 2)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 3)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 4)  ]]	
	[[ "$output" =~ (2[\)]).*(Error: Verification FAILED but was continued for further analysis).*(Log signature verification failed)  ]]
	[[ "$output" =~ (1[\)]).*(Error: 2 hash comparison failures found).*(Log signature verification failed)  ]]
}

@test "Log line nr.4 modified. Rec. hashes present. Stored hashes are used and verification is continued." {
	run src/logksi verify test/resource/continue-verification/log-line-4-changed test/resource/continue-verification/log-ok.logsig --use-stored-hash-on-fail -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed.).*(Error: Failed to verify logline no. 4:).*(Using stored hash to continue).*(Count of hash failures:      1) ]]
	[[ ! "$output" =~ (Error: Skipping block)  ]]	
	[[ "$output" =~ (1[\)]).*(Error: 1 hash comparison failures found).*(Log signature verification failed)  ]]
}

@test "Logline nr.4 removed from log file and from block 2. Rec. hashes present, tree hashes removed. Sig verification fails but verification is continued." {
	run src/logksi verify test/resource/continue-verification/log-line-4-removed -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed).*(Error: Verification of block 2 KSI signature failed) ]]
	[[ ! "$output" =~ (Error: Skipping block 1)  ]]	
	[[ "$output" =~ (Error: Skipping block 2)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 3)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 4)  ]]	
	[[ "$output" =~ (3[\)]).*(Error: Verification FAILED but was continued for further analysis).*(Log signature verification failed)  ]]
	[[ "$output" =~ (2[\)]).*(Error: 1 hash comparison failures found).*(Verification failed)  ]]
	[[ "$output" =~ (1[\)]).*(Error:).*(GEN-01).*(Wrong document. Signature verification according to trust anchor failed.).*(Verification failed)  ]]
}

@test "Log rec nr.4 removed from log signature file. Rec. hashes present. Unable to verify almost anything as records and log lines are shifted." {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-line-4-removed.logsig  -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed).*(Error: Failed to verify logline no. 5).*(Error: Skipping block 2).*(Error: Output hash of block 2 differs from input hash of block 3).*(Verification is continued).*(Error: Failed to verify logline no. 6).*(Error: Skipping block 3).*(Error: Output hash of block 3 differs from input hash of block 4).*(Verification is continued).*(Count of hash failures:      4) ]]
	[[ ! "$output" =~ (Error: Skipping block 1)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 4)  ]]	
	[[ "$output" =~ (2[\)]).*(Error: Verification FAILED but was continued for further analysis).*(verification failed)  ]]
	[[ "$output" =~ (1[\)]).*(Error: Block no. 4: end of log file contains unexpected records).*(verification failed)  ]]
}

@test "Log rec nr.4 changed in log signature file. Rec. hashes present." {
	run src/logksi verify test/resource/continue-verification/log-rec-4-changed -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed).*(Error: Verification of block 2 KSI signature failed) ]]
	[[ ! "$output" =~ (Error: Skipping block 1)  ]]	
	[[ "$output" =~ (Error: Skipping block 2)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 3)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 4)  ]]	
	[[ "$output" =~ (3[\)]).*(Error: Verification FAILED but was continued for further analysis).*(Log signature verification failed)  ]]
	[[ "$output" =~ (2[\)]).*(Error: 1 hash comparison failures found).*(Verification failed)  ]]
	[[ "$output" =~ (1[\)]).*(Error:).*(GEN-01).*(Wrong document. Signature verification according to trust anchor failed.).*(Verification failed)  ]]
}

@test "KSI signature is replaced in block 2. Rec. hashes present. Sig verification fails but verification is continued." {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-sig-no2-wrong.logsig -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed).*(Error: Verification of block 2 KSI signature failed) ]]
	[[ ! "$output" =~ (Error: Skipping block 1)  ]]	
	[[ "$output" =~ (Error: Skipping block 2)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 3)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 4)  ]]	
	[[ "$output" =~ (2[\)]).*(Error: Verification FAILED but was continued for further analysis).*(Log signature verification failed)  ]]
	[[ "$output" =~ (1[\)]).*(Error:).*(GEN-01).*(Wrong document. Signature verification according to trust anchor failed.).*(Verification failed)  ]]
}

@test "Verify log signatures that contains unsigned blocks with continuation." {
	run ./src/logksi verify test/resource/logs_and_signatures/unsigned -d --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed.)..( x Error: Block 5 is unsigned!)..( x Error: Skipping block 5!)..( x Error: Block 6 is unsigned!)..( x Error: Skipping block 6!).*( x Error: Block 25 is unsigned!)..( x Error: Skipping block 25!) ]]
	[[ ! "$output" =~ (Error: Skipping block 4)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 7)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 24)  ]]	
	[[ ! "$output" =~ (Error: Skipping block 26)  ]]	
	[[ "$output" =~ (2[\)]).*(Error: Verification FAILED but was continued for further analysis)  ]]
}

@test "Verify log signature that has unexpected client ID." {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-ok.logsig -d --continue-on-fail --client-id "GT :: KT :: GT :: anon"
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Error: Verification FAILED but was continued for further analysis." ]]
}

##
# If other than verification error is encountered, process must be terminated. 
##

@test "Try to continue verification in case of unexpected TLV 904.905.666. It must fail and stop verification." {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-unknown-tlv-904.905.666.logsig -ddd --continue-on-fail
	[ "$status" -eq 4 ]
	[[ "$output" =~ "Error: Block no. 2: unable to parse KSI signature"  ]]
	[[ ! "$output" =~ (Block no.   3)  ]]
	[[ ! "$output" =~ (Error: Verification FAILED but was continued for further analysis)  ]]
}

@test "Try to continue verification in case of missing mandatory TLV 901.01. It must fail and stop verification." {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-missing-tlv-901.01.logsig -ddd --continue-on-fail
	[ "$status" -eq 4 ]
	[[ "$output" =~ "Block no.   1: processing block header... failed"  ]]
	[[ "$output" =~ "Error: Block no. 1: missing hash algorithm in block header"  ]]
	[[ ! "$output" =~ (Block no.   2)  ]]
	[[ ! "$output" =~ (Error: Verification FAILED but was continued for further analysis)  ]]
}

@test "Try to continue verification in case of missing mandatory TLV 904.905. It must fail and stop verification." {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-missing-tlv-904.905.logsig -ddd --continue-on-fail
	[ "$status" -eq 4 ]
	[[ "$output" =~ "Block no.   1: processing block signature data... failed."  ]]
	[[ "$output" =~ "Error: Block no. 1: missing KSI signature (and unsigned block marker) in block signature"  ]]
	[[ ! "$output" =~ (Block no.   2)  ]]
	[[ ! "$output" =~ (Error: Verification FAILED but was continued for further analysis)  ]]
}

@test "Try to continue verification in case of missing mandatory TLV 904.02. It must fail and stop verification." {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-missing-tlv-911.02.logsig -ddd --continue-on-fail
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Block no.   4: {M X"  ]]
	[[ "$output" =~ "Error: Block no. 4: Unable to get TLV 911.02.01 (Meta record key)"  ]]
	[[ ! "$output" =~ (Block no.   4: processing block signature data... ok)  ]]
	[[ ! "$output" =~ (Error: Verification FAILED but was continued for further analysis)  ]]
}

##
# Time check.
##

@test "verify log record --time-diff: block 1,2 and 4 ok, block 3 nok" {
	run ./src/logksi verify test/resource/logs_and_signatures/totally-resigned -dd --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 340d19H58M59 --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... ok.).*(Verifying block no.   3... failed.).*(Verifying block no.   4... ok.) ]]
	[[ "$output" =~ (Error: Verification FAILED but was continued for further analysis)  ]]
}

@test "verify with --block-time-diff and continue on fail to detect all block that are too close and too apart (1,259d19H42M24)." {
	run src/logksi verify test/resource/logfiles/unsigned test/resource/logsignatures/unsigned-same-sign-time.logsig --ignore-desc-block-time -d --block-time-diff 1,259d19H42M24 --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (x Error: Blocks 1 and 2 signing times are too close) ]]
	[[ "$output" =~ (x Error: Blocks 24 and 25 signing times are too apart) ]]
	[[ "$output" =~ (Count of failures:           2) ]]
}

@test "verify with --block-time-diff and continue on fail to detect all resigned blocks that are too recent (-259d19H42M29,oo)." {
	run src/logksi verify test/resource/logfiles/unsigned test/resource/logsignatures/unsigned-same-sign-time.logsig -d --block-time-diff -259d19H42M29,oo --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ (x Error: Blocks 2 signing time is more recent than expected relative to block 3:) ]]
	[[ "$output" =~ (x Error: Blocks 17 signing time is more recent than expected relative to block 18:) ]]
	[[ "$output" =~ (Count of failures:           2) ]]
}

@test "verify with --block-time-diff and continue on fail and check that time check for unsigned block is skipped." {
	run src/logksi verify test/resource/logs_and_signatures/unsigned  -d --block-time-diff 1 --ignore-desc-block-time --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying... failed.)..( x Error: Block 5 is unsigned!)..( x Error: Skipping block 5!)..( x Error: Block 6 is unsigned!)..( x Error: Skipping block 6!)..( x Error: Block 25 is unsigned!)..( x Error: Skipping block 25!)..(Summary of logfile) ]]
}
