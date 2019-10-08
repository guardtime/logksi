#!/bin/bash

export KSI_CONF=test/test.cfg

@test "sign output with debug level 1" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Signing... ok.)..(Summary of logfile:).( . Count of blocks:             30).( . Count of record hashes:      88).( . Count of resigned blocks:    3).( . Count of meta-records:       1) ]]
}

@test "sign output with debug level 2" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Signing Block no.   5... ok.*ms.)..(Summary of block 5:).( . Sig time.                    .[0-9]{10}..*).( . Lines:                       13 . 15 .3.)..(Signing Block no.   6... ok.*ms.)..(Summary of block 6:).( . Sig time.                    .[0-9]{10}..*).( . Lines:                       16 . 18 .3.)..(Signing Block no.  25... ok.*ms.)..(Summary of block 25:).( . Sig time.                    .[0-9]{10}..*).( . Lines:                       73 . 75 .3.)...(Summary of logfile:).( . Count of blocks:             30).( . Count of record hashes:      88).( . Count of resigned blocks:    3).( . Count of meta-records:       1) ]]
}

@test "sign output with debug level 3" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   4: processing block header... ok.).(Block no.   4: .r.r..r..).(Block no.   4: processing partial signature data... ok.).(Block no.   4: signing time: .1517928939..*UTC).(Block no.   4: writing block signature to file... ok.).(Block no.   4: lines processed 10 . 12 .3.).(Block no.   4: Warning: all final tree hashes are missing.).(Block no.   5: processing block header... ok.).(Block no.   5: .r.r..r..).(Block no.   5: processing partial signature data... ok.).(Block no.   5: creating missing KSI signature... ok.*ms.).(Block no.   5: signing time: .[0-9]{10}.*UTC).(Block no.   5: writing block signature to file... ok.).(Block no.   5: lines processed 13 . 15 .3.).(Block no.   5: Warning: all final tree hashes are missing.) ]]
}

#block, err_hex
f_sign_error () {
	echo "( x Error: Failed to sign unsigned block $1:).(   . Network error. .$2.).(   . Signing is continued and unsigned block will be kept.)"
}

#blocks, records, resigned, unsigned, meta-rec
f_blk_smry_wth_err () {
	echo "(Summary of logfile:).( . Count of blocks:             $1).( . Count of record hashes:      $2).( . Count of resigned blocks:    $3).( . Count of unsigned blocks:    $4).( . Count of meta-records:       $5)"
}

#block
f_blk_fail () {
	echo "(Signing Block no.  $1... failed..*ms.)"
}

@test "sign output with debug level 1: continue on fail with debug level 1" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned --continue-on-fail -S this_url_does_not_work -o test/out/dummy.ksig -d
	[ "$status" -eq 1 ]
	[[ "$output" =~ (Signing... failed.)..`f_sign_error 5 0x202`..`f_sign_error 6 0x202`..`f_sign_error 25 0x202`..`f_blk_smry_wth_err 30 88 0 3 1` ]]
}

@test "sign output with debug level 1: continue on fail with debug level 2" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned --continue-on-fail -S this_url_does_not_work -o test/out/dummy.ksig -dd
	[ "$status" -eq 1 ]
	[[ "$output" =~ `f_blk_fail " 5"`..`f_sign_error 5 0x202`..`f_blk_fail " 6"`..`f_sign_error 6 0x202`..`f_blk_fail "25"`..`f_sign_error 25 0x202`...`f_blk_smry_wth_err 30 88 0 3 1` ]]
}

@test "sign output with debug level 1: continue on fail with debug level 3" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned --continue-on-fail -S this_url_does_not_work -o test/out/dummy.ksig -ddd
	[ "$status" -eq 1 ]
	[[ "$output" =~ .(Block no.   5: processing block header... ok.).(Block no.   5: .r.r..r..).(Block no.   5: processing partial signature data... ok.).(Block no.   5: creating missing KSI signature... failed.*ms.).(Block no.   5: writing block signature to file... ok.).(Block no.   5: lines processed 13 . 15 .3.).(Block no.   5: Warning: all final tree hashes are missing.).(Block no.   5: Error: Signing is continued and unsigned block will be kept.).(Block no.   6: processing block header... ok.) ]]
}

@test "check if --aggr-pdu-v rises the warning" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -d --aggr-pdu-v v2
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Warning: --aggr-pdu-v has no effect and will be removed in the future." ]]
}

@test "sign output with debug level 3 and --hex-to-str" {
	run src/logksi sign test/resource/logs_and_signatures/signed -o test/out/dummy.ksig --hex-to-str -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   4: Meta-record value: 'Block closed due to file closure.\\00'." ]]
}
