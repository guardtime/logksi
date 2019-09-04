#!/bin/bash

export KSI_CONF=test/test.cfg


@test "integrate output with debug level 1" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.ksig --force-overwrite -d
	[[ "$output" =~ (Integrating... ok.)..(Summary of logfile:).( . Count of blocks:             4).( . Count of record hashes:      9).( . Count of meta-records:       1) ]]
	[ "$status" -eq 0 ]
}

@test "integrate output with debug level 2" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.ksig --force-overwrite -dd
	[[ "$output" =~ (Integrating block no.   1: into log signature... ok.)..(Summary of block 1:).( . Sig time:    .1517928882.*).( . Input hash:  SHA-512:7f3dea.*ee3141).( . Output hash: SHA-512:20cfea.*88944a).( . Lines:                       1 . 3 .3.)..(Integrating block no.   2: into log signature... ok.)..(Summary of block 2:).( . Sig time:    .1517928883.*).( . Input hash:  SHA-512:20cfea.*88944a).( . Output hash: SHA-512:9c1ea0.*42e444).( . Lines:                       4 . 6 .3.)..(Integrating block no.   3: into log signature... ok.)..(Summary of block 3:).( . Sig time:    .1517928884.*).( . Input hash:  SHA-512:9c1ea0.*42e444).( . Output hash: SHA-512:1dfeae.*43e987).( . Lines:                       7 . 9 .3.)..(Integrating block no.   4: into log signature... ok.)..(Summary of block 4:).( . Sig time:    .1517928885.*).( . Input hash:  SHA-512:1dfeae.*43e987).( . Output hash: SHA-512:f7f5b4.*b2b596).( . Line:                        n.a).( . Count of meta-records:       1)...(Summary of logfile:).( . Count of blocks:             4).( . Count of record hashes:      9).( . Count of meta-records:       1) ]]
	[ "$status" -eq 0 ]
}

@test "integrate output with debug level 3" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.ksig --force-overwrite -ddd
	[[ "$output" =~ (Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: .r.r..r..).(Block no.   1: processing partial block data... ok.).(Block no.   1: processing partial signature data... ok.).(Block no.   1: signing time: .1517928882..*UTC).(Block no.   1: writing block signature to file... ok.).(Block no.   1: lines processed 1 . 3 .3.).(Block no.   1: Warning: all final tree hashes are missing.).(Block no.   2: processing block header... ok.).(Block no.   2: .r.r..r..).(Block no.   2: processing partial block data... ok.).(Block no.   2: processing partial signature data... ok.).(Block no.   2: signing time: .1517928883..*UTC).(Block no.   2: writing block signature to file... ok.).(Block no.   2: lines processed 4 . 6 .3.).(Block no.   2: Warning: all final tree hashes are missing.).(Block no.   3: processing block header... ok.).(Block no.   3: .r.r..r..).(Block no.   3: processing partial block data... ok.).(Block no.   3: processing partial signature data... ok.).(Block no.   3: signing time: .1517928884..*UTC).(Block no.   3: writing block signature to file... ok.).(Block no.   3: lines processed 7 . 9 .3.).(Block no.   3: Warning: all final tree hashes are missing.).(Block no.   4: processing block header... ok.).(Block no.   4: Meta-record key  : .com.guardtime.blockCloseReason..).(Block no.   4: Meta-record value: 426c6f636b20636c6f7365642064756520746f2066696c6520636c6f737572652e00.).(Block no.   4: .Mr..).(Block no.   4: processing partial block data... ok.).(Block no.   4: processing partial signature data... ok.).(Block no.   4: signing time: .1517928885..*UTC).(Block no.   4: writing block signature to file... ok.).(Block no.   4: line processed n.a).(Block no.   4: all final tree hashes are present.).(Finalizing log signature... ok.)..(Warning: Some tree hashes are missing from the log signature file.) ]]
	[ "$status" -eq 0 ]
}

test_check="(Log signature parts not found:).( test\/resource\/logsignatures\/doesNotExist.logsig.parts\/blocks.dat).( test\/resource\/logsignatures\/doesNotExist.logsig.parts\/block-signatures.dat)..(Interpreting file .test\/out\/dummy.ksig. as result of synchronous signing.).(There is nothing to integrate.)"

@test "integrate output with debug level 1,2,3: result of synchronous signing already exists" {
	run ./src/logksi integrate test/resource/logsignatures/doesNotExist -o test/out/dummy.ksig -d
	[[ "$output" =~ $test_check ]]
	[ "$status" -eq 0 ]

	run ./src/logksi integrate test/resource/logsignatures/doesNotExist -o test/out/dummy.ksig -dd
	[[ "$output" =~ $test_check ]]
	[ "$status" -eq 0 ]

	run ./src/logksi integrate test/resource/logsignatures/doesNotExist -o test/out/dummy.ksig -ddd
	[[ "$output" =~ $test_check ]]
	[ "$status" -eq 0 ]
}

@test "integrate output with debug level 3 and --hex-to-str" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.ksig --force-overwrite --hex-to-str -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   4: Meta-record value: 'Block closed due to file closure.\\00'." ]]
}