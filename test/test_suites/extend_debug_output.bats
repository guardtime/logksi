#!/bin/bash

export KSI_CONF=test/test.cfg

@test "extend output with debug level 1" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Extending... ok.)..(Summary of logfile:).( . Count of blocks:             4.*).( . Count of record hashes:      9.*).( . Count of meta-records:       1) ]]
}

@test "integrate output with debug level 2" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -dd
	[[ "$output" =~ (Extending Block no.   1 to the earliest available publication... ok.*ms.)..(Summary of block 1:).( . Sig time:                    .1517928882.*).( . Extended to:                 .1518652800.*).( . Lines:                       1 . 3 .3.)..(Extending Block no.   2 to the earliest available publication... ok.*ms.)..(Summary of block 2:).( . Sig time:                    .1517928883.*).( . Extended to:                 .1518652800.*).( . Lines:                       4 . 6 .3.)..(Extending Block no.   3 to the earliest available publication... ok.*ms.)..(Summary of block 3:).( . Sig time:                    .1517928884.*).( . Extended to:                 .1518652800.*).( . Lines:                       7 . 9 .3.)..(Extending Block no.   4 to the earliest available publication... ok.*ms.)..(Summary of block 4:).( . Sig time:                    .1517928885.*).( . Extended to:                 .1518652800.*).( . Line:                        n.a).( . Count of meta-records:       1)...(Summary of logfile:).( . Count of blocks:             4).( . Count of record hashes:      9).( . Count of meta-records:       1) ]]
	[ "$status" -eq 0 ]
}

@test "extend output with debug level 3" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Receiving publications file... ok.*ms.).(Verifying publications file... ok.*ms.).(Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: .r.r..r..).(Block no.   1: processing block signature data... ok.).(Block no.   1: lines processed 1 - 3 .3.).(Block no.   1: verifying KSI signature... ok.*ms.).(Block no.   1: extending KSI signature to the earliest available publication: 2018.02.15 00.00.00 UTC .1518652800.... ok.*ms.).(Block no.   1: signing time: .1517928882.).*(Block no.   1: Warning: all final tree hashes are missing.).(Block no.   2: processing block header... ok.) ]]
}

@test "extend with publication string and check output with debug level 2" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig --pub-str AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2F -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Extending Block no.   1 to the specified publication... ok.*ms.)..(Summary of block 1:).( . Sig time:                    .1517928882.*).( . Extended to:                 .1531612800.*).( . Lines:                       1 . 3 .3.)..(Extending Block no.   2 to the specified publication... ok.*ms.)..(Summary of block 2:).( . Sig time:                    .1517928883.*).( . Extended to:                 .1531612800.*).( . Lines:                       4 . 6 .3.)..(Extending Block no.   3 to the specified publication... ok.*ms.)..(Summary of block 3:).( . Sig time:                    .1517928884.*).( . Extended to:                 .1531612800.*).( . Lines:                       7 . 9 .3.)..(Extending Block no.   4 to the specified publication... ok.*ms.)..(Summary of block 4:).( . Sig time:                    .1517928885.*).( . Extended to:                 .1531612800.*).( . Line:                        n.a).( . Count of meta-records:       1)...(Summary of logfile:).( . Count of blocks:             4).( . Count of record hashes:      9).( . Count of meta-records:       1) ]]
}

@test "extend with publication string and check output with debug level 3" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig --pub-str AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2F -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Receiving publications file... ok.*ms.).(Verifying publications file... ok.*ms.).(Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: .r.r..r..).(Block no.   1: processing block signature data... ok.).(Block no.   1: lines processed 1 - 3 .3.).(Block no.   1: verifying KSI signature... ok.*ms.).(Block no.   1: Searching for a publication record from publications file... ok.).(Block no.   1: extending KSI signature to the specified publication: 2018.07.15 00.00.00 UTC .1531612800.... ok.*ms.) ]]
}

#.(Block no.   1: signing time: .1517928882.).*(Block no.   1: Warning: all final tree hashes are missing.).(Block no.   2: processing block header... ok.)