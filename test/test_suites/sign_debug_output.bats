#!/bin/bash

export KSI_CONF=test/test.cfg

@test "sign output with debug level 1" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Signing... ok.).(Summary of logfile:).( . Count of blocks:             30).( . Count of record hashes:      88).( . Count of resigned blocks:    3).( . Count of meta-records:       1) ]]
}

@test "sign output with debug level 2" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Signing Block no.   5... ok.*ms.).(Summary of block 5:).( . Sig time.                    .[0-9]{10}..*).( . Lines:                       13 . 15 .3.)..(Signing Block no.   6... ok.*ms.).(Summary of block 6:).( . Sig time.                    .[0-9]{10}..*).( . Lines:                       16 . 18 .3.)..(Signing Block no.  25... ok.*ms.).(Summary of block 25:).( . Sig time.                    .[0-9]{10}..*).( . Lines:                       73 . 75 .3.)..(Summary of logfile:).( . Count of blocks:             30).( . Count of record hashes:      88).( . Count of resigned blocks:    3).( . Count of meta-records:       1) ]]
}

@test "sign output with debug level 3" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   4: processing block header... ok.).(Block no.   4: processing record hash... ok.).(Block no.   4: processing tree hash...   ok.).(Block no.   4: processing record hash... ok.).(Block no.   4: processing tree hash...   ok.).(Block no.   4: processing tree hash...   ok.).(Block no.   4: processing record hash... ok.).(Block no.   4: processing tree hash...   ok.).(Block no.   4: processing partial signature data... ok.).(Block no.   4: writing block signature to file... ok.).(Block no.   4: output hash: SHA-512:8aed.*2c00.).(Warning: Block no.   4: all final tree hashes are missing.).(Block no.   5: processing block header... ok.).(Block no.   5: processing record hash... ok.).(Block no.   5: processing tree hash...   ok.).(Block no.   5: processing record hash... ok.).(Block no.   5: processing tree hash...   ok.).(Block no.   5: processing tree hash...   ok.).(Block no.   5: processing record hash... ok.).(Block no.   5: processing tree hash...   ok.).(Block no.   5: processing partial signature data... ok.).(Block no.   5: creating missing KSI signature... ok.*ms.).(Block no.   5: writing block signature to file... ok.).(Block no.   5: output hash: SHA-512:868f.*602e.) ]]
}