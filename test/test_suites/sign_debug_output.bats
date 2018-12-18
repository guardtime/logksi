#!/bin/bash

export KSI_CONF=test/test.cfg

@test "Sign output with debug level 1" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Signing Block no.   5... ok.*ms.).(Signing Block no.   6... ok.*ms.).(Signing Block no.  25... ok.*ms.) ]]
}

@test "Sign output with debug level 2" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   4: processing block header... ok.).(Block no.   4: processing record hash... ok.).(Block no.   4: processing tree hash...   ok.).(Block no.   4: processing record hash... ok.).(Block no.   4: processing tree hash...   ok.).(Block no.   4: processing tree hash...   ok.).(Block no.   4: processing record hash... ok.).(Block no.   4: processing tree hash...   ok.).(Block no.   4: processing partial signature data... ok.).(Block no.   4: writing block signature to file... ok.).(Block no.   4: output hash: SHA-512:8aed.*2c00.).(Warning: Block no.   4: all final tree hashes are missing.).(Block no.   5: processing block header... ok.).(Block no.   5: processing record hash... ok.).(Block no.   5: processing tree hash...   ok.).(Block no.   5: processing record hash... ok.).(Block no.   5: processing tree hash...   ok.).(Block no.   5: processing tree hash...   ok.).(Block no.   5: processing record hash... ok.).(Block no.   5: processing tree hash...   ok.).(Block no.   5: processing partial signature data... ok.).(Block no.   5: creating missing KSI signature... ok.*ms.).(Block no.   5: writing block signature to file... ok.).(Block no.   5: output hash: SHA-512:868f.*602e.) ]]
}
