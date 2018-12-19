#!/bin/bash

export KSI_CONF=test/test.cfg


@test "extract record output with debug level 1" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -o test/out/dummy.excerpt -r 1,3-5 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Extracting log record from block   1 .line   1.... ok.).(Extracting log record from block   1 .line   3.... ok.).(Extracting log record from block   2 .line   4.... ok.).(Extracting log record from block   2 .line   5.... ok.) ]]

}

@test "extract record output with debug level 2" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -o test/out/dummy.excerpt -r 1,3-5 -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   2: processing block header... ok.).(Block no.   2: processing record hash... ok.).(Block no.   2: processing tree hash...   ok.).(Block no.   2: processing record hash... ok.).(Block no.   2: processing tree hash...   ok.).(Block no.   2: processing tree hash...   ok.).(Block no.   2: processing record hash... ok.).(Block no.   2: processing tree hash...   ok.).(Block no.   2: processing block signature data... ok.).(Block no.   2: verifying KSI signature... ok.*ms.).(Block no.   2: extracting log records .line   4.... ok.).(Block no.   2: extracting log records .line   5.... ok.).(Block no.   2: output hash: SHA-512:8f82.*cbaf.).(Warning: Block no.   2: all final tree hashes are missing.).(Block no.   3: processing block header... ok.).(Block no.   3: processing record hash... ok.).(Block no.   3: processing tree hash...   ok.).(Block no.   3: processing record hash... ok.).(Block no.   3: processing tree hash...   ok.).(Block no.   3: processing tree hash...   ok.).(Block no.   3: processing record hash... ok.).(Block no.   3: processing tree hash...   ok.).(Block no.   3: processing block signature data... ok.).(Block no.   3: verifying KSI signature... ok.*ms.).(Block no.   3: output hash: SHA-512:64e6.*00c.) ]]
}




