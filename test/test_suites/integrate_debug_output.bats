#!/bin/bash

export KSI_CONF=test/test.cfg


@test "Integrate output with debug level 1" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.ksig --force-overwrite -d
	[[ "$output" =~ (Integrating block no.   1: into log signature... ok.).(Integrating block no.   2: into log signature... ok.).(Integrating block no.   3: into log signature... ok.).(Integrating block no.   4: into log signature... ok.) ]]
	[ "$status" -eq 0 ]
}

@test "Integrate output with debug level 2" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.ksig --force-overwrite -dd
	[[ "$output" =~ (Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing partial block data... ok.).(Block no.   1: processing partial signature data... ok.).(Block no.   1: writing block signature to file... ok.).(Block no.   1: output hash: SHA-512:20cfe.*8944a.).(Warning: Block no.   1: all final tree hashes are missing.).(Block no.   2: processing block header... ok.).*(Block no.   4: all final tree hashes are present.).(Finalizing log signature... ok.) ]]	
	[ "$status" -eq 0 ]
}
