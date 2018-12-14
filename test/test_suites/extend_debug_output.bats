#!/bin/bash

export KSI_CONF=test/test.cfg

#

#src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -d
#src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig --pub-str AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2F -d

@test "Extend output with debug level 1" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -d
	[ "$status" -eq 0 ]
		[[ "$output" =~ (Receiving publications file... ok.*ms.).(Verifying publications file... ok.*ms.).(Extending Block no.   1 to the earliest available publication... ok.*ms.).(Extending Block no.   2 to the earliest available publication... ok.*ms.).(Extending Block no.   3 to the earliest available publication... ok.*ms.).(Extending Block no.   4 to the earliest available publication... ok.*ms.) ]]
}

@test "Extend output with debug level 2" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -dd
	[ "$status" -eq 0 ]
		[[ "$output" =~ (Receiving publications file... ok.*ms.).(Verifying publications file... ok.*ms.).(Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing block signature data... ok.).(Block no.   1: verifying KSI signature... ok.*ms.).(Block no.   1: extending KSI signature to the earliest available publication: 2018.02.15 00.00.00 UTC .1518652800.... ok.*ms.).(Block no.   1: output hash: SHA-512:20cfe.*8944a.).(Warning: Block no.   1: all final tree hashes are missing.).(Block no.   2: processing block header... ok.).*(Block no.   4: all final tree hashes are present.).(Finalizing log signature... ok.) ]]
}

@test "Extend with publication string and check output with debug level 1" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig --pub-str AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2F -d
	[ "$status" -eq 0 ]
		[[ "$output" =~ (Receiving publications file... ok.*ms.).(Verifying publications file... ok.*ms.).(Extending Block no.   1 to the specified publication... ok.*ms.).(Extending Block no.   2 to the specified publication... ok.*ms.).(Extending Block no.   3 to the specified publication... ok.*ms.).(Extending Block no.   4 to the specified publication... ok.*ms.) ]]
}

@test "Extend with publication string and check output with debug level 2" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig --pub-str AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2F -dd
	[ "$status" -eq 0 ]
																																																																																																																																																											     #Block no.   1: extending KSI signature to the specified publication: 2018-07-15 00:00:00 UTC (1531612800)... ok. (30 ms)
		[[ "$output" =~ (Receiving publications file... ok.*ms.).(Verifying publications file... ok.*ms.).(Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing block signature data... ok.).(Block no.   1: verifying KSI signature... ok.*ms.).(Block no.   1: Searching for a publication record from publications file... ok.).(Block no.   1: extending KSI signature to the specified publication: 2018.07.15 00.00.00 UTC .1531612800.... ok.*ms.).(Block no.   1: output hash: SHA-512:20cfe.*8944a.).(Warning: Block no.   1: all final tree hashes are missing.).(Block no.   2: processing block header... ok.).*(Block no.   4: all final tree hashes are present.).(Finalizing log signature... ok.) ]]
}


