#!/bin/bash

export KSI_CONF=test/test.cfg

@test "Verify output with debug level 1" {
	run src/logksi verify test/resource/logfiles/unsigned test/resource/logsignatures/unsigned-repared.logsig --ignore-desc-block-time -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).(Verifying block no.   2... ok.*).(Verifying block no.   3... ok.*).*(Verifying block no.  30... ok.*) ]]
}

@test "Verify output with debug level 2. Multiple blocks. Missing hshes. " {
	run src/logksi verify test/resource/logfiles/unsigned test/resource/logsignatures/unsigned-repared.logsig --ignore-desc-block-time -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: input hash: SHA-512:dd4e87.*2b137.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing tree hash...   ok.).(Block no.   1: processing block signature data... ok.).(Block no.   1: verifying KSI signature... ok.*ms.).(Block no.   1: output hash: SHA-512:18708a.*eeeb7.).(Warning: Block no.   1: all final tree hashes are missing.).(Block no.   2: processing block header... ok.).(Block no.   2: input hash: SHA-512:18708a.*eeeb7.).*(Block no.  30: all final tree hashes are present.).(Finalizing log signature... ok.) ]]
}

@test "Verify output with debug level 2. Single block with Metarecord." {
	run src/logksi verify test/resource/interlink/ok-testlog-interlink-1 -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: input hash: SHA-256:a55829.*a5fc9.).(Block no.   1: processing record hash... ok..).*(Block no.   1: processing metarecord...  ok.).(Block no.   1: processing record hash... ok.).(Block no.   1: processing block signature data... ok.).(Block no.   1: verifying KSI signature... ok.*ms.).(Block no.   1: output hash: SHA-256:ecbc3a.*6c019.).(Finalizing log signature... ok.) ]]
}

@test "Previous block is more recent than next block with debug level 1." {
	run ./src/logksi verify -d test/resource/logfiles/unsigned test/resource/logsignatures/unsigned-repared.logsig
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.  17... ok.).(Verifying block no.  18... failed.).(Error: Block no.  17 .*is more recent than).(       block no.  18 .1517928940. 2018.02.06 14.55.40 UTC.00.00).(Verifying block no.  19... ok.) ]]
}

@test "Previous block is more recent than next block with debug level 2." {
	run ./src/logksi verify -dd test/resource/logfiles/unsigned test/resource/logsignatures/unsigned-repared.logsig
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Block no.  18: verifying KSI signature... ok.*ms.).(Block no.  18: checking signing time with previous block... failed.).(Error: Block no.  17 .*is more recent than).(       block no.  18 .1517928940. 2018.02.06 14.55.40 UTC.00.00).(Block no.  18: output hash) ]]
}