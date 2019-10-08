#!/bin/bash

export KSI_CONF=test/test.cfg

@test "verify output with debug level 1" {
	run src/logksi verify test/resource/logs_and_signatures/log_repaired --ignore-desc-block-time -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying... ok.)..(Summary of logfile:).( . Count of blocks:             30.*).( . Count of record hashes:      88).( . Count of meta.records:       1).( . Input hash:  SHA-512:dd4e87.*e2b137).( . Output hash: SHA-512:7f5a17.*cd7827) ]]
}

@test "verify output with debug level 2" {
	run src/logksi verify test/resource/logs_and_signatures/signed --ignore-desc-block-time -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying block no.   1... ok.)..(Summary of block 1:).( . Sig time:    .1517928882.*).( . Input hash:  SHA-512:7f3dea.*ee3141).( . Output hash: SHA-512:20cfea.*88944a).( . Lines:                       1 . 3 .3.)..(Verifying block no.   2... ok.)..(Summary of block 2:).( . Sig time:    .1517928883.*).( . Input hash:  SHA-512:20cfea.*88944a).( . Output hash: SHA-512:9c1ea0.*42e444).( . Lines:                       4 . 6 .3.)..(Verifying block no.   3... ok.)..(Summary of block 3:).( . Sig time:    .1517928884.*).( . Input hash:  SHA-512:9c1ea0.*42e444).( . Output hash: SHA-512:1dfeae.*43e987).( . Lines:                       7 . 9 .3.)..(Verifying block no.   4... ok.)..(Summary of block 4:).( . Sig time:    .1517928885.*).( . Input hash:  SHA-512:1dfeae.*43e987).( . Output hash: SHA-512:f7f5b4.*b2b596).( . Line:                        n.a).( . Count of meta-records:       1)...(Summary of logfile:).( . Count of blocks:             4).( . Count of record hashes:      9).( . Count of meta-records:       1).( . Input hash:  SHA-512:7f3dea.*ee3141).( . Output hash: SHA-512:f7f5b4.*b2b596) ]]
}

@test "verify output with debug level 3. Multiple blocks. Missing hshes" {
	run src/logksi verify test/resource/logs_and_signatures/log_repaired --ignore-desc-block-time -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: input hash: SHA-512:dd4e87.*2b137.).(Block no.   1: .r.r..r..).(Block no.   1: processing block signature data... ok.).(Block no.   1: lines processed 1 . 3 .3.).(Block no.   1: verifying KSI signature... ok.*ms.).(Block no.   1: signing time: .1517928936.*).(Block no.   1: output hash: SHA-512:18708a.*eeeb7.).(Block no.   1: Warning: all final tree hashes are missing.).*(Block no.  30: all final tree hashes are present.).(Finalizing log signature... ok.) ]]
}

@test "verify output with debug level 3. Single block with Metarecord" {
	run src/logksi verify test/resource/interlink/ok-testlog-interlink-1 -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: input hash: SHA-256:a55829.*a5fc9.).(Block no.   1: Meta-record key  : .com.guardtime.blockCloseReason..).(Block no.   1: Meta-record value: 426c6f636b20636c6f7365642064756520746f2066696c6520636c6f737572652e00.).(Block no.   1: .rrrrrrrrrrrrMr.).(Block no.   1: processing block signature data... ok.).(Block no.   1: lines processed 1 . 12 .12.).(Block no.   1: verifying KSI signature... ok.*ms.).(Block no.   1: signing time: .1539771487.) ]]
}

@test "verify output with debug level 3. Single block with Metarecord as string" {
	run src/logksi verify test/resource/interlink/ok-testlog-interlink-1 -ddd --hex-to-str
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   1: input hash: SHA-256:a55829.*a5fc9.).(Block no.   1: Meta-record key  : .com.guardtime.blockCloseReason..).(Block no.   1: Meta-record value: .Block closed due to file closure..00..).(Block no.   1: .rrrrrrrrrrrrMr.) ]]
}

@test "previous block is more recent than next block with debug level 2" {
	run ./src/logksi verify test/resource/logs_and_signatures/log_repaired -dd
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Verifying block no.  17... ok.).*(Verifying block no.  18... failed.)..( x Error: Block no.  17 .*is more recent than).(          block no.  18 .1517928940. 2018.02.06 14.55.40 UTC.00.00)..(Summary of block 18:).( . Sig time:    .1517928940.*).( . Input hash:  SHA-512:0e11fd.*1991c4).( . Output hash: SHA-512:907899.*d2be10).( . Lines:                       52 . 54 .3.)..(Verifying block no.  19... ok.) ]]
}

@test "previous block is more recent than next block with debug level 3" {
	run ./src/logksi verify -ddd test/resource/logs_and_signatures/log_repaired
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Block no.  18: verifying KSI signature... ok.*ms.).(Block no.  18: signing time: .1517928940.).*(Block no.  18: checking signing time with previous block... failed.).(Block no.  18: output hash.*SHA-512:907899.*d2be10.).(Block no.  18: Warning: all final tree hashes are missing.).(Block no.  18: Error: Block no.  17 .*is more recent than block no.  18 .1517928940. 2018.02.06 14.55.40 UTC.00.00). ]]
}

@test "verify output with debug level 3. record hash missing for a logline" {
	run ./src/logksi verify test/resource/logfiles/all_hashes test/resource/logsignatures/record_hash_missing_for_last_record.logsig -ddd
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Block no.   1: processing block header... ok.).(Block no.   1: input hash: SHA-512:7f5a17.*cd7827.).(Block no.   1: [{]r.r... X) ]]
	[[ "$output" =~ "Error: Block no. 1: missing record hash for logline no. 3" ]]
}

@test "verify output with debug level 3. tree hash out of block" {
	run ./src/logksi verify test/resource/logfiles/all_hashes test/resource/logsignatures/tree_hash_out_of_block.logsig -ddd
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Block no.   1: processing block header... ok.).(Block no.   1: input hash: SHA-512:7f5a17.*cd7827.).(Block no.   1: [{]r.r..r.[}]).*(Block no.   1: [{]. X) ]]
	[[ "$output" =~ "Error: Block no. 2: tree hash without preceding block header found." ]]
}

@test "verify output with debug level 3. too much final tree hashes" {
	run ./src/logksi verify test/resource/logfiles/all_hashes test/resource/logsignatures/tree_hashes_final_too_many.logsig -ddd
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Block no.   1: processing block header... ok.).(Block no.   1: input hash: SHA-512:7f5a17.*cd7827.).(Block no.   1: interpreting tree hash no.   5 as a final hash... ok.).(Block no.   1: [{]r.r..r.:. X) ]]
	[[ "$output" =~ "Error: Block no. 1: unexpected final tree hash no. 6." ]]
}

@test "verify output with debug level 1. two files with same signing time for output and input hash" {
	run src/logksi verify --warn-same-block-time -d -- test/resource/interlink/ok-testlog-interlink-same-sig-time-[12]
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying... ok.)..(Summary of logfile:).*( . Output hash: SHA-256:601697.*35dc7d)..(Warning: Last block from file).*(ok-testlog-interlink-same-sig-time-1).*(and).*(first block from file).*(ok-testlog-interlink-same-sig-time-2).*(has same signing time .1540454662.) ]]
}

@test "verify output with debug level 2. two files with same signing time for output and input hash" {
	run src/logksi verify --warn-same-block-time -dd -- test/resource/interlink/ok-testlog-interlink-same-sig-time-[12]
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Log file.*ok-testlog-interlink-same-sig-time-1..).(Verifying block no.   1... ok.).*(Log file.*ok-testlog-interlink-same-sig-time-2..).(Verifying block no.   1... ok.).*(Summary of logfile:).*( . Output hash: SHA-256:601697.*35dc7d)..(Warning: Last block from file).*(ok-testlog-interlink-same-sig-time-1).*(and).*(first block from file).*(ok-testlog-interlink-same-sig-time-2).*(has same signing time .1540454662.) ]]
}

@test "verify output with debug level 3. two files with same signing time for output and input hash" {
	run src/logksi verify --warn-same-block-time -ddd -- test/resource/interlink/ok-testlog-interlink-same-sig-time-[12]
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   1: output hash: SHA-256:601697.*35dc7d.).(Block no.   1: Warning: Last block from file).*(ok-testlog-interlink-same-sig-time-1).*(and).*(first block from file).*(ok-testlog-interlink-same-sig-time-2).*(has same signing time .1540454662.) ]]
}

@test "verify output with debug level 1. excerpt file." {
	run src/logksi verify test/resource/excerpt/log-ok.excerpt -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying... ok.)..(Summary of logfile:).( . Count of blocks:             2).( . Count of record hashes:      4) ]]
}

@test "verify output with debug level 2. excerpt file." {
	run src/logksi verify test/resource/excerpt/log-ok.excerpt -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying block no.   1... ok.)..(Summary of block 1:).( . Sig time:    .1517928936.*).( . Record count:                2)..(Verifying block no.   2... ok.)..(Summary of block 2:).( . Sig time:    .1517928937.*).( . Record count:                2)...(Summary of logfile:).( . Count of blocks:             2).( . Count of record hashes:      4) ]]
}

@test "verify output with debug level 3. excerpt file." {
	run src/logksi verify test/resource/excerpt/log-ok.excerpt -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Processing magic number... ok.).(Block no.   1: processing KSI signature ... ok.).(Block no.   1: verifying KSI signature... ok.*ms.).(Block no.   1: signing time: .1517928936.*).(Block no.   1: .rr.).(Block no.   2: processing KSI signature ... ok.).(Block no.   2: verifying KSI signature... ok.*ms.).(Block no.   2: signing time: .1517928937.*).(Block no.   2: .rr.) ]]
}

@test "verify and warn about changing client id with debug level 1" {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-ok-one-sig-diff-client-id.logsig --ignore-desc-block-time --warn-client-id-change -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying... ok.)..(Summary of logfile:).*(Output hash: SHA-512:f7f5b4.*b2b596)..( o Warning: Client ID in block 2 is not constant:).(   . Expecting: .GT :: GT :: GT :: anon.).(   . But is:    .GT :: GT :: GT :: sha512.) ]]
}

@test "verify and warn about changing client id with debug level 2" {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-ok-one-sig-diff-client-id.logsig --ignore-desc-block-time --warn-client-id-change -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... ok.).*(Verifying block no.   3... ok.).*(Verifying block no.   4... ok.).*(Summary of logfile:).*(Output hash: SHA-512:f7f5b4.*b2b596)..( o Warning: Client ID in block 2 is not constant:).(   . Expecting: .GT :: GT :: GT :: anon.).(   . But is:    .GT :: GT :: GT :: sha512.) ]]
}

@test "verify and warn about changing client id with debug level 3" {
	run src/logksi verify test/resource/continue-verification/log test/resource/continue-verification/log-ok-one-sig-diff-client-id.logsig --ignore-desc-block-time --warn-client-id-change -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   2: output hash: SHA-512:9c1ea0.*42e444.).(Block no.   2: Warning: all final tree hashes are missing.).(Block no.   2: Warning: Client ID is not constant. Expecting .GT :: GT :: GT :: anon.. but is .GT :: GT :: GT :: sha512..).(Block no.   3: processing block header... ok.) ]]
	[[ ! "$output" =~ " o Warning: Client ID in block 2 is not constant" ]]
}

@test "verify excerpt file and warn about changing client id with debug level 1" {
	run src/logksi verify test/resource/excerpt/diff-client-id.excerpt --warn-client-id-change -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying... ok.)..(Summary of logfile:).*( . Count of record hashes:      2)..( o Warning: Client ID in block 2 is not constant:).(   . Expecting: .GT :: GT :: GT :: anon.).(   . But is:    .GT :: GT :: GT :: sha512.) ]]
}

@test "verify excerpt file and warn about changing client id with debug level 2" {
	run src/logksi verify test/resource/excerpt/diff-client-id.excerpt --warn-client-id-change -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying block no.   1... ok.).*(Verifying block no.   2... ok.).*(Summary of logfile:).*( . Count of record hashes:      2)..( o Warning: Client ID in block 2 is not constant:).(   . Expecting: .GT :: GT :: GT :: anon.).(   . But is:    .GT :: GT :: GT :: sha512.) ]]
}

@test "verify excerpt file and warn about changing client id with debug level 3" {
	run src/logksi verify test/resource/excerpt/diff-client-id.excerpt --warn-client-id-change -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   2: verifying KSI signature... ok.*ms.).(Block no.   2: signing time: .1553672948.*UTC).(Block no.   2: .r.).(Block no.   2: Warning: Client ID is not constant. Expecting .GT :: GT :: GT :: anon.. but is .GT :: GT :: GT :: sha512..).(Finalizing log signature... ok.) ]]
	[[ ! "$output" =~ " o Warning: Client ID in block 2 is not constant" ]]
}

@test "check if --ext-pdu-v rises the warning" {
	run src/logksi verify test/resource/logs_and_signatures/log_repaired --ignore-desc-block-time -d --ext-pdu-v v2
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Warning: --ext-pdu-v has no effect and will be removed in the future." ]]
}