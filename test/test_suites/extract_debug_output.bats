#!/bin/bash

export KSI_CONF=test/test.cfg


@test "extract record output with debug level 1" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -o test/out/dummy.excerpt -r 1,3-5 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Extracting records... ok.).(Summary of logfile:).( . Count of blocks:             30.*).( . Count of record hashes:      88).( . Count of meta.records:       1).( . Records extracted:           4) ]]
}

@test "extract record output with debug level 2" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -o test/out/dummy.excerpt -r 1,3-5 -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Extracting log record from block   1 .line   1.... ok.).(Extracting log record from block   1 .line   3.... ok.).(Summary of block 1:).( . Sig time:                    .1517928936.).*(Lines:                       1 . 3 .3.).( . Records extracted:           2)..(Extracting log record from block   2 .line   4.... ok.).(Extracting log record from block   2 .line   5.... ok.).(Summary of block 2:).( . Sig time:                    .1517928937.).*(Lines:                       4 . 6 .3.).( . Records extracted:           2)..(Summary of logfile:).( . Count of blocks:             30.*).( . Count of record hashes:      88).( . Count of meta.records:       1).( . Records extracted:           4) ]]
}

@test "extract record output with debug level 3" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -o test/out/dummy.excerpt -r 1,3-5 -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   2: processing block header... ok.).(Block no.   2: .r.r..r..).(Block no.   2: processing block signature data... ok.).(Block no.   2: lines processed 4 . 6 .3.).(Block no.   2: verifying KSI signature... ok.*ms.).(Block no.   2: extracting log records .line   4.... ok.).(Block no.   2: extracting log records .line   5.... ok.).(Block no.   2: signing time: .1517928937.*UTC).(Block no.   2: Warning: all final tree hashes are missing.) ]]
}
