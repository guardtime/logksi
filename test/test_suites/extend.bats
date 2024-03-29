#!/bin/bash

export KSI_CONF=test/test.cfg

cp test/resource/logfiles/signed test/out/signed2
cp test/resource/logfiles/signed test/out/signed3
cp test/resource/logfiles/signed test/out/signed4


@test "extend signed.logsig to earliest publication" {
	run ./src/logksi extend test/out/signed \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "extend signed2.logsig to publication string" {
	run test -f test/out/signed2.logsig.bak
	[ "$status" -ne 0 ]
	run ./src/logksi extend test/out/signed2 \
	--pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2JK \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed2.logsig.bak
	[ "$status" -eq 0 ]
}

# @SKIP_MEMORY_TEST
@test "extend from standard input" {
	run bash -c "cat test/out/signed3.logsig | ./src/logksi extend --sig-from-stdin -o test/out/extended_from_stdin.logsig \
	--pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2JK \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -ddd"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/extended_from_stdin.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/signed3.logsig.bak
	[ "$status" -ne 0 ]
}

@test "extend signed3.logsig to output signed4.logsig" {
	run ./src/logksi extend test/out/signed3 -o test/out/signed4.logsig \
	--pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2JK \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed4.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/signed3.logsig.bak
	[ "$status" -ne 0 ]
}

# @SKIP_MEMORY_TEST
@test "extend signed3.logsig to stdout" {
	run bash -c "./src/logksi extend test/out/signed3 -o - \
	--pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2JK \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -ddd > test/out/extended_stdout.logsig"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/extended_stdout.logsig
	[ "$status" -eq 0 ]
	run diff test/out/signed4.logsig test/out/extended_stdout.logsig
	[ "$status" -eq 0 ]
}

@test "extend log_repaired.logsig to earliest publication. Check if more recent signatures has more recent publications. " {
	run src/logksi extend test/resource/logs_and_signatures/log_repaired -ddd -o test/out/delme.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   [1-4]: extending KSI signature to the earliest available publication: 2018.02.15 00:00:00 UTC.*){4} ]]
	[[ "$output" =~ (Block no.   [5-9]: extending KSI signature to the earliest available publication: 2018.11.15 00:00:00 UTC.*){5} ]]
	[[ "$output" =~ (Block no.  1[0-7]: extending KSI signature to the earliest available publication: 2018.11.15 00:00:00 UTC.*){8} ]]
	[[ "$output" =~ (Block no.  1[8-9]: extending KSI signature to the earliest available publication: 2018.02.15 00:00:00 UTC.*){2} ]]
	[[ "$output" =~ (Block no.  2[0-4]: extending KSI signature to the earliest available publication: 2018.02.15 00:00:00 UTC.*){5} ]]
	[[ "$output" =~ (Block no.  25: extending KSI signature to the earliest available publication: 2018.11.15 00:00:00 UTC.*) ]]
	[[ "$output" =~ (Block no.  2[6-9]: extending KSI signature to the earliest available publication: 2018.02.15 00:00:00 UTC.*){4} ]]
	[[ "$output" =~ (Block no.  30: extending KSI signature to the earliest available publication: 2018.02.15 00:00:00 UTC.*) ]]
}

@test "extend log_repaired.logsig to specified publication. Check if every signatures has the same publication. " {
	run src/logksi extend test/resource/logs_and_signatures/log_repaired -ddd --pub-str AAAAAA-C35S3Q-AAJAEO-LVGZFW-DI5Q5A-6KQFIK-C62UVK-TX7ULN-6GZQNY-TXIPP3-MQNLJD-SUWGVT -o test/out/delme.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   [1-9]: extending KSI signature to the specified publication: 2018.11.15 00:00:00 UTC.*){9} ]]
	[[ "$output" =~ (Block no.  [1-3][0-9]: extending KSI signature to the specified publication: 2018.11.15 00:00:00 UTC.*){21} ]]
}

@test "extend and check if backup is really backup" {
	run cp  test/resource/logs_and_signatures/signed test/out/ext-backup-test
	run cp  test/resource/logs_and_signatures/signed.logsig test/out/ext-backup-test.logsig
	run ./src/logksi extend test/out/ext-backup-test -dd --pub-str AAAAAA-DBNDCI-AAKOZB-4EAVXI-OMCRJJ-ZPHEEM-Y7XQZM-YVTHYH-7IJAXF-FYELFS-C77R5H-DMWXJP
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Summary of block 1).*(Extended to).*(1634256000).*(Summary of block 4).*(Extended to).*(1634256000) ]]
	run test -f test/out/ext-backup-test.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/ext-backup-test.logsig.bak
	[ "$status" -eq 0 ]
	run diff test/resource/logs_and_signatures/signed.logsig test/out/ext-backup-test.logsig.bak
	[ "$status" -eq 0 ]
	run diff test/resource/logs_and_signatures/signed.logsig test/out/ext-backup-test.logsig
	[ "$status" -ne 0 ]
}

@test "Extend excerpt file to earliest publication" {
	run src/logksi extend test/resource/excerpt/log-ok.excerpt -o test/out/log-ok.excerpt.extended.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   [1-2]: extending KSI signature to the earliest available publication: 2018.02.15 00:00:00 UTC.*){2} ]]
}

@test "Extend excerpt file to publication string" {
	run src/logksi extend test/resource/excerpt/log-ok.excerpt --pub-str AAAAAA-C2VG3Y-AANAMA-FULJ3X-CMWLPB-F5O2BA-7Y6UE5-VOJKPQ-OV2VFQ-W3SXJM-JIDMWY-4PDBN2 -o test/out/log-ok.excerpt.extended-to-pub.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no.   [1-2]: extending KSI signature to the specified publication: 2018.03.15 00:00:00 UTC.*){2} ]]
}

@test "extend excerpt file and check if backup is really backup" {
	run cp test/resource/excerpt/log-ok.excerpt test/out/backup-test.excerpt
	run cp test/resource/excerpt/log-ok.excerpt.logsig test/out/backup-test.excerpt.logsig
	run ./src/logksi extend test/out/backup-test.excerpt -dd
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Summary of block 1).*(Extended to).*(1518652800).*(Summary of block 2).*(Extended to).*(1518652800) ]]
	run test -f test/out/backup-test.excerpt.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/backup-test.excerpt.logsig.bak
	[ "$status" -eq 0 ]
	run diff test/resource/excerpt/log-ok.excerpt.logsig test/out/backup-test.excerpt.logsig.bak
	[ "$status" -eq 0 ]
	run diff test/resource/excerpt/log-ok.excerpt.logsig test/out/backup-test.excerpt.logsig
	[ "$status" -ne 0 ]
	run diff test/out/log-ok.excerpt.extended.logsig test/out/backup-test.excerpt.logsig
	[ "$status" -eq 0 ]
}

# @SKIP_MEMORY_TEST
@test "extend excerpt file from standard input" {
	run bash -c "cat test/resource/excerpt/log-ok.excerpt.logsig | ./src/logksi extend --sig-from-stdin -o test/out/extended_excerpt_from_stdin.logsig \
	--pub-str AAAAAA-C2VG3Y-AANAMA-FULJ3X-CMWLPB-F5O2BA-7Y6UE5-VOJKPQ-OV2VFQ-W3SXJM-JIDMWY-4PDBN2 \
	-ddd"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/extended_excerpt_from_stdin.logsig
	[ "$status" -eq 0 ]
	run diff test/out/log-ok.excerpt.extended-to-pub.logsig test/out/extended_excerpt_from_stdin.logsig
	[ "$status" -eq 0 ]
}

# @SKIP_MEMORY_TEST
@test "extend excerpt file to stdout, check that backup is not created" {
	run cp test/resource/excerpt/log-ok.excerpt.logsig test/out/backup-test2.excerpt.logsig
	run cp test/resource/excerpt/log-ok.excerpt test/out/backup-test2.excerpt
	run bash -c "./src/logksi extend test/out/backup-test2.excerpt -o - \
	--pub-str AAAAAA-C2VG3Y-AANAMA-FULJ3X-CMWLPB-F5O2BA-7Y6UE5-VOJKPQ-OV2VFQ-W3SXJM-JIDMWY-4PDBN2 \
	-ddd > test/out/extended_excerpt_stdout.logsig"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/extended_excerpt_stdout.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/extended_excerpt_stdout.logsig.bak
	[ "$status" -ne 0 ]
	run diff test/out/log-ok.excerpt.extended-to-pub.logsig test/out/extended_excerpt_stdout.logsig
	[ "$status" -eq 0 ]
	run diff test/resource/excerpt/log-ok.excerpt.logsig test/out/backup-test2.excerpt.logsig
	[ "$status" -eq 0 ]
}