#!/bin/bash

export KSI_CONF=test/test.cfg

@test "extend signed.logsig to earliest publication" {
	run ./src/logksi extend test/out/signed \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "extend signed2.logsig to publication string" {
	run test -f test/out/signed2.logsig.bak
	[ "$status" -ne 0 ]
	run ./src/logksi extend test/out/signed2 \
	--pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2JK \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed2.logsig.bak
	[ "$status" -eq 0 ]
}

@test "extend from standard input" {
	run bash -c "cat test/out/signed3.logsig | ./src/logksi extend --sig-from-stdin -o test/out/extended_from_stdin.logsig \
	--pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2JK \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -d"
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
	-V test/resource/certificates/dummy-cert.pem -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed4.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/signed3.logsig.bak
	[ "$status" -ne 0 ]
}

@test "extend signed3.logsig to stdout" {
	run bash -c "./src/logksi extend test/out/signed3 -o - > test/out/extended_stdout.logsig \
	--pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2JK \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -d"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/extended_stdout.logsig
	[ "$status" -eq 0 ]
	run diff test/out/signed4.logsig test/out/extended_stdout.logsig
	[ "$status" -eq 0 ]
}

