#!/bin/bash

export KSI_CONF=test/test.cfg

@test "verify signed.logsig" {
	run ./src/logksi verify test/out/signed \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed2.logsig" {
	run ./src/logksi verify test/out/signed test/out/signed2.logsig \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed2.logsig against publication string" {
	run ./src/logksi verify --ver-pub test/out/signed test/out/signed2.logsig \
	--pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2JK \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed4.logsig" {
	run ./src/logksi verify test/out/signed4 \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

