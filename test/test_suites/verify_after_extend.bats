#!/bin/bash

export KSI_CONF=test/test.cfg

@test "verify signed.logsig" {
	run ./src/logksi verify test/out/signed \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem \
	--cnstr email=internal@guardtime.com -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed2.logsig" {
	run ./src/logksi verify test/out/signed test/out/signed2.logsig \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem \
	--cnstr email=internal@guardtime.com -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed4.logsig" {
	run ./src/logksi verify test/out/signed4 \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem \
	--cnstr email=internal@guardtime.com -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

