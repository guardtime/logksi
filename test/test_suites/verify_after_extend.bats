#!/bin/bash

export KSI_CONF=test/test.cfg

@test "verify signed.logsig" {
	run ./src/logksi verify test/out/signed \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed2.logsig" {
	run ./src/logksi verify test/out/signed test/out/signed2.logsig \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed2.logsig against publication string" {
	run ./src/logksi verify --ver-pub test/out/signed test/out/signed2.logsig \
	--pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2JK \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify signed4.logsig" {
	run ./src/logksi verify test/out/signed4 \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify extended signature with publications file that does not contain needed publication record" {
	run ./src/logksi verify test/out/signed4
	[ "$status" -eq 1 ]
	[[ "$output" =~ (Signature verification according to trust anchor).*(GEN-02).*(Verification inconclusive).*(Verification of block 1 KSI signature inconclusive).*(Signature is extended to a publication that does not exist in publications file).* ]]
}

@test "Verify ext-backup-test.logsig." {
	run ./src/logksi verify --ver-pub test/out/ext-backup-test test/out/ext-backup-test.logsig -ddd --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "Verify extended (to earliest) excerpt file" {
	run src/logksi verify --ver-pub --pub-str AAAAAA-C2QTGY-AAPWM5-CPIYU5-HN7JBO-CIDA2R-P2MCVN-ZSGTU3-CTENZU-JZBC2A-A3Q7ZO-6WT5V2 test/resource/excerpt/log-ok.excerpt test/out/log-ok.excerpt.extended.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying... ok.) ]]
}

@test "Verify extended (to specific) excerpt file" {
	run src/logksi verify --ver-pub --pub-str AAAAAA-C2VG3Y-AANAMA-FULJ3X-CMWLPB-F5O2BA-7Y6UE5-VOJKPQ-OV2VFQ-W3SXJM-JIDMWY-4PDBN2 test/resource/excerpt/log-ok.excerpt test/out/log-ok.excerpt.extended-to-pub.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Verifying... ok.) ]]
}
