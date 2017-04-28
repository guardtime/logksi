#!/bin/bash

@test "extend signed.logsig to earliest publication" {
	run ./src/logksi extend test/out/signed \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem \
	--cnstr email=internal@guardtime.com -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "extend signed2.logsig to publication string" {
	run test -f test/out/signed2.logsig.bak
	[ "$status" -ne 0 ]
	run ./src/logksi extend test/out/signed2 \
	--pub-str AAAAAA-CZAIED-AAPVYU-HILW2M-KXRX6Z-M5QQQC-WUJVMM-B5USWC-7VHLO2-UQ4DME-WKKRKB-NBYMUF \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem \
	--cnstr email=internal@guardtime.com -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed2.logsig.bak
	[ "$status" -eq 0 ]
}

@test "extend signed3.logsig to output signed4.logsig" {
	run ./src/logksi extend test/out/signed3 -o test/out/signed4.logsig \
	--pub-str AAAAAA-CZAIED-AAPVYU-HILW2M-KXRX6Z-M5QQQC-WUJVMM-B5USWC-7VHLO2-UQ4DME-WKKRKB-NBYMUF \
	-P file://test/resource/publication/dummy-publications.bin \
	-V test/resource/certificates/dummy-cert.pem \
	--cnstr email=internal@guardtime.com -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run test -f test/out/signed4.logsig
	[ "$status" -eq 0 ]
	run test -f test/out/signed3.logsig.bak
	[ "$status" -ne 0 ]
}

