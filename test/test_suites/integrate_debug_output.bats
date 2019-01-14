#!/bin/bash

export KSI_CONF=test/test.cfg


@test "integrate output with debug level 1" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.ksig --force-overwrite -d
	[[ "$output" =~ (Integrating... ok.).(Summary of logfile:).( . Count of blocks:             4).( . Count of record hashes:      9).( . Count of meta-records:       1) ]]
	[ "$status" -eq 0 ]
}

@test "integrate output with debug level 2" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.ksig --force-overwrite -dd
	[[ "$output" =~ (Integrating block no.   1: into log signature... ok.).(Summary of block 1:).( . Sig time:    .1517928882.*).( . Input hash:  SHA-512:7f3dea.*ee3141).( . Output hash: SHA-512:20cfea.*88944a).( . Lines:                       1 . 3 .3.)..(Integrating block no.   2: into log signature... ok.).(Summary of block 2:).( . Sig time:    .1517928883.*).( . Input hash:  SHA-512:20cfea.*88944a).( . Output hash: SHA-512:9c1ea0.*42e444).( . Lines:                       4 . 6 .3.)..(Integrating block no.   3: into log signature... ok.).(Summary of block 3:).( . Sig time:    .1517928884.*).( . Input hash:  SHA-512:9c1ea0.*42e444).( . Output hash: SHA-512:1dfeae.*43e987).( . Lines:                       7 . 9 .3.)..(Integrating block no.   4: into log signature... ok.).(Summary of block 4:).( . Sig time:    .1517928885.*).( . Input hash:  SHA-512:1dfeae.*43e987).( . Output hash: SHA-512:f7f5b4.*b2b596).( . Line:                        n.a).( . Count of meta-records:       1)..(Summary of logfile:).( . Count of blocks:             4).( . Count of record hashes:      9).( . Count of meta-records:       1) ]]
	[ "$status" -eq 0 ]
}

@test "integrate output with debug level 3" {
	run ./src/logksi integrate test/resource/logsignatures/signed -o test/out/dummy.ksig --force-overwrite -ddd
	[[ "$output" =~ (Processing magic number... ok.).(Block no.   1: processing block header... ok.).(Block no.   1: .r.r..r..).(Block no.   1: processing partial block data... ok.).(Block no.   1: processing partial signature data... ok.).(Block no.   1: writing block signature to file... ok.).(Block no.   1: Warning: all final tree hashes are missing.).(Block no.   2: processing block header... ok.).(Block no.   2: .r.r..r..).(Block no.   2: processing partial block data... ok.).(Block no.   2: processing partial signature data... ok.).(Block no.   2: writing block signature to file... ok.).(Block no.   2: Warning: all final tree hashes are missing.).(Block no.   3: processing block header... ok.).(Block no.   3: .r.r..r..).(Block no.   3: processing partial block data... ok.).(Block no.   3: processing partial signature data... ok.).(Block no.   3: writing block signature to file... ok.).(Block no.   3: Warning: all final tree hashes are missing.).(Block no.   4: processing block header... ok.).(Block no.   4: .Mr..).(Block no.   4: processing partial block data... ok.).(Block no.   4: processing partial signature data... ok.).(Block no.   4: writing block signature to file... ok.).(Block no.   4: all final tree hashes are present.).(Finalizing log signature... ok.)..(Warning: Some tree hashes are missing from the log signature file.) ]]	
	[ "$status" -eq 0 ]
}