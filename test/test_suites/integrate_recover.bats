#!/bin/bash

export KSI_CONF=test/test.cfg

mkdir -p test/out/integrate-recover

@test "recover-1: integrate blocks.dat that has last block corrupted, recovery is possible" {
	run src/logksi integrate test/resource/recover_logsig_parts/logfile test/resource/recover_logsig_parts/recover-last-block-tlv-corrupted.logsig.parts -o test/out/integrate-recover/recovered-1.logsig --out-log test/out/integrate-recover/recovered-1 -d --force-overwrite --recover
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Integrating... failed.).(Checking recoverability... ok.).(Removing corrupted data from log signature... ok.).(Copying valid log lines into recovered log file... ok.).(It was possible to recover 2 blocks .lines 1 . 6..).(Recovered log signature saved to \'test\/out\/integrate-recover\/recovered-1.logsig\').(Recovered Log file saved to \'test\/out\/integrate-recover\/recovered-1\') ]]
	[[ "$output" =~ "Error: Block no. 3: unable to parse block signature as TLV element" ]]
}

@test "recover-1: verify" {
	run src/logksi verify test/out/integrate-recover/recovered-1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Count of blocks).*(2).*(Count of record hashes).*(6).*(Input hash).*(SHA-512:7f3dea.*ee3141).*(Output hash).*(SHA-512:9c1ea0.*42e444) ]]
}

@test "recover-2: integrate blocks.dat that has second block corrupted, recovery is possible" {
	run src/logksi integrate test/resource/recover_logsig_parts/logfile test/resource/recover_logsig_parts/recover-second-block-tlv-corrupted.logsig.parts -o test/out/integrate-recover/recovered-2.logsig --out-log test/out/integrate-recover/recovered-2 -d --force-overwrite --recover
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Integrating... failed.).(Checking recoverability... ok.).(Removing corrupted data from log signature... ok.).(Copying valid log lines into recovered log file... ok.).(It was possible to recover 1 blocks .lines 1 . 3..).(Recovered log signature saved to \'test\/out\/integrate-recover\/recovered-2.logsig\').(Recovered Log file saved to \'test\/out\/integrate-recover\/recovered-2\') ]]
	[[ "$output" =~ "Error: Output hash of block 1 differs from input hash of block 2." ]]
}

@test "recover-2: verify" {
	run src/logksi verify test/out/integrate-recover/recovered-2 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Count of blocks).*(1).*(Count of record hashes).*(3).*(Input hash).*(SHA-512:7f3dea.*ee3141).*(Output hash).*(SHA-512:20cfea.*88944a) ]]
}

@test "recover-3: integrate blocks.dat that has first block corrupted, recovery is impossible" {
	run src/logksi integrate test/resource/recover_logsig_parts/logfile test/resource/recover_logsig_parts/recover-first-block-tlv-corrupted.logsig.parts -o test/out/integrate-recover/not-existing.logsig --out-log test/out/integrate-recover/not-existing --force-overwrite --recover
	[ "$status" -eq 4 ]
	[[ "$output" =~ (Error).*(Unable to recover any blocks as the first block is already corrupted).*(Error).*(Block no. 1: missing random seed in block header) ]]
	run test -e test/out/integrate-recover/not-existing
	[ "$status" -ne 0 ]
	run test -e test/out/integrate-recover/not-existing.logsig
	[ "$status" -ne 0 ]
}

@test "recover-4: integrate block-signatures.dat that has first block corrupted, recovery is impossible" {
	run src/logksi integrate test/resource/recover_logsig_parts/logfile test/resource/recover_logsig_parts/recover-first-block-sig-tlv-corrupted.logsig.parts -o test/out/integrate-recover/not-existing.logsig --out-log test/out/integrate-recover/not-existing --force-overwrite --recover
	[ "$status" -eq 4 ]
	[[ "$output" =~ (Error).*(Unable to recover any blocks as the first block is already corrupted).*(Error).*(Block no. 1: unable to parse KSI signature in signatures file).*(Error).*(Data size mismatch) ]]
	run test -e test/out/integrate-recover/not-existing
	[ "$status" -ne 0 ]
	run test -e test/out/integrate-recover/not-existing.logsig
	[ "$status" -ne 0 ]
}

@test "recover-5: integrate block-signatures.dat that has second block corrupted, recovery is possible" {
	run src/logksi integrate test/resource/recover_logsig_parts/logfile test/resource/recover_logsig_parts/recover-second-block-sig-tlv-corrupted.logsig.parts -o test/out/integrate-recover/recovered-5.logsig --out-log test/out/integrate-recover/recovered-5 --force-overwrite --recover -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Integrating... failed.).(Checking recoverability... ok.).(Removing corrupted data from log signature... ok.).(Copying valid log lines into recovered log file... ok.).(It was possible to recover 1 blocks .lines 1 . 3..).(Recovered log signature saved to \'test\/out\/integrate-recover\/recovered-5.logsig\').(Recovered Log file saved to \'test\/out\/integrate-recover\/recovered-5\') ]]
	[[ "$output" =~ "Error: Failed to read nested TLV" ]]
}

@test "recover-5: verify" {
	run src/logksi verify test/out/integrate-recover/recovered-5 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Count of blocks).*(1).*(Count of record hashes).*(3).*(Input hash).*(SHA-512:7f3dea.*ee3141).*(Output hash).*(SHA-512:20cfea.*88944a) ]]
}

@test "recover-6: integrate block-signatures.dat that has second block corrupted, recovery is possible" {
	run src/logksi integrate test/resource/recover_logsig_parts/logfile test/resource/recover_logsig_parts/recover-last-block-sig-tlv-corrupted.logsig.parts -o test/out/integrate-recover/recovered-6.logsig --out-log test/out/integrate-recover/recovered-6 --force-overwrite --recover -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Integrating... failed.).(Checking recoverability... ok.).(Removing corrupted data from log signature... ok.).(Copying valid log lines into recovered log file... ok.).(It was possible to recover 3 blocks .lines 1 . 9..).(Recovered log signature saved to \'test\/out\/integrate-recover\/recovered-6.logsig\').(Recovered Log file saved to \'test\/out\/integrate-recover\/recovered-6\') ]]
	[[ "$output" =~ "Error: Failed to read nested TLV" ]]
}

@test "recover-6: verify" {
	run src/logksi verify test/out/integrate-recover/recovered-6 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Count of blocks).*(3).*(Count of record hashes).*(9).*(Input hash).*(SHA-512:7f3dea.*ee3141).*(Output hash).*(SHA-512:1dfeae.*43e987) ]]
}

@test "recover-7: integrate block-signatures.dat that has one extra log record in the first block, recovery is impossible" {
	run src/logksi integrate test/resource/logfiles/signed test/resource/logsignatures/too-many-record-hashes.logsig.parts/ -o test/out/integrate-recover/not-existing.logsig --out-log test/out/integrate-recover/not-existing -d --force-overwrite --recover
	[ "$status" -eq 6 ]
	[[ "$output" =~  (Error).*(Unable to recover any blocks as the first block is already corrupted).*(Error).*(Block no. 1. there are too many record hashes for this block).*(Error).*(Block no. 1: expected 2 record hashes, but found 3) ]]
	run test -e test/out/integrate-recover/not-existing
	[ "$status" -ne 0 ]
	run test -e test/out/integrate-recover/not-existing.logsig
	[ "$status" -ne 0 ]
}

@test "recover-8: integrate block-signatures.dat that has too few log record in the first block, recovery is impossible" {
	run src/logksi integrate test/resource/logfiles/signed test/resource/logsignatures/too-few-record-hashes.logsig.parts/ -o test/out/integrate-recover/not-existing.logsig --out-log test/out/integrate-recover/not-existing -d --force-overwrite --recover
	[ "$status" -eq 6 ]
	[[ "$output" =~  (Error).*(Unable to recover any blocks as the first block is already corrupted).*(Error).*(Block no. 1: missing record hash for logline no. 4).*(Error).*(Block no. 1: there are too few record hashes for this block).*(Error).*(Block no. 1: expected 5 record hashes, but found 3) ]]
	run test -e test/out/integrate-recover/not-existing
	[ "$status" -ne 0 ]
	run test -e test/out/integrate-recover/not-existing.logsig
	[ "$status" -ne 0 ]
}

@test "recover-9: integrate and recover without matching log file" {
	run src/logksi integrate test/resource/recover_logsig_parts/recover-last-block-tlv-corrupted -o test/out/integrate-recover/not-existing.logsig --out-log test/out/integrate-recover/not-existing-1 -d --force-overwrite --recover
	[ "$status" -eq 4 ]
	[[ "$output" =~  (Integrating... failed.).(Checking recoverability... ok.).(Removing corrupted data from log signature... ok.).(Copying valid log lines into recovered log file... failed.) ]]
	[[ "$output" =~  (Error).*( Unable to open input logfile).*(Error).*(Block no. 3: unable to parse block signature as TLV element) ]]
	run test -e test/out/integrate-recover/not-existing
	[ "$status" -ne 0 ]
	run test -e test/out/integrate-recover/not-existing.logsig
	[ "$status" -ne 0 ]
}

@test "recover-10: generate output file names (with --force-overwrite)" {
	run cp test/resource/recover_logsig_parts/logfile test/out/integrate-recover/recover-file-name-gen-1
	run cp -r test/resource/recover_logsig_parts/recover-last-block-tlv-corrupted.logsig.parts test/out/integrate-recover/recover-file-name-gen-1.logsig.parts
	run src/logksi integrate test/out/integrate-recover/recover-file-name-gen-1 -d --force-overwrite --recover
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Integrating... failed.).(Checking recoverability... ok.).(Removing corrupted data from log signature... ok.).(Copying valid log lines into recovered log file... ok.).(It was possible to recover 2 blocks .lines 1 . 6..).(Recovered log signature saved to \'test\/out\/integrate-recover\/recover-file-name-gen-1.recovered.logsig\').(Recovered Log file saved to \'test\/out\/integrate-recover\/recover-file-name-gen-1.recovered\') ]]
	[[ "$output" =~ "Error: Block no. 3: unable to parse block signature as TLV element" ]]
}

@test "recover-10: verify" {
	run src/logksi verify test/out/integrate-recover/recover-file-name-gen-1.recovered -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Count of blocks).*(2).*(Count of record hashes).*(6).*(Input hash).*(SHA-512:7f3dea.*ee3141).*(Output hash).*(SHA-512:9c1ea0.*42e444) ]]
}

@test "recover-11: try overwriting of files with automatically generate file names 1 (without --force-overwrite)" {
	run src/logksi integrate test/out/integrate-recover/recover-file-name-gen-1 -d --recover
	[ "$status" -eq 9 ]
	[[ "$output" =~ "Error: Overwriting of existing log signature file" ]]
}

@test "recover-11: try overwriting of files with automatically generate file names 2 (without --force-overwrite)" {
	run src/logksi integrate test/out/integrate-recover/recover-file-name-gen-1 -d --recover -o test/out/integrate-recover/not-existing.logsig
	[ "$status" -eq 9 ]
	[[ "$output" =~ "Error: Overwriting of existing log file test/out/integrate-recover/recover-file-name-gen-1.recovered not allowed." ]]
}

@test "recover-12: generate output file log signature name, but specify output log file (with --force-overwrite)" {
	run cp test/resource/recover_logsig_parts/logfile test/out/integrate-recover/recover-file-name-gen-2
	run cp -r test/resource/recover_logsig_parts/recover-last-block-tlv-corrupted.logsig.parts test/out/integrate-recover/recover-file-name-gen-2.logsig.parts
	run src/logksi integrate test/out/integrate-recover/recover-file-name-gen-2 --out-log test/out/integrate-recover/explicitly-specified-recovered-logfile -d --force-overwrite --recover
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Integrating... failed.).(Checking recoverability... ok.).(Removing corrupted data from log signature... ok.).(Copying valid log lines into recovered log file... ok.).(It was possible to recover 2 blocks .lines 1 . 6..).(Recovered log signature saved to \'test\/out\/integrate-recover\/recover-file-name-gen-2.recovered.logsig\').(Recovered Log file saved to \'test\/out\/integrate-recover\/explicitly-specified-recovered-logfile\') ]]
	[[ "$output" =~ "Error: Block no. 3: unable to parse block signature as TLV element" ]]
}

@test "recover-12: verify" {
	run src/logksi verify test/out/integrate-recover/explicitly-specified-recovered-logfile test/out/integrate-recover/recover-file-name-gen-2.recovered.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Count of blocks).*(2).*(Count of record hashes).*(6).*(Input hash).*(SHA-512:7f3dea.*ee3141).*(Output hash).*(SHA-512:9c1ea0.*42e444) ]]
}

@test "recover-13: generate output file log signature name, but specify output log signature file (with --force-overwrite)" {
	run cp test/resource/recover_logsig_parts/logfile test/out/integrate-recover/recover-file-name-gen-3
	run cp -r test/resource/recover_logsig_parts/recover-last-block-tlv-corrupted.logsig.parts test/out/integrate-recover/recover-file-name-gen-3.logsig.parts
	run src/logksi integrate test/out/integrate-recover/recover-file-name-gen-3 -o test/out/integrate-recover/explicitly-specified-recovered-log-signature-file -d --force-overwrite --recover
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Integrating... failed.).(Checking recoverability... ok.).(Removing corrupted data from log signature... ok.).(Copying valid log lines into recovered log file... ok.).(It was possible to recover 2 blocks .lines 1 . 6..).(Recovered log signature saved to \'test\/out\/integrate-recover\/explicitly-specified-recovered-log-signature-file\').(Recovered Log file saved to \'test\/out\/integrate-recover\/recover-file-name-gen-3.recovered\') ]]
	[[ "$output" =~ "Error: Block no. 3: unable to parse block signature as TLV element" ]]
}

@test "recover-13: verify" {
	run src/logksi verify test/out/integrate-recover/recover-file-name-gen-3.recovered test/out/integrate-recover/explicitly-specified-recovered-log-signature-file -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Count of blocks).*(2).*(Count of record hashes).*(6).*(Input hash).*(SHA-512:7f3dea.*ee3141).*(Output hash).*(SHA-512:9c1ea0.*42e444) ]]
}