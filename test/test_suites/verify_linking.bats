#!/bin/bash

export KSI_CONF=test/test.cfg

echo SHA-512:dd4e870e7e0c998f160688b97c7bdeef3d6d01b1c5f02db117018058ad51996777ae3dc8008d70b3e11c172b0049e8158571cea1b8a439593b67c41ebbe2b137 > test/out/input-hash.txt

@test "verify log_repaired.logsig with input hash from command line" {
	run ./src/logksi verify test/resource/logs_and_signatures/log_repaired -ddd --input-hash SHA-512:dd4e870e7e0c998f160688b97c7bdeef3d6d01b1c5f02db117018058ad51996777ae3dc8008d70b3e11c172b0049e8158571cea1b8a439593b67c41ebbe2b137 --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no).*(1).*(verifying inter-linking input hash... ok).*(Finalizing log signature... ok) ]]
}

@test "verify log_repaired.logsig with input hash from file" {
	run ./src/logksi verify test/resource/logs_and_signatures/log_repaired -ddd --input-hash test/out/input-hash.txt --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no).*(1).*(verifying inter-linking input hash... ok).*(Finalizing log signature... ok) ]]
}

@test "verify log_repaired.logsig output last leaf hash to file" {
	run ./src/logksi verify test/resource/logs_and_signatures/log_repaired -ddd --output-hash test/out/output-hash.txt --ignore-desc-block-time
	[ "$status" -eq 0 ]
	run cat test/out/output-hash.txt
	[[ "$output" =~ (Log file).*(test\/resource\/logs_and_signatures\/log_repaired).*(Last leaf from previous log signature).*(test\/resource\/logs_and_signatures\/log_repaired.logsig).*(SHA-512:7f5a178f581de2aed0d36739f908733643b316aac8bed0c9f89c040ad1d1e601ae8fd1ae1e177c2cdf9ebf59a2f43df00614893723d5019b6326b225bbcd7827) ]]
}

@test "verify log_repaired.logsig output last leaf hash to stdout" {
	run ./src/logksi verify test/resource/logs_and_signatures/log_repaired -ddd --output-hash - --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Log file).*(test\/resource\/logs_and_signatures\/log_repaired).*(Last leaf from previous log signature).*(test\/resource\/logs_and_signatures\/log_repaired.logsig).*(SHA-512:7f5a178f581de2aed0d36739f908733643b316aac8bed0c9f89c040ad1d1e601ae8fd1ae1e177c2cdf9ebf59a2f43df00614893723d5019b6326b225bbcd7827) ]]
}

@test "verify log_repaired.logsig with wrong input hash" {
	run ./src/logksi verify test/resource/logs_and_signatures/log_repaired -ddd --input-hash SHA-512:dd4e870e7e0c998f160688b97c7bdeef3d6d01b1c5f02db117018058ad51996777ae3dc8008d70b3e11c172b0049e8158571cea1b8a439593b67c41ebbe2b138
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Block no).*(1).*(verifying inter-linking input hash... failed) ]]
	[[ "$output" =~ .*(Error).*(Block no).*(1).*(The last leaf from the previous block).*(from --input-hash).*(does not match with the current first block).*(log_repaired).* ]]
}

@test "try to write excerpt signature output hash to stdout. It must fail" {
	run ./src/logksi verify test/out/extract.base.10.excerpt --output-hash -
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: --output-hash does not work with excerpt signature file" ]]
}

@test "verify inter-linking of two sequential log signatures by saving temporary hash imprint to file" {
	run ./src/logksi verify test/resource/interlink/ok-testlog-interlink-1 -ddd --output-hash test/out/ok-testlog-interlink-1-output-hash
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok" ]]

	run ./src/logksi verify test/resource/interlink/ok-testlog-interlink-2 -ddd --input-hash test/out/ok-testlog-interlink-1-output-hash
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no).*(1).*(verifying inter-linking input hash... ok).*(Finalizing log signature... ok) ]]
}

@test "verify inter-linking of two sequential log signatures by passing previous leaf hash imprint value via stdout" {
	run bash -c "./src/logksi verify test/resource/interlink/ok-testlog-interlink-1 -ddd --output-hash - | ./src/logksi verify test/resource/interlink/ok-testlog-interlink-2 -ddd --input-hash -"
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Block no).*(1).*(verifying inter-linking input hash... ok).*(Finalizing log signature... ok) ]]
}

@test "verify inter-linking of two NOT matching log signatures by passing previous leaf hash imprint value via stdout" {
	run bash -c "./src/logksi verify test/resource/logs_and_signatures/log_repaired -ddd --ignore-desc-block-time --output-hash - | ./src/logksi verify test/resource/interlink/ok-testlog-interlink-2 -ddd --input-hash -"
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Block no).*(1).*(verifying inter-linking input hash... failed) ]]
	[[ "$output" =~ .*(Error).*(Block no).*(1).*(The last leaf from the previous block).*(from --input-hash -).*(does not match with the current first block).*(interlink/ok-testlog-interlink-2).* ]]
}

@test "verify inter-linking automatically by giving 2 log files after --" {
	run src/logksi verify -ddd -- test/resource/interlink/ok-testlog-interlink-1 test/resource/interlink/ok-testlog-interlink-2
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Log file.*ok-testlog-interlink-1).*(Finalizing log signature... ok).*(Log file.*ok-testlog-interlink-2).*(verifying inter-linking input hash... ok).*(Finalizing log signature... ok) ]]
}

@test "verify inter-linking automatically by giving 2 log files after --. Check --input-hash" {
	run src/logksi verify -ddd --input-hash sha2-256:a558295ae8da8cf4e2b13a34289d2a17676821f14e0792ac1098d27d9bea5fc9 -- test/resource/interlink/ok-testlog-interlink-1 test/resource/interlink/ok-testlog-interlink-2
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Log file.*ok-testlog-interlink-1).*(Block no).*(1).*(verifying inter-linking input hash... ok).*(Finalizing log signature... ok).*(Log file.*ok-testlog-interlink-2).*(Block no).*(1).*(verifying inter-linking input hash... ok).*(Finalizing log signature... ok) ]]
}

@test "verify inter-linking automatically by giving 2 log files after --. Check output hash (must match to last log and log signature)" {
	run src/logksi verify -ddd --output-hash - -- test/resource/interlink/ok-testlog-interlink-1 test/resource/interlink/ok-testlog-interlink-2
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Log file.*ok-testlog-interlink-1).*(Finalizing log signature... ok).*(Log file.*ok-testlog-interlink-2).*(Block no).*(1).*(verifying inter-linking input hash... ok).*(Finalizing log signature... ok) ]]
	[[ "$output" =~ "SHA-256:601697d09896bf2c537a913c77c213630e9bd9b034b328a5c93e0d2b2e35dc7d" ]]
}

@test "verify inter-linking automatically by giving multiple log files with wildcard after --" {
	run bash -c "./src/logksi verify -ddd -- test/resource/interlink/ok-testlog-interlink-[12]"
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Log file.*ok-testlog-interlink-1).*(Finalizing log signature... ok).*(Log file.*ok-testlog-interlink-2).*(Block no).*(1).*(verifying inter-linking input hash... ok).*(Finalizing log signature... ok) ]]
}

@test "verify inter-linking automatically by giving 2 log files in WRONG ORDER after --" {
	run src/logksi verify -ddd -- test/resource/interlink/ok-testlog-interlink-2 test/resource/interlink/ok-testlog-interlink-1
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Log file.*ok-testlog-interlink-2).*(Finalizing log signature... ok).*(Log file.*ok-testlog-interlink-1).*(Block no).*(1).*(verifying inter-linking input hash... failed) ]]
	[[ "$output" =~ .*(Error).*(Block no).*(1).*(The last leaf from the previous block).*(/ok-testlog-interlink-2).*(does not match with the current first block).*(/ok-testlog-interlink-1).*.*(Expecting).*(SHA-256:601697d09896bf2c537a913c77c213630e9bd9b034b328a5c93e0d2b2e35dc7d).*(but got).*(SHA-256:a558295ae8da8cf4e2b13a34289d2a17676821f14e0792ac1098d27d9bea5fc9) ]]
}

@test "verify inter-linking where first log is resigned" {
	run src/logksi verify -ddd -- test/resource/interlink/ok-testlog-interlink-resigned-1 test/resource/interlink/ok-testlog-interlink-2
	[ "$status" -eq 6 ]
	[[ "$output" =~ .*(Error).*(Last block).*(1540301997).*(from file).*(ok-testlog-interlink-resigned-1).*(is more recent than).*(first block).*(1539771503).*(from file).*(ok-testlog-interlink-2) ]]
}

@test "verify inter-linking and warn when consecutive blocks have same signing time" {
	run src/logksi verify --warn-same-block-time -- test/resource/interlink/ok-testlog-interlink-same-sig-time-[12]
	[ "$status" -eq 0 ]
	[[ "$output" =~ .*(Warning).*(Last block).*(from file).*(ok-testlog-interlink-same-sig-time-1).*(and).*(first block).*(from file).*(ok-testlog-interlink-same-sig-time-2).*(has same signing time).*(1540454662).* ]]
}
