#!/bin/bash

export KSI_CONF=test/test.cfg

@test "sign CMD test: try to use invalid stdout combination" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o - -d --log -
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (-o -, --log -)." ]]
}

@test "sign CMD test: try to retrieve signature from file and stdin simultaneously" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned --sig-from-stdin -o test/out/dummy.ksig
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Maybe you want to: Sign data from file. --input -S" ]]
	[[ "$output" =~ "Maybe you want to: Sign data from standard input. --sig-from-stdin -S" ]]
}

@test "sign CMD test: try to use invalid HMAC hash algorithm" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig --aggr-hmac-alg dummy
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Algorithm name is incorrect).*(Parameter.*CMD.*aggr-hmac-alg).*(dummy) ]]
}

@test "sign CMD test: try to sign not existing log signature file" {
	run src/logksi sign -o test/out/dummy.ksig dummy.not.existing
	[ "$status" -eq 9 ]
	[[ "$output" =~  (Error: Could not open input signature file).*(dummy.not.existing.logsig) ]]
}