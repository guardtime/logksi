#!/bin/bash

export KSI_CONF=test/test.cfg


#@test "extend CMD test: try to extend signature from stdin and from command line simultaneously" {
#	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -d --sig-from-stdin
#	[ "$status" -eq 3 ]
#	[[ "$output" =~ "Maybe you want to: Extend, from file, to the earliest available publication. --input -X -P" ]]
#	[[ "$output" =~ "Maybe you want to: Extend, from standard input, to the earliest available publication. --sig-from-stdin -X -P" ]]
#	[[ "$output" =~ "Maybe you want to: Extend, from file, to time specified in publications string. --input -X -P --pub-str" ]]
#}

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

@test "sign CMD test: try to use invalid PDU version" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig --aggr-pdu-v 1v --aggr-pdu-v 2v --aggr-pdu-v v3
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Invalid version).*(Parameter.*CMD.*aggr-pdu-v).*(1v) ]]
	[[ "$output" =~ (Invalid version).*(Parameter.*CMD.*aggr-pdu-v).*(2v) ]]
	[[ "$output" =~ (Invalid version).*(Parameter.*CMD.*aggr-pdu-v).*(v3) ]]
}



