#!/bin/bash

mkdir -p test/out/create_tlv_util

@test "create tlvutil: check hash algorithm, seed and input hash components" {
	run src/logksi create test/resource/logs_and_signatures/signed -o test/out/create_tlv_util/sha512.logsig -dd --blk-size 3 --seed test/resource/random/seed_signed_log -H SHA2-512 --input-hash SHA2-512:7f3dea12fa4d448860f0a954b0d31f450062d5f47e4eca163ffdda2961f32908c5dd974588c559bf2761f30000ee9e41a5909eedde5ef4820480b05ae5ee3141
	[ "$status" -eq 0 ]

	run gttlvgrep -H 8 901.01 test/out/create_tlv_util/sha512.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ 05.05.05.05 ]]

	run gttlvgrep -H 8 901.02 test/out/create_tlv_util/sha512.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ (554489.*cd3156).(f9b6e1.*5a0443).(617d02.*369427).(b7f8d7.*63c0b6) ]]

	run gttlvgrep -H 8 901.03 test/out/create_tlv_util/sha512.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ (057f3d.*ee3141).(0520cf.*88944a).(059c1e.*42e444).(051dfe.*43e987) ]]

}
