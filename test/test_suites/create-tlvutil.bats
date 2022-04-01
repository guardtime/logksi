#!/bin/bash

export KSI_CONF=test/test.cfg

mkdir -p test/out/create_tlv_util

@test "create tlvutil: check hash algorithm, seed (default size) and input hash components" {
	run src/logksi create test/resource/logs_and_signatures/signed -o test/out/create_tlv_util/sha512.logsig -dd --blk-size 3 --seed test/resource/random/seed_signed_log -H SHA2-512 --input-hash SHA2-512:7f3dea12fa4d448860f0a954b0d31f450062d5f47e4eca163ffdda2961f32908c5dd974588c559bf2761f30000ee9e41a5909eedde5ef4820480b05ae5ee3141
	[ "$status" -eq 0 ]

	run gttlvgrep -H 8 901.01 test/out/create_tlv_util/sha512.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ 05.05.05.05 ]]

	run gttlvgrep -H 8 901.02 test/out/create_tlv_util/sha512.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ (55448916bff77a86005803af044346a91a0563928997c160e7b9df499a0b14573ff03b77acecaf2c894772d6df2c520e39c12379cd79560a9e0e2938cccd3156).(f9b6e1.*5a0443).(617d02.*369427).(b7f8d7.*63c0b6) ]]

	run gttlvgrep -H 8 901.03 test/out/create_tlv_util/sha512.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ (057f3d.*ee3141).(0520cf.*88944a).(059c1e.*42e444).(051dfe.*43e987) ]]
}

@test "create tlvutil: check random seed smaller than default" {
	run src/logksi create test/resource/logs_and_signatures/signed -o test/out/create_tlv_util/sha512-small-seed.logsig -dd --blk-size 3 --seed test/resource/random/seed_signed_log --seed-len 4
	[ "$status" -eq 0 ]

	run gttlvgrep -H 8 901.02 test/out/create_tlv_util/sha512-small-seed.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ 55448916.bff77a86.005803af.044346a9 ]]
}

@test "create tlvutil: check random seed larger than default" {
	run src/logksi create test/resource/logs_and_signatures/signed -o test/out/create_tlv_util/sha512-large-seed.logsig -dd --blk-size 6 --seed test/resource/random/seed_signed_log --seed-len 128
	[ "$status" -eq 0 ]

	run gttlvgrep -H 8 901.02 test/out/create_tlv_util/sha512-large-seed.logsig
	[ "$status" -eq 0 ]
	[[ "$output" =~ 55448916bff77a86005803af044346a91a0563928997c160e7b9df499a0b14573ff03b77acecaf2c894772d6df2c520e39c12379cd79560a9e0e2938cccd3156f9b6e1453b0847d3e25d5398deda861f5b56dece4c194a1d02359907693a1b9badddf9fcbb8ec02767379f6e9647c498a19c199917ca3c0fc776cf87395a0443.617d02de955eb89c9137cd7f2ab6eb20f3f1868d3cf5a07e4e345dcf307e945cc30a86e2de69e7f827bfac8f4aa42a37612d1973d9a52897fb0ea379fd369427b7f8d7e8db818ce6d40a55796a28b377f69461682eceab2ab06151a3e4cac7347d2d726b23b0b466af2587f822b5297227b1752f479a8cbc80f356a50863c0b6 ]]
}