#!/bin/bash

export KSI_CONF=test/test.cfg


# block_count, rec_hash_count, meta_rec_count, ih, oh
f_summary_of_logfile_short () {
	 echo "(Summary of logfile:).( . Count of blocks:             $1).( . Count of record hashes:      $2).( . Count of meta-records:       $3).( . Input hash:  $4).( . Output hash: $5)"
}

@test "recreate log signature: signed" {
	run src/logksi create test/resource/logs_and_signatures/signed -o test/out/signed_create.logsig -dd --blk-size 3 --seed test/resource/random/seed_signed_log -H SHA2-512 --input-hash SHA2-512:7f3dea12fa4d448860f0a954b0d31f450062d5f47e4eca163ffdda2961f32908c5dd974588c559bf2761f30000ee9e41a5909eedde5ef4820480b05ae5ee3141
	[ "$status" -eq 0 ]
	[[ "$output" =~ `f_summary_of_logfile_short 4 9 1 "SHA-512:7f3dea.*ee3141" "SHA-512:f7f5b4.*b2b596"` ]]
	run ./src/logksi verify test/resource/logs_and_signatures/signed test/out/signed_create.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok." ]]
	[[ "$output" =~ `f_summary_of_logfile_short 4 9 1 "SHA-512:7f3dea.*ee3141" "SHA-512:f7f5b4.*b2b596"` ]]
}
