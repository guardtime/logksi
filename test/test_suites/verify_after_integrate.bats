#!/bin/bash

export KSI_CONF=test/test.cfg

cp -r test/resource/logfiles/signed test/out

@test "verify integrated signed.logsig" {
	run ./src/logksi verify test/out/signed -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify integrated signed_all_final_hashes.logsig" {
	run ./src/logksi verify test/out/signed test/out/signed_all_final_hashes.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify integrated overwritten.logsig" {
	run ./src/logksi verify test/out/signed test/out/overwritten.logsig -ddd
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

cp -r test/resource/logfiles/unsigned test/out

@test "try verifying integrated unsigned.logsig" {
	run ./src/logksi verify test/out/unsigned -ddd
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Block no.   1: Warning: all final tree hashes are missing." ]]
	[[ "$output" =~ "Block no.   5: Error: Block is unsigned!" ]]
	[[ "$output" =~ "Error: Block no. 5 is unsigned and missing KSI signature in block signature." ]]
	[[ "$output" =~ "Error: Verification inconclusive and was stopped." ]]
	[[ "$output" =~ (Suggestion: Make sure that block signature is actually the original output).*(use logksi sign to sign unsigned blocks) ]]
}

@test "try verifying integrated unsigned_all_final_hashes.logsig" {
	run ./src/logksi verify test/out/unsigned test/out/unsigned_all_final_hashes.logsig -ddd
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Block no.   1: all final tree hashes are present." ]]
	[[ "$output" =~ "Block no.   5: Error: Block is unsigned!" ]]
	[[ "$output" =~ "Error: Block no. 5 is unsigned and missing KSI signature in block signature." ]]
	[[ "$output" =~ "Error: Verification inconclusive and was stopped." ]]
	[[ "$output" =~ (Suggestion: Make sure that block signature is actually the original output).*(use logksi sign to sign unsigned blocks) ]]
}
