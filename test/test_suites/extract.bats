#!/bin/bash

export KSI_CONF=test/test.cfg

@test "extract record 1" {
	run ./src/logksi extract test/out/all_hashes -r 1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify record 1" {
	run ./src/logksi verify test/out/all_hashes.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "diff excerpt of record 1" {
	run diff test/out/all_hashes.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "verify record 1 modified" {
	run ./src/logksi verify test/resource/logfiles/r1_modified.part test/out/all_hashes.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: record hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify record 1 too long" {
	run ./src/logksi verify test/resource/logfiles/r1_too_long.part test/out/all_hashes.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: end of log file contains unexpected records." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong record hash" {
	run ./src/logksi verify test/out/all_hashes.part test/resource/logsignatures/proof_wrong_record_hash.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: record hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong sibling hash 1" {
	run ./src/logksi verify test/out/all_hashes.part test/resource/logsignatures/proof_wrong_sibling_hash_1.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong sibling hash 3" {
	run ./src/logksi verify test/out/all_hashes.part test/resource/logsignatures/proof_wrong_sibling_hash_3.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong level correction 1" {
	run ./src/logksi verify test/out/all_hashes.part test/resource/logsignatures/proof_wrong_level_correction_1.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong level correction 2" {
	run ./src/logksi verify test/out/all_hashes.part test/resource/logsignatures/proof_wrong_level_correction_2.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong link direction" {
	run ./src/logksi verify test/out/all_hashes.part test/resource/logsignatures/proof_wrong_link_direction.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "extract last (meta)record" {
	run ./src/logksi extract test/out/all_hashes -r 1430 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify last (meta)record" {
	run ./src/logksi verify test/out/all_hashes.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "diff empty excerpt of last (meta)record" {
	run diff test/out/all_hashes.part test/resource/logfiles/r1430.part 
	[ "$status" -eq 0 ]
}

@test "extract last (log)record" {
	run ./src/logksi extract test/out/all_hashes -r 1429 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify last (log)record" {
	run ./src/logksi verify test/out/all_hashes.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "diff excerpt of last (log)record" {
	run diff test/out/all_hashes.part test/resource/logfiles/r1429.part 
	[ "$status" -eq 0 ]
}

@test "extract range over three blocks" {
	run ./src/logksi extract test/out/all_hashes -r 3-7 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify range over three blocks" {
	run ./src/logksi verify test/out/all_hashes.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "diff excerpt with range over three blocks" {
	run diff test/out/all_hashes.part test/resource/logfiles/r3-7.part 
	[ "$status" -eq 0 ]
}

