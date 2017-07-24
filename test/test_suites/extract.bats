#!/bin/bash

export KSI_CONF=test/test.cfg

cp -r test/resource/logsignatures/extract.base.logsig test/out
cp -r test/resource/logfiles/extract.base test/out
cp -r test/out/extract.base.logsig test/out/extract.base.1.logsig
cp -r test/out/extract.base test/out/extract.base.1
cp -r test/out/extract.base.logsig test/out/extract.base.2.logsig
cp -r test/out/extract.base test/out/extract.base.2
cp -r test/out/extract.base.logsig test/out/extract.base.3.logsig
cp -r test/out/extract.base test/out/extract.base.3
cp -r test/out/extract.base.logsig test/out/extract.base.4.logsig
cp -r test/out/extract.base test/out/extract.base.4
cp -r test/out/extract.base.logsig test/out/extract.base.5.logsig
cp -r test/out/extract.base test/out/extract.base.5
cp -r test/out/extract.base.logsig test/out/extract.base.6.logsig
cp -r test/out/extract.base test/out/extract.base.6
cp -r test/out/extract.base.logsig test/out/extract.base.7.logsig
cp -r test/out/extract.base test/out/extract.base.7
cp -r test/out/extract.base.logsig test/out/extract.base.8.logsig
cp -r test/out/extract.base test/out/extract.base.8
cp -r test/out/extract.base.logsig test/out/extract.base.9.logsig
cp -r test/out/extract.base test/out/extract.base.9
cp -r test/out/extract.base.logsig test/out/extract.base.10.logsig
cp -r test/out/extract.base test/out/extract.base.10

@test "extract record 1" {
	run ./src/logksi extract test/out/extract.base -r 1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.base -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.base.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, specify log records file" {
	run ./src/logksi extract test/out/extract.base.1 --out-log test/out/extract.user.1.part -r 1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.user.1.part test/out/extract.base.1.part.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.user.1.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, specify integrity proof file" {
	run ./src/logksi extract test/out/extract.base.2 --out-proof test/out/extract.user.2.part.logsig -r 1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.base.2.part test/out/extract.user.2.part.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.base.2.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, specify both output files" {
	run ./src/logksi extract test/out/extract.base.3 --out-log test/out/extract.user.3.part --out-proof test/out/extract.user.3.part.logsig -r 1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.user.3.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.user.3.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, specify output" {
	run ./src/logksi extract test/out/extract.base.4 -o test/out/extract.user.4 -r 1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.user.4.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.user.4.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, specify output, override log records" {
	run ./src/logksi extract test/out/extract.base.5 -o test/out/extract.user.5 --out-log test/out/extract.user.5.1 -r 1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.user.5.1 test/out/extract.user.5.part.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.user.5.1 test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, specify output, override integrity proof" {
	run ./src/logksi extract test/out/extract.base.6 -o test/out/extract.user.6 --out-proof test/out/extract.user.6.1 -r 1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.user.6.part test/out/extract.user.6.1 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.user.6.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, redirect log records to stdout" {
	run bash -c "./src/logksi extract test/out/extract.base.7 --out-log - -r 1 -d > test/out/extract.user.7.stdout"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.user.7.stdout test/out/extract.base.7.part.logsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.user.7.stdout test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, redirect integrity proof to stdout" {
	run bash -c "./src/logksi extract test/out/extract.base.8 --out-proof - -r 1 -d > test/out/extract.user.8.stdout"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.base.8.part test/out/extract.user.8.stdout -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.base.8.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, attempt to redirect both outputs to stdout" {
	run bash -c "./src/logksi extract test/out/extract.base.8 --out-log - --out-proof - -r 1 -d"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: both output files cannot be redirected to stdout." ]]
	run bash -c "./src/logksi extract test/out/extract.base.8 -o - -r 1 -d"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: both output files cannot be redirected to stdout." ]]
}

@test "extract record 1, read log file from stdin" {
	run bash -c "cat test/out/extract.base.9 | ./src/logksi extract --log-from-stdin test/out/extract.base.9.logsig -o test/out/extract.user.9 -r 1 -d"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.user.9.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.user.9.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, read signature file from stdin" {
	run bash -c "cat test/out/extract.base.10.logsig | ./src/logksi extract test/out/extract.base.10 --sig-from-stdin -r 1 -d"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.base.10.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.base.10.part test/resource/logfiles/r1.part 
	[ "$status" -eq 0 ]
}

@test "extract record 1, attempt to read both files from stdin" {
	run ./src/logksi extract --log-from-stdin --sig-from-stdin -r 1 -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Maybe you want to:" ]]
}

@test "extract record 1, attempt to read one file from stdin without specifying the other input file" {
	run ./src/logksi extract --log-from-stdin -r 1 -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "You have to define flag(s) '--input'." ]]
	run ./src/logksi extract --sig-from-stdin -r 1 -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "You have to define flag(s) '--input'." ]]
}

@test "extract record 1, attemp to read log file from stdin without specifying the output file" {
	run ./src/logksi extract --log-from-stdin test/out/extract.base.10.logsig -r 1 -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: output log records file name must be specified if log file is read from stdin." ]]
	run ./src/logksi extract --log-from-stdin test/out/extract.base.10.logsig --out-log test/out/extract.user.10.part -r 1 -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: output integrity proof file name must be specified if log file is read from stdin." ]]
}

@test "verify record 1 modified" {
	run ./src/logksi verify test/resource/logfiles/r1_modified.part test/out/extract.base.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: record hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify record 1 too long" {
	run ./src/logksi verify test/resource/logfiles/r1_too_long.part test/out/extract.base.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: end of log file contains unexpected records." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong record hash" {
	run ./src/logksi verify test/out/extract.base.part test/resource/logsignatures/proof_wrong_record_hash.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: record hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong sibling hash 1" {
	run ./src/logksi verify test/out/extract.base.part test/resource/logsignatures/proof_wrong_sibling_hash_1.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong sibling hash 3" {
	run ./src/logksi verify test/out/extract.base.part test/resource/logsignatures/proof_wrong_sibling_hash_3.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong level correction 1" {
	run ./src/logksi verify test/out/extract.base.part test/resource/logsignatures/proof_wrong_level_correction_1.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong level correction 2" {
	run ./src/logksi verify test/out/extract.base.part test/resource/logsignatures/proof_wrong_level_correction_2.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "verify proof wrong link direction" {
	run ./src/logksi verify test/out/extract.base.part test/resource/logsignatures/proof_wrong_link_direction.part.logsig -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Block no.   1: root hashes not equal." ]]
	[[ "$output" =~ "Log signature verification failed." ]]
}

@test "extract last (meta)record" {
	run ./src/logksi extract test/out/extract.base -r 1430 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.base.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.base.part test/resource/logfiles/r1430.part 
	[ "$status" -eq 0 ]
}

@test "extract last (log)record" {
	run ./src/logksi extract test/out/extract.base -r 1429 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.base.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.base.part test/resource/logfiles/r1429.part 
	[ "$status" -eq 0 ]
}

@test "extract range over three blocks" {
	run ./src/logksi extract test/out/extract.base -r 3-7 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/extract.base.part -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run diff test/out/extract.base.part test/resource/logfiles/r3-7.part 
	[ "$status" -eq 0 ]
}

@test "attempt to extract a range given in descending order" {
	run ./src/logksi extract test/out/extract.base -r 7-3 -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: list of positions must be given in strictly ascending order." ]]
}

@test "attempt to extract a list that contains duplicates" {
	run ./src/logksi extract test/out/extract.base -r 3,4,5-7,7 -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: list of positions must be given in strictly ascending order." ]]
}

@test "attempt to extract a list of ranges given in descending order" {
	run ./src/logksi extract test/out/extract.base -r 6-7,3-5 -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: list of positions must be given in strictly ascending order." ]]
}
