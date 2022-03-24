#!/bin/bash

mkdir -p test/out/urandom
cp test/resource/logfiles/treehash1 test/out/urandom/logfile_1A

@test "create urandom: use default random seed" {
	run src/logksi create test/out/urandom/logfile_1A --blk-size 16 -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Creating... ok" ]]

	run src/logksi verify test/out/urandom/logfile_1A -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok" ]]
}