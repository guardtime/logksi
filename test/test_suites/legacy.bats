#!/bin/bash

export KSI_CONF=test/test.cfg

cp -r test/resource/logfiles/legacy test/out
cp -r test/resource/logsignatures/legacy.gtsig test/out

@test "verify legacy.gtsig explicitly" {
	run ./src/logksi verify test/out/legacy test/out/legacy.gtsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Warning: RFC3161 timestamp(s) found in log signature." ]]
	[[ "$output" =~ "Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify legacy.gtsig implicitly" {
	run ./src/logksi verify test/out/legacy -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Warning: RFC3161 timestamp(s) found in log signature." ]]
	[[ "$output" =~ "Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "try extending and overwriting legacy.gtsig" {
	run ./src/logksi extend test/out/legacy -d
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Error: Overwriting of legacy log signature file not enabled." ]]
	[[ "$output" =~ "Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures." ]]
}

@test "extend legacy.gtsig to extended_legacy.gtsig" {
	run ./src/logksi extend test/out/legacy -o test/out/extended_legacy.gtsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify extended_legacy.gtsig" {
	run ./src/logksi verify test/out/legacy -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Warning: RFC3161 timestamp(s) found in log signature." ]]
	[[ "$output" =~ "Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures." ]]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
	run ./src/logksi verify test/out/legacy test/out/extended_legacy.gtsig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "extending and overwriting legacy.gtsig" {
	run ./src/logksi extend test/out/legacy --enable-rfc3161-conversion -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

@test "verify extended legacy.gtsig" {
	run ./src/logksi verify test/out/legacy -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok." ]]
}

