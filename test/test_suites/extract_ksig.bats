#!/bin/bash

export KSI_CONF=test/test.cfg

mkdir -p test/out/ksig
cp -r test/resource/logsignatures/extract.base.logsig test/out/ksig
cp -r test/resource/logfiles/extract.base test/out/ksig
mkdir -p test/out/ksig-base-name
mkdir -p test/out/ksig-diff-base-name

mkdir -p test/out/ksig-base-name-only-out-log
cp -r test/resource/logsignatures/extract.base.logsig test/out/ksig-base-name-only-out-log
cp -r test/resource/logfiles/extract.base test/out/ksig-base-name-only-out-log

mkdir -p test/out/ksig-base-name-only-out-proof
cp -r test/resource/logsignatures/extract.base.logsig test/out/ksig-base-name-only-out-proof
cp -r test/resource/logfiles/extract.base test/out/ksig-base-name-only-out-proof

mkdir -p test/out/ksig-base-name-base-plus-out-proof
mkdir -p test/out/ksig-base-name-base-plus-out-log

mkdir -p test/out/ksig-to-stdout
mkdir -p test/out/ksig-to-stdout-with-base-name

mkdir -p test/out/ksig-not-const-size-aggr-chain
cp -r test/resource/logsignatures/extract.base.logsig test/out/ksig-not-const-size-aggr-chain/extract.base.logsig
cp -r test/resource/logfiles/extract.base test/out/ksig-not-const-size-aggr-chain/extract.base






@test "extract pure KSI signatures - derive names from logfile name and store in same dir" {
	run src/logksi extract -r 1,3-4 test/out/ksig/extract.base -d --ksig
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           3" ]]

	run test -f test/out/ksig/extract.base.excerpt
	[ "$status" -ne 0 ]
	run test -f test/out/ksig/extract.base.excerpt.logsig
	[ "$status" -ne 0 ]
	run bash -c "ls test/out/ksig/ | wc -w"
	[[ "$output" =~ "8" ]]

	run ksi verify --ver-int test/out/ksig/extract.base.line.1.ksig -f test/out/ksig/extract.base.line.1
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig/extract.base.line.3.ksig -f test/out/ksig/extract.base.line.3
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig/extract.base.line.4.ksig -f test/out/ksig/extract.base.line.4
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - specify output file base name" {
	run src/logksi extract -r 1,3-4 test/out/ksig/extract.base -d -o test/out/ksig-base-name/mylog --ksig
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           3" ]]

	run test -f test/out/ksig-base-name/mylog.excerpt
	[ "$status" -ne 0 ]
	run test -f test/out/ksig-base-name/mylog.excerpt.logsig
	[ "$status" -ne 0 ]
	run bash -c "ls test/out/ksig-base-name/ | wc -w"
	[[ "$output" =~ "6" ]]

	run ksi verify --ver-int test/out/ksig-base-name/mylog.line.1.ksig -f test/out/ksig-base-name/mylog.line.1
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name/mylog.line.3.ksig -f test/out/ksig-base-name/mylog.line.3
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name/mylog.line.4.ksig -f test/out/ksig-base-name/mylog.line.4
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - specify different base names for log and ksi signature" {
	run src/logksi extract -r 1,3-4 test/out/ksig/extract.base -d --out-log test/out/ksig-diff-base-name/mylog --out-proof test/out/ksig-diff-base-name/mysig --ksig
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           3" ]]

	run test -f test/out/ksig-diff-base-name/mylog
	[ "$status" -ne 0 ]
	run test -f test/out/ksig-diff-base-name/mysig
	[ "$status" -ne 0 ]
	run bash -c "ls test/out/ksig-diff-base-name/ | wc -w"
	[[ "$output" =~ "6" ]]

	run ksi verify --ver-int test/out/ksig-diff-base-name/mysig.line.1.ksig -f test/out/ksig-diff-base-name/mylog.line.1
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-diff-base-name/mysig.line.3.ksig -f test/out/ksig-diff-base-name/mylog.line.3
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-diff-base-name/mysig.line.4.ksig -f test/out/ksig-diff-base-name/mylog.line.4
	[ "$status" -eq 0 ]
}

# Log line file base name is specified explicitly, signature file names base is derived from log file name.
@test "extract pure KSI signatures - specify only --out-log" {
	run src/logksi extract -r 1,3-4 test/out/ksig-base-name-only-out-log/extract.base -d --out-log test/out/ksig-base-name-only-out-log/mylog --ksig
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           3" ]]

	run test -f test/out/ksig-base-name-only-out-log/mylog
	[ "$status" -ne 0 ]
	run test -f test/out/ksig-base-name-only-out-log/extract.base.excerpt.logsig
	[ "$status" -ne 0 ]
	run bash -c "ls test/out/ksig-base-name-only-out-log/ | wc -w"
	[[ "$output" =~ "8" ]]

	run ksi verify --ver-int test/out/ksig-base-name-only-out-log/extract.base.line.1.ksig -f test/out/ksig-base-name-only-out-log/mylog.line.1
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name-only-out-log/extract.base.line.3.ksig -f test/out/ksig-base-name-only-out-log/mylog.line.3
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name-only-out-log/extract.base.line.4.ksig -f test/out/ksig-base-name-only-out-log/mylog.line.4
	[ "$status" -eq 0 ]
}

# TODO FIX COMMENT
# Log line file base name is specified explicitly, signature file names base is derived from log file name.
@test "extract pure KSI signatures - specify only --out-proof" {
	run src/logksi extract -r 1,3-4 test/out/ksig-base-name-only-out-proof/extract.base -d --out-proof test/out/ksig-base-name-only-out-proof/mysig --ksig
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           3" ]]

	run test -f test/out/ksig-base-name-only-out-proof/extract.base.excerpt
	[ "$status" -ne 0 ]
	run test -f test/out/ksig-base-name-only-out-proof/mysig
	[ "$status" -ne 0 ]
	run bash -c "ls test/out/ksig-base-name-only-out-proof/ | wc -w"
	[[ "$output" =~ "8" ]]

	run ksi verify --ver-int test/out/ksig-base-name-only-out-proof/mysig.line.1.ksig -f test/out/ksig-base-name-only-out-proof/extract.base.line.1
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name-only-out-proof/mysig.line.3.ksig -f test/out/ksig-base-name-only-out-proof/extract.base.line.3
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name-only-out-proof/mysig.line.4.ksig -f test/out/ksig-base-name-only-out-proof/extract.base.line.4
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - specify -o and --out-proof" {
	run src/logksi extract -r 1,3-4 test/out/ksig/extract.base -d -o test/out/ksig-base-name-base-plus-out-proof/basename --out-proof test/out/ksig-base-name-base-plus-out-proof/mysig --ksig
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           3" ]]

	run test -f test/out/ksig-base-name-base-plus-out-proof/basename.excerpt
	[ "$status" -ne 0 ]
	run test -f test/out/ksig-base-name-base-plus-out-proof/mysig
	[ "$status" -ne 0 ]
	run bash -c "ls test/out/ksig-base-name-base-plus-out-proof/ | wc -w"
	[[ "$output" =~ "6" ]]

	run ksi verify --ver-int test/out/ksig-base-name-base-plus-out-proof/mysig.line.1.ksig -f test/out/ksig-base-name-base-plus-out-proof/basename.line.1
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name-base-plus-out-proof/mysig.line.3.ksig -f test/out/ksig-base-name-base-plus-out-proof/basename.line.3
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name-base-plus-out-proof/mysig.line.4.ksig -f test/out/ksig-base-name-base-plus-out-proof/basename.line.4
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - specify -o and --out-log" {
	run src/logksi extract -r 1,3-4 test/out/ksig/extract.base -d -o test/out/ksig-base-name-base-plus-out-log/basename --out-log test/out/ksig-base-name-base-plus-out-log/mylog --ksig
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           3" ]]

	run test -f test/out/ksig-base-name-base-plus-out-log/mylog
	[ "$status" -ne 0 ]
	run test -f test/out/ksig-base-name-base-plus-out-log/basename.excerpt.logsig
	[ "$status" -ne 0 ]
	run bash -c "ls test/out/ksig-base-name-base-plus-out-log/ | wc -w"
	[[ "$output" =~ "6" ]]

	run ksi verify --ver-int test/out/ksig-base-name-base-plus-out-log/basename.line.1.ksig -f test/out/ksig-base-name-base-plus-out-log/mylog.line.1
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name-base-plus-out-log/basename.line.3.ksig -f test/out/ksig-base-name-base-plus-out-log/mylog.line.3
	[ "$status" -eq 0 ]
	run ksi verify --ver-int test/out/ksig-base-name-base-plus-out-log/basename.line.4.ksig -f test/out/ksig-base-name-base-plus-out-log/mylog.line.4
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - --out-log to stdout" {
	run bash -c "src/logksi extract -r 1 test/out/ksig/extract.base -d --out-log - --out-proof test/out/ksig-to-stdout/mysig --ksig > test/out/ksig-to-stdout/log_from_stdout"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           1" ]]

	run bash -c "ls test/out/ksig-to-stdout/ | wc -w"
	[[ "$output" =~ "2" ]]

	run ksi verify --ver-int test/out/ksig-to-stdout/mysig.line.1.ksig -f test/out/ksig-to-stdout/log_from_stdout
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - --out-proof to stdout" {
	run bash -c "src/logksi extract -r 1 test/out/ksig/extract.base -d --out-log test/out/ksig-to-stdout/mylog --out-proof - --ksig > test/out/ksig-to-stdout/sig_from_stdout"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           1" ]]

	run bash -c "ls test/out/ksig-to-stdout/ | wc -w"
	[[ "$output" =~ "4" ]]

	run ksi verify --ver-int test/out/ksig-to-stdout/sig_from_stdout -f test/out/ksig-to-stdout/mylog.line.1
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - -o to stdout with --out-proof" {
	run bash -c "src/logksi extract -r 1 test/out/ksig/extract.base -d -o - --out-proof test/out/ksig-to-stdout-with-base-name/mysig --ksig > test/out/ksig-to-stdout-with-base-name/log_from_stdout"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           1" ]]

	run bash -c "ls test/out/ksig-to-stdout-with-base-name/ | wc -w"
	[[ "$output" =~ "2" ]]

	run ksi verify --ver-int test/out/ksig-to-stdout-with-base-name/mysig.line.1.ksig -f test/out/ksig-to-stdout-with-base-name/log_from_stdout
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - -o to stdout with --out-log" {
	run bash -c "src/logksi extract -r 1 test/out/ksig/extract.base -d --out-log test/out/ksig-to-stdout-with-base-name/mylog -o - --ksig > test/out/ksig-to-stdout-with-base-name/sig_from_stdout"
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           1" ]]

	run bash -c "ls test/out/ksig-to-stdout-with-base-name/ | wc -w"
	[[ "$output" =~ "4" ]]

	run ksi verify --ver-int test/out/ksig-to-stdout-with-base-name/sig_from_stdout -f test/out/ksig-to-stdout-with-base-name/mylog.line.1
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - extract hash chain thats length is slightly smaller due to the shape of the tree" {
	run ./src/logksi extract test/out/ksig-not-const-size-aggr-chain/extract.base -r 51 --ksig -d
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Extracting records... ok." ]]
	[[ "$output" =~ "Records extracted:           1" ]]

	run bash -c "ls test/out/ksig-to-stdout-with-base-name/ | wc -w"
	[[ "$output" =~ "4" ]]

	run ksi verify --ver-int test/out/ksig-not-const-size-aggr-chain/extract.base.line.51.ksig -f test/out/ksig-not-const-size-aggr-chain/extract.base.line.51
	[ "$status" -eq 0 ]
}

@test "extract pure KSI signatures - try to extract from legacy" {
	run ./src/logksi extract test/resource/logfiles/legacy_extract test/resource/logsignatures/legacy_extract.gtsig  -r 1 --ksig -o test/out/unable-to-extract-ksig
	[ "$status" -eq 4 ]
	[[ "$output" =~ "Error: It is not possible to extract pure KSI signature from RFC3161 timestamp." ]]
}
