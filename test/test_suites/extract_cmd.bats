#!/bin/bash

export KSI_CONF=test/test.cfg

@test "extract CMD: attempt to open not existing log file" {
	run src/logksi extract notexist -r 1
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error: Could not open input log file).*(notexist) ]]
}

@test "extract CMD: attempt to open not existing log signature file" {
	run src/logksi extract test/resource/logfiles/legacy_extract -r 1
	[ "$status" -eq 9 ]
	[[ "$output" =~ (Error: Could not open input sig file).*(legacy_extract.logsig) ]]
}

@test "extract CMD: attempt to redirect both outputs to stdout via -o -" {
	run bash -c "./src/logksi extract test/resource/logs_and_signatures/log_repaired -o - -r 1"
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Both output files cannot be redirected to stdout." ]]
	[[ "$output" =~ "Suggestion:  Use ONLY '--out-log -' OR '--out-proof -' to redirect desired output to stdout." ]]
}

@test "extract CMD: attempt to redirect both outputs to stdout via -o - --ksig" {
	run bash -c "./src/logksi extract test/resource/logs_and_signatures/log_repaired -o - -r 1"
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Both output files cannot be redirected to stdout." ]]
	[[ "$output" =~ "Suggestion:  Use ONLY '--out-log -' OR '--out-proof -' to redirect desired output to stdout." ]]
}

@test "extract CMD: attempt to redirect multiple outputs to stdout 2" {
	run bash -c "./src/logksi extract test/resource/logs_and_signatures/log_repaired --out-log - --out-proof - -r 1"
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (--out-log -, --out-proof -)." ]]
	run bash -c "./src/logksi extract test/resource/logs_and_signatures/log_repaired --out-log - --out-proof - --log - -r 1"
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Multiple different simultaneous outputs to stdout (--log -, --out-log -, --out-proof -)." ]]
	run bash -c "./src/logksi extract test/resource/logs_and_signatures/log_repaired --out-proof - --log - -r 1"
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Multiple different simultaneous outputs to stdout (--log -, --out-proof -)." ]]
	run bash -c "./src/logksi extract test/resource/logs_and_signatures/log_repaired --out-log - --log - -r 1"
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Multiple different simultaneous outputs to stdout (--log -, --out-log -)." ]]
}

@test "extract CMD: attempt to redirect multiple outputs to stdout with --ksig and -r 1,2" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired --ksig --out-log - --out-proof - -r 1,2
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (--out-log -, --out-proof -)." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired --ksig --out-log - -o test/out/dummy -r 1,2
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (--ksig, --out-log -, -r 1,2)." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired --ksig --out-proof - -o test/out/dummy -r 1,2
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (--ksig, --out-proof -, -r 1,2)." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired --ksig --out-proof - -o test/out/dummy -r 1-2
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (--ksig, --out-proof -, -r 1-2)." ]]
}

@test "extract CMD: attempt to read both files from stdin" {
	run ./src/logksi extract --log-from-stdin --sig-from-stdin -r 1 -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Maybe you want to).*(Extract records and hash chains, log from stdin, signature from file) ]]
	[[ "$output" =~ (Maybe you want to).*(Extract records and hash chains, log from file, signature from stdin) ]]
	[[ "$output" =~ (Maybe you want to).*(Extract records and hash chains, log and signature from file) ]]
}

@test "extract CMD: attempt to read one file from stdin without specifying the other input file" {
	run ./src/logksi extract --log-from-stdin -r 1 -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Task).*(Extract records and hash chains, log from stdin, signature from file).*(is invalid).* ]]
	[[ "$output" =~ (You have to define) ]]
	run ./src/logksi extract --sig-from-stdin -r 1 -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Task).*(Extract records and hash chains, log from file, signature from stdin).*(is invalid).* ]]
}

@test "extract CMD: attempt to read log file from stdin without specifying the output file" {
	run ./src/logksi extract --log-from-stdin test/resource/logsignatures/extract.base.logsig -r 1 -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Output log records file name must be specified if log file is read from stdin." ]]
	run ./src/logksi extract --log-from-stdin test/resource/logsignatures/extract.base.logsig --out-log test/out/extract.user.10.excerpt -r 1 -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Output integrity proof file name must be specified if log file is read from stdin." ]]
}

@test "extract CMD: attempt to extract a range given in descending order" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 7-3
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must be given in strictly ascending order." ]]
}

@test "extract CMD: attempt to extract a list that contains duplicates" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 3,4,5-7,7
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must be given in strictly ascending order." ]]
}

@test "extract CMD: attempt to extract a list of ranges given in descending order" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 6-7,3-5
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must be given in strictly ascending order." ]]
}

@test "extract CMD: attempt to extract a list that contains non-positive numbers" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 6,-7
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 6,7-8,-9
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 6,7--8,9
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 0,3
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 0-3
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r -3-3
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
}

@test "extract CMD: attempt to extract a list that contains syntax errors" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r ,
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 5,
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r -
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 6-
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 5,,6
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 5-6-7
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
}

@test "extract CMD: attempt to extract a list that contains whitespace" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r "5 6"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r "5 ,6"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r "5, 6"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r "5 -7"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r "5- 7"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r "5,7 "
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r " 5-7"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r " 5\t7"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r " 5\n7"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r " 5\v7"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r " 5\f7"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r " 5\r7"
	[ "$status" -ne 0 ]
	[[ "$output" =~ "List of positions must not contain whitespace. Use ',' and '-' as separators." ]]
}

@test "extract CMD: attempt to extract a list that contains non-decimal integers" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 0x5
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 0X5
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 5,0x6
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r 5-0X6
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
}

@test "extract CMD: attempt to extract a list that contains illegal characters" {
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r a
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r Z
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r +
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r \*
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r %
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r $
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r .
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
	run ./src/logksi extract test/resource/logs_and_signatures/log_repaired -r :
	[ "$status" -ne 0 ]
	[[ "$output" =~ "Positions must be represented by positive decimal integers, using a list of comma-separated ranges." ]]
}
