#!/bin/bash

export KSI_CONF=test/test.cfg

@test "CDM test: use invalid stdin combination" {
	run src/logksi verify --log-from-stdin --input-hash - test/resource/interlink/ok-testlog-interlink-1.logsig
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous inputs from stdin (--input-hash -, --log-from-stdin)" ]]
}

@test "CDM test: use invalid stdout combination" {
	run src/logksi verify  test/resource/interlink/ok-testlog-interlink-1 --log - --output-hash -
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (--log -, --output-hash -)." ]]
}

@test "verify CMD test: use invalid stdin combination" {
	run src/logksi verify --log-from-stdin --input-hash - test/resource/interlink/ok-testlog-interlink-1.logsig
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous inputs from stdin (--input-hash -, --log-from-stdin)" ]]
}

@test "verify CMD test: use invalid stdout combination" {
	run src/logksi verify  test/resource/interlink/ok-testlog-interlink-1 --log - --output-hash -
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (--log -, --output-hash -)." ]]
}

@test "verify CMD test: try to use only one not existing input file"  {
	run src/logksi verify i_do_not_exist
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(--input).*(i_do_not_exist) ]]
}

@test "verify CMD test: try to use two not existing input files"  {
	run src/logksi verify i_do_not_exist_1 i_do_not_exist_2
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(--input).*(i_do_not_exist_1) ]]
	[[ "$output" =~ (File does not exist).*(Parameter).*(--input).*(i_do_not_exist_2) ]]
}

@test "verify CMD test: try to use two not existing input files after --"  {
	run src/logksi verify -- i_do_not_exist_1 i_do_not_exist_2
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(--input).*(i_do_not_exist_1) ]]
	[[ "$output" =~ (File does not exist).*(Parameter).*(--input).*(i_do_not_exist_2) ]]
}

@test "verify CMD test: existing explicitly specified log and log signature file with one unexpected but existing extra file"  {
	run src/logksi verify test/resource/logs_and_signatures/log_repaired test/resource/logs_and_signatures/log_repaired.logsig test/resource/logfiles/unsigned
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Only two inputs (log and log signature file) are required, but there are 3!" ]]
}

@test "verify CMD test: existing explicitly specified log and log signature file with one unexpected token that is not existing file"  {
	run src/logksi verify test/resource/logs_and_signatures/log_repaired i_do_not_exist
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(--input).*(i_do_not_exist) ]]
}

@test "verify CMD test: Try to verify log file from stdin and specify multiple input files" {
	run bash -c "echo dummy signature | ./src/logksi verify --log-from-stdin -ddd test/resource/logfiles/unsigned test/resource/logfiles/unsigned"
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error).*(Log file from stdin [(]--log-from-stdin[)] needs only ONE explicitly specified log signature file, but there are 2)  ]]
}

@test "verify CMD test: Try to verify log file from stdin and from input after --" {
	run bash -c "echo dummy signature | ./src/logksi verify --log-from-stdin -ddd -- test/resource/logfiles/unsigned"
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error).*(It is not possible to verify both log file from stdin [(]--log-from-stdin[)] and log file[(]s[)] specified after [-][-])  ]]
}

@test "verify CMD test: Try to use invalid publication string: Invalid character" {
	run ./src/logksi verify --ver-pub test/resource/logs_and_signatures/log_repaired --pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2J#
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Invalid base32 character).*(Parameter).*(--pub-str).*(AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF-I7W2J#) ]]
}

@test "verify CMD test: Try to use invalid publication string: Too short" {
	run ./src/logksi verify --ver-pub test/resource/logs_and_signatures/log_repaired --pub-str AAAAAA-C2PMAF-IAISKD-4JLNKD-ZFCF5L-4OWMS5-DMJLTC-DCJ6SS-QDFBC4-ELLWTM-5BO7WF
	[ "$status" -eq 4 ]
	[[ "$output" =~ (Error).*(Unable parse publication string) ]]
}

@test "verify CMD test: Try to use invalid certificate constraints: Invalid constraints format" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -ddd --ignore-desc-block-time --cnstr = --cnstr =A --cnstr B=
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Parameter is invalid).*(Parameter).*(--cnstr).*(=) ]]
	[[ "$output" =~ (Parameter is invalid).*(Parameter).*(--cnstr).*(=A) ]]
	[[ "$output" =~ (Parameter is invalid).*(Parameter).*(--cnstr).*(B=) ]]
}

@test "verify CMD test: Try to use invalid certificate constraints: Invalid constraints OID" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -ddd --ignore-desc-block-time --cnstr dummy=nothing
	[ "$status" -eq 3 ]
	[[ "$output" =~ (OID is invalid).*(Parameter).*(--cnstr).*(dummy=nothing) ]]
}

@test "verify CMD test: Try to use invalid --time-diff 1" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -d --time-diff "" --time-diff " " --time-diff S --time-diff M --time-diff H --time-diff d --time-diff s --time-diff m --time-diff h --time-diff D --time-diff - --time-diff o
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Parameter has no content).*(Parameter).*(--time-diff).*(\'\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\' \') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'S\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'M\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'H\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'d\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'s\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'m\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'h\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'D\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'-\') ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(\'o\') ]]
}

@test "verify CMD test: Try to use invalid --time-diff 2" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -d --time-diff 1S2 --time-diff 1S3S --time-diff 1M3M  --time-diff 1H3H  --time-diff 1d3d --time-diff "2 2" --time-diff dHMS --time-diff S5 --time-diff M6 --time-diff H7 --time-diff d8 --time-diff --2 --time-diff 2d-1 --time-diff 2D
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(1S2) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(1S3S) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(1M3M) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(1H3H) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(1d3d) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(2 2) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(dHMS) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(S5) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(M6) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(H7) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(d8) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(--2) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(2d-1) ]]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-diff).*(2D) ]]
}

@test "verify CMD test: Try to use invalid --time-diff range (n,m)" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -d --time-diff , --time-diff 5, --time-diff ,5 --time-diff 5,4 --time-diff -5,-4 --time-diff -3,2, --time-diff 5,oo --time-diff -oo,oo
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Time range should be -<int>,<int>.).*(Parameter).*(--time-diff).*(,) ]]
	[[ "$output" =~ (Time range should be -<int>,<int>.).*(Parameter).*(--time-diff).*(5,) ]]
	[[ "$output" =~ (Time range should be -<int>,<int>.).*(Parameter).*(--time-diff).*(,5) ]]
	[[ "$output" =~ (Time range should be -<int>,<int>.).*(Parameter).*(--time-diff).*(5,4) ]]
	[[ "$output" =~ (Time range should be -<int>,<int>.).*(Parameter).*(--time-diff).*(-5,-4) ]]
	[[ "$output" =~ (Time range should be -<int>,<int>.).*(Parameter).*(--time-diff).*(-3,2,) ]]
	[[ "$output" =~ (Time range should be -<int>,<int>.).*(Parameter).*(--time-diff).*(5,oo) ]]
	[[ "$output" =~ (Time range should be -<int>,<int>.).*(Parameter).*(--time-diff).*(-oo,oo) ]]
}

@test "verify CMD test: Try to use invalid --block-time-diff range" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -d  --block-time-diff -oo,-oo --block-time-diff oo,oo --block-time-diff ,oo --block-time-diff oo, --block-time-diff o --block-time-diff -o --block-time-diff 5,o --block-time-diff o,5 --block-time-diff o,o
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Time range with infinity can be -oo,oo, <int>,oo or -oo,<int>).*(Parameter).*(--block-time-diff).*(-oo,-oo) ]]
	[[ "$output" =~ (Time range with infinity can be -oo,oo, <int>,oo or -oo,<int>).*(Parameter).*(--block-time-diff).*(oo,oo) ]]
	[[ "$output" =~ (Time range should be -<int>,<int>).*(Parameter).*(--block-time-diff).*(,oo) ]]
	[[ "$output" =~ (Time range with infinity can be -oo,oo, <int>,oo or -oo,<int>).*(Parameter).*(--block-time-diff).*(oo,) ]]
	[[ "$output" =~ (Only digits, oo and 1x d, H, M and S allowed).*(Parameter).*(--block-time-diff).*(o) ]]
	[[ "$output" =~ (Only digits, oo and 1x d, H, M and S allowed).*(Parameter).*(--block-time-diff).*(-o) ]]
	[[ "$output" =~ (Only digits, oo and 1x d, H, M and S allowed).*(Parameter).*(--block-time-diff).*(5,o) ]]
	[[ "$output" =~ (Only digits, oo and 1x d, H, M and S allowed).*(Parameter).*(--block-time-diff).*(o,5) ]]
	[[ "$output" =~ (Only digits, oo and 1x d, H, M and S allowed).*(Parameter).*(--block-time-diff).*(o,o) ]]
}

@test "verify CMD test: Check if --time-disordered has the same type as --time-diff but does not allow comma nor minus nor infinity" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -d --time-disordered 1S2
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowed).*(Parameter).*(--time-disordered).*(1S2) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -d --time-disordered 1,1
	[ "$status" -eq 3 ]
	[[ "$output" =~ (No comma .,. supported for range).*(Parameter).*(--time-disordered).*(1,1) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -d --time-disordered -5
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Only unsigned value allowed).*(Parameter).*(--time-disordered).*(-5) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -d --time-disordered oo
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Only digits and 1x d, H, M and S allowe).*(Parameter).*(--time-disordered).*(oo) ]]
}

@test "verify CMD test: Check parsing of --time-diff S" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -2
	[[ "$output" =~ (expected time window).*(-00:00:02) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -2S
	[[ "$output" =~ (expected time window).*(-00:00:02) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -59S
	[[ "$output" =~ (expected time window).*(-00:00:59) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -60S
	[[ "$output" =~ (expected time window).*(-00:01:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -121
	[[ "$output" =~ (expected time window).*(-00:02:01) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -3599
	[[ "$output" =~ (expected time window).*(-00:59:59) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -3600
	[[ "$output" =~ (expected time window).*(-01:00:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -86400
	[[ "$output" =~ (expected time window).*(-1d 00:00:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -6048000
	[[ "$output" =~ (expected time window).*(-70d 00:00:00) ]]
}

@test "verify CMD test: Check parsing of --time-diff M" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -2M
	[[ "$output" =~ (expected time window).*(-00:02:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -59M
	[[ "$output" =~ (expected time window).*(-00:59:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -60M
	[[ "$output" =~ (expected time window).*(-01:00:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -61M
	[[ "$output" =~ (expected time window).*(-01:01:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -121M
	[[ "$output" =~ (expected time window).*(-02:01:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -1440M
	[[ "$output" =~ (expected time window).*(-1d 00:00:00) ]]
}

@test "verify CMD test: Check parsing of --time-diff H" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -2H
	[[ "$output" =~ (expected time window).*(-02:00:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -23H
	[[ "$output" =~ (expected time window).*(-23:00:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -24H
	[[ "$output" =~ (expected time window).*(-1d 00:00:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -48H
	[[ "$output" =~ (expected time window).*(-2d 00:00:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -49H
	[[ "$output" =~ (expected time window).*(-2d 01:00:00) ]]
}

@test "verify CMD test: Check parsing of --time-diff d" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -2d
	[[ "$output" =~ (expected time window).*(-2d 00:00:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -70d
	[[ "$output" =~ (expected time window).*(-70d 00:00:00) ]]
}

@test "verify CMD test: Check parsing of --time-diff S M H d" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -0d3H5M0S
	[[ "$output" =~ (expected time window).*(-03:05:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -0S0d5M3H
	[[ "$output" =~ (expected time window).*(-03:05:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -10d59
	[[ "$output" =~ (expected time window).*(-10d 00:00:59) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -1H59M60S
	[[ "$output" =~ (expected time window).*(-02:00:00) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed  --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -23H59M60S
	[[ "$output" =~ (expected time window).*(-1d 00:00:00) ]]
}

@test "verify CMD test: Check parsing of --time-diff with 2 values (range)" {
	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-higher-and-lower-from-ksig test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff 1d,-1d17
	[[ "$output" =~ (expected time window).*(-1d 00:00:17 - 1d 00:00:00) ]]

	run ./src/logksi verify test/resource/log_rec_time/log-line-embedded-date-higher-and-lower-from-ksig test/resource/log_rec_time/log-line-embedded-date-changed.logsig --use-stored-hash-on-fail --time-form "%B %d %H:%M:%S" --time-base 2018 --time-diff -1d17,1d
	[[ "$output" =~ (expected time window).*(-1d 00:00:17 - 1d 00:00:00) ]]
}

@test "verify CMD test: Check parsing of --block-time-diff" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed -d --block-time-diff 1d1M32S,2
	[[ "$output" =~ (does not fit into).*(00:00:02 - 1d 00:01:32) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed -d --block-time-diff 2,1d1M32S
	[[ "$output" =~ (does not fit into).*(00:00:02 - 1d 00:01:32) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed -d --block-time-diff 2,oo
	[[ "$output" =~ (does not fit into).*(00:00:02 - oo) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed -d --block-time-diff -oo
	[[ "$output" =~ (does not fit into).*(-oo - 0) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed -d --block-time-diff -5
	[[ "$output" =~ (does not fit into).*(-00:00:05 - 0) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed -d --block-time-diff -oo,-5
	[[ "$output" =~ (does not fit into).*(-oo - -00:00:05) ]]

	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/signed -d --block-time-diff 2,oo
	[[ "$output" =~ (does not fit into).*(00:00:02 - oo) ]]
}
