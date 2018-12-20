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
	run bash -c "echo dummy signature | ./src/logksi verify --log-from-stdin -dd test/resource/logfiles/unsigned test/resource/logfiles/unsigned"
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error).*(Log file from stdin [(]--log-from-stdin[)] needs only ONE explicitly specified log signature file, but there are 2)  ]]
}

@test "verify CMD test: Try to verify log file from stdin and from input after --" {
	run bash -c "echo dummy signature | ./src/logksi verify --log-from-stdin -dd -- test/resource/logfiles/unsigned"
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
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -dd --ignore-desc-block-time --cnstr = --cnstr =A --cnstr B=
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Parameter is invalid).*(Parameter).*(--cnstr).*(=) ]]
	[[ "$output" =~ (Parameter is invalid).*(Parameter).*(--cnstr).*(=A) ]]
	[[ "$output" =~ (Parameter is invalid).*(Parameter).*(--cnstr).*(B=) ]]
}

@test "verify CMD test: Try to use invalid certificate constraints: Invalid constraints OID" {
	run ./src/logksi verify --ver-key test/resource/logs_and_signatures/log_repaired -dd --ignore-desc-block-time --cnstr dummy=nothing
	[ "$status" -eq 3 ]
	[[ "$output" =~ (OID is invalid).*(Parameter).*(--cnstr).*(dummy=nothing) ]]
}
