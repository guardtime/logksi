#!/bin/bash

export KSI_CONF=test/test.cfg


@test "Extend CMD test: try to extend signature from stdin and from command line simultaneously" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -d --sig-from-stdin
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Maybe you want to: Extend, from file, to the earliest available publication. --input -X -P" ]]
	[[ "$output" =~ "Maybe you want to: Extend, from standard input, to the earliest available publication. --sig-from-stdin -X -P" ]]
	[[ "$output" =~ "Maybe you want to: Extend, from file, to time specified in publications string. --input -X -P --pub-str" ]]
}

@test "Extend CMD test: try to use invalid stdout combination" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o - --log - -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Multiple different simultaneous outputs to stdout (-o -, --log -)." ]]
}

@test "Extend CMD test: try to use only one not existing log file"  {
	run src/logksi extend i_do_not_exist -o test/out/dummy.ksig -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(--input).*(i_do_not_exist) ]]
}

@test "Extend CMD test: try to use two not existing input files"  {
	run src/logksi extend i_do_not_exist_1 i_do_not_exist_2 -o test/out/dummy.ksig -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ (File does not exist).*(Parameter).*(--input).*(i_do_not_exist_1) ]]
	[[ "$output" =~ (File does not exist).*(Parameter).*(--input).*(i_do_not_exist_2) ]]
}

@test "Extend CMD test: try to use one unexpected but existing extra input file"  {
	run src/logksi extend test/resource/logs_and_signatures/signed test/resource/logs_and_signatures/signed -o test/out/dummy.ksig
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Error: Only one inputs (log file to locate its log signature file) is required, but there are 2!" ]]
}

@test "Extend CMD test: try to use invalid publication string: Invalid character" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig --pub-str AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2# -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Invalid base32 character).*(Parameter).*(--pub-str).*(AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2#) ]]
}

# TODO: Fix...
#@test "Extend CMD test: try to use invalid publication string: Too short" {
#	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig --pub-str AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N -d
#	[ "$status" -eq 4 ]
#	[[ "$output" =~ (Error).*(Unable parse publication string) ]]
#}

#@test "Extend CMD test: try to use invalid publication string: Too long" {
#	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig --pub-str AAAAAA-C3JKHI-AAKZ7D-HQQZU2-AF2ZKN-ZNXY5B-LMWRIN-DI37WF-PETGGY-YWWEA7-3MRG3N-V4WO2F-V4WO2F -d
#	[ "$status" -eq 4 ]
#	[[ "$output" =~ (Error).*(Unable parse publication string) ]]
#}

@test "Extend CMD test: try to use invalid certificate constraints: Invalid constraints format" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -d  --cnstr = --cnstr =A --cnstr B=
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Parameter is invalid).*(Parameter).*(--cnstr).*(=) ]]
	[[ "$output" =~ (Parameter is invalid).*(Parameter).*(--cnstr).*(=A) ]]
	[[ "$output" =~ (Parameter is invalid).*(Parameter).*(--cnstr).*(B=) ]]
}

@test "Extend CMD test: try to use invalid certificate constraints: Invalid constraints OID" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -d  --cnstr dummy=nothing
	[ "$status" -eq 3 ]
	[[ "$output" =~ (OID is invalid).*(Parameter).*(--cnstr).*(dummy=nothing) ]]
}
