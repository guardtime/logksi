#!/bin/bash

# Note: KSI_CONF must be empty string. 
export KSI_CONF=""



@test "embedded URL test: check that there is no default conf" {
	run src/logksi conf
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Warning: Environment variable KSI_CONF is an empty string." ]]
	[[ "$output" =~ (Signing.*Not defined) ]]
	[[ "$output" =~ (Extending.*Not defined) ]]
	[[ "$output" =~ (Publications file.*Not defined) ]]
}


@test "embedded URL test: generate configuration files" {
	run bash -c "test/construct_conf_file.sh test/test.cfg '' '' '' '' 'ksi+http://' > test/out/ok-embed-ksi-usrinf.cnf"
	[ "$status" -eq 0 ]

	run bash -c "test/construct_conf_file.sh test/test.cfg '' '' '' '' 'http://' > test/out/ok-embed-http-usrinf.cnf"
	[ "$status" -eq 0 ]

	run cp test/out/ok-embed-ksi-usrinf.cnf test/out/ok-embed-ksi-usrinf-with-bad-explicit-usrinf.cnf
	[ "$status" -eq 0 ]

	run bash -c "echo ' --aggr-key _invalid_key_' >> test/out/ok-embed-ksi-usrinf-with-bad-explicit-usrinf.cnf"
	[ "$status" -eq 0 ]
	run bash -c "echo ' --aggr-user _invalid_user_' >> test/out/ok-embed-ksi-usrinf-with-bad-explicit-usrinf.cnf"
	[ "$status" -eq 0 ]
	run bash -c "echo ' --ext-key _invalid_key_' >> test/out/ok-embed-ksi-usrinf-with-bad-explicit-usrinf.cnf"
	[ "$status" -eq 0 ]
	run bash -c "echo ' --ext-user _invalid_user_' >> test/out/ok-embed-ksi-usrinf-with-bad-explicit-usrinf.cnf"
	[ "$status" -eq 0 ]
}

@test "embedded URL test: sign with correct user info embedded into the URL" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -d --conf test/out/ok-embed-ksi-usrinf.cnf
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Signing... ok.).*(Count of resigned blocks:    3) ]]
}

@test "embedded URL test: extend with correct user info embedded into the URL" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -dd --conf test/out/ok-embed-ksi-usrinf.cnf
	[ "$status" -eq 0 ]
	[[ "$output" =~ (Extending Block no).*(1).*(to the earliest available publication).*(ok) ]]
}

# Check that http user info is not interpreted as KSI user info. A configuration
# file is provided that has correct service URLs and has proper KSI user info
# embedded into the URLs as http user info - it must not be used for KSI
# service. Task must fail as default configuration file contains some nonsense
# as user info.
@test "embedded URL test: check that http user info is not interpreted as KSI user info during signing" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -d --conf test/out/ok-embed-http-usrinf.cnf
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Unable to configure network provider.) ]]
}

@test "embedded URL test: check that http user info is not interpreted as KSI user info during extending" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -dd --conf test/out/ok-embed-http-usrinf.cnf
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Error: Unable to configure network provider.) ]]
}

# Use configuration file that has correct KSI service URL with correct embedded
# KSI user info and invalid explicit user info that will overwrite the embedded
# user info. Task must fail.
@test "embedded URL test: check that embedded user info has lower priority when signing" {
	run src/logksi sign test/resource/logs_and_signatures/unsigned -o test/out/dummy.ksig -d --conf test/out/ok-embed-ksi-usrinf-with-bad-explicit-usrinf.cnf
	[ "$status" -eq 14 ]
	[[ "$output" =~ (Error: The request could not be authenticated) ]]
}

@test "embedded URL test: check that embedded user info has lower priority when extending" {
	run src/logksi extend test/resource/logs_and_signatures/signed -o test/out/dummy.ksig -dd --conf test/out/ok-embed-ksi-usrinf-with-bad-explicit-usrinf.cnf
	[ "$status" -eq 14 ]
	[[ "$output" =~ (Error: The request could not be authenticated) ]]
}