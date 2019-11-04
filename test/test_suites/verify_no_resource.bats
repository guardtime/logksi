#!/bin/bash

# Note: KSI_CONF must be empty string. 
export KSI_CONF=""



@test "check that there is no default conf" {
	run src/logksi conf
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Warning: Environment variable KSI_CONF is an empty string." ]]
	[[ "$output" =~ (Signing.*Not defined) ]]
	[[ "$output" =~ (Extending.*Not defined) ]]
	[[ "$output" =~ (Publications file.*Not defined) ]]
}

@test "trust anchor-based verification: no -P for Calendar Authentication Record" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: Publications file (-P) needed for verifying Calendar Authentication Record is not configured!" ]]
}

@test "trust anchor-based verification: no -P for Calendar Authentication Record and --continue-on-fail" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --continue-on-fail
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: Publications file (-P) needed for verifying Calendar Authentication Record is not configured!" ]]
}

@test "trust anchor-based verification: no -P for Publication Record" {
	run src/logksi verify test/resource/logs_and_signatures/extended -d
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: Publications file (-P) needed for verifying signature's Publication Record is not configured!" ]]
}

@test "trust anchor-based verification: no -P for Publication and --continue-on-fail" {
	run src/logksi verify test/resource/logs_and_signatures/extended -d --continue-on-fail
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: Publications file (-P) needed for verifying signature's Publication Record is not configured!" ]]
}

@test "trust anchor-based verification: no -x with -X" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d -x
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: Extending is permitted (-x) but extender is not configured (-X)." ]]
}

@test "trust anchor-based verification: no -x with -X and --continue-on-fail" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d -x --continue-on-fail
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: Extending is permitted (-x) but extender is not configured (-X)." ]]
}

@test "key-based verification: without resources" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-key
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Task).*(Key-based verification)*(is invalid) ]]
	[[ "$output" =~ (You have to define flag).*(-P)*(--cnstr) ]]
}

@test "calendar-based verification: without resources" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal
	[ "$status" -eq 3 ]
	[[ "$output" =~ (Task).*(Calendar-based verification)*(is invalid) ]]
	[[ "$output" =~ (You have to define flag).*(-X) ]]
}

@test "publication-based verification: without resources" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-pub
	[ "$status" -eq 3 ]
	[[ "$output" =~ "Maybe you want to: Publication-based verification" ]]
}

@test "calendar-based verification: HMAC failure and --continue-on-fail" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_102.tlv --ext-key Xanon --ext-user anon --continue-on-fail
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped" ]]
	[[ "$output" =~ "Error: HMAC mismatch" ]]
}

@test "calendar-based verification: not existing response from file and --continue-on-fail" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/thisfiledoesnotexist --ext-key plah --ext-user plah --continue-on-fail
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: Unable to open file." ]]
}

@test "calendar-based verification: unknown extender url and --continue-on-fail" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X http://this-extender-url-must-not-exist --ext-key plah --ext-user plah --continue-on-fail
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: Could not resolve host: this-extender-url-must-not-exist" ]]
}

@test "key-based verification: unknown publications file url and --continue-on-fail" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-key  --continue-on-fail -P http://this-pubfile-url-must-not-exist --cnstr "E=dummy.email@email.com"
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: Could not resolve host: this-pubfile-url-must-not-exist" ]]
}


# err_message
f_error_response_message () {
	echo "(Verifying... failed.)..( x Error: $1).( x Error: Signature calendar-based verification: .GEN-02. Verification inconclusive.).( x Error: Verification of block 1 KSI signature failed.).*(Error: Verification FAILED but was continued for further analysis.)"
}

@test "calendar-based verification: --continue-on-fail extender error 101" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_101.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The request had invalid format."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 102 (is stopped)" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_102.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Verifying... failed." ]]
	[[ "$output" =~ "Error: Verification FAILED and was stopped." ]]
	[[ "$output" =~ "Error: The request could not be authenticated" ]]
}

@test "calendar-based verification: --continue-on-fail extender error 103" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_103.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The request contained invalid payload."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 104" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_104.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The request asked for a hash chain going backwards in time."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 105" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_105.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The request asked for hash values older than the oldest round in the server's database."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 106" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_106.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The request asked for hash values newer than the newest round in the server's database."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 107" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_107.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The request asked for hash values newer than the current real time."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 200" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_200.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The server encountered an unspecified internal error."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 201" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_201.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The server misses the internal database needed to service the request."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 202" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_202.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The server's internal database is in an inconsistent state."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 300" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_300.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "The server encountered unspecified critical errors connecting to upstream servers."`) ]]
}

@test "calendar-based verification: --continue-on-fail extender error 301" {
	run src/logksi verify test/resource/logs_and_signatures/signed -d --ver-cal -X file://test/resource/server/ok_extender_error_response_301.tlv --ext-key anon --ext-user anon --continue-on-fail
	[ "$status" -eq 6 ]
	[[ "$output" =~ (`f_error_response_message "No response from upstream servers."`) ]]
}
