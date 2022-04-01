#!/bin/bash

export KSI_CONF=test/test-not-existing.cfg

@test "Try to use conf file that does not exist." {
	run ./src/logksi verify --ver-int test/resource/logs_and_signatures/log_repaired --ignore-desc-block-time
	[ "$status" -eq 0 ]
	[[ "$output" =~ .*(Configuration file).*(test.not-existing.cfg).*(pointed to by KSI_CONF does not exist).* ]]
}

