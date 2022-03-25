#!/bin/bash

@test "use conf with not supported ksi tool options" {
	run ./src/logksi verify --ver-int test/resource/logs_and_signatures/log_repaired -d --ignore-desc-block-time --conf test/resource/conf/ksi-tool-options.cfg
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Verifying... ok" ]]
}

