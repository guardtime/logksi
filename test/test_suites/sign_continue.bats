#!/bin/bash

export KSI_CONF=test/test.cfg

@test "Sign unsigned.logsig and skip signing errors." {
	run ./src/logksi sign test/resource/logs_and_signatures/unsigned  -d --continue-on-fail -o test/out/unsigned-not-resigned-successfully.logsig -S dummy_url
	[ "$status" -eq 1 ]
	[[ "$output" =~ (Error: Signing FAILED but was continued. All failed blocks are left unsigned.)  ]]
	run test -f test/out/unsigned-not-resigned-successfully.logsig
	[ "$status" -eq 0 ]
	run diff test/resource/logs_and_signatures/unsigned.logsig test/out/unsigned-not-resigned-successfully.logsig
	[ "$status" -eq 0 ]
}

@test "Try to continue signing with a file that has 1 recored removed. It must fail and stop signing." {
	run ./src/logksi sign test/resource/continue-verification/log-line-4-removed -ddd --continue-on-fail -o test/out/dummy-signed.logsig
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Error: Block no. 2: root hashes not equal.)  ]]
	[[ ! "$output" =~ (Block no.   3)  ]]
	[[ ! "$output" =~ (Error: Signing FAILED but was continued. All failed blocks are left unsigned.)  ]]
	run test -f test/out/dummy-signed.logsig
	[ "$status" -ne 0 ]
}

@test "Try to continue signing with file that has 1 record modified. It must fail and stop signing." {
	run ./src/logksi sign test/resource/continue-verification/log-rec-4-changed -ddd --continue-on-fail -o test/out/dummy-signed.logsig
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Error: Block no. 2: root hashes not equal.)  ]]
	[[ ! "$output" =~ (Block no.   3)  ]]
	[[ ! "$output" =~ (Error: Signing FAILED but was continued. All failed blocks are left unsigned.)  ]]
	run test -f test/out/dummy-signed.logsig
	[ "$status" -ne 0 ]
}

@test "Try to continue signing with a file that has KSI signature replaced. It must fail and stop signing." {
	run ./src/logksi sign test/resource/continue-verification/log-sig-no2-wrong -ddd --continue-on-fail -o test/out/dummy-signed.logsig
	[ "$status" -eq 6 ]
	[[ "$output" =~ (Error: Block no. 2: root hashes not equal.)  ]]
	[[ ! "$output" =~ (Block no.   3)  ]]
	[[ ! "$output" =~ (Error: Signing FAILED but was continued. All failed blocks are left unsigned.)  ]]
	run test -f test/out/dummy-signed.logsig
	[ "$status" -ne 0 ]
}

@test "Try to continue signing in case of unexpected TLV 904.905.666. It must fail and stop signing." {
	run ./src/logksi sign test/resource/continue-verification/log-unknown-tlv-904.905.666 -ddd --continue-on-fail -o test/out/dummy-signed.logsig
	[ "$status" -eq 4 ]
	[[ "$output" =~ "Error: Block no. 2: unable to parse KSI signature"  ]]
	[[ ! "$output" =~ (Block no.   3)  ]]
	[[ ! "$output" =~ (Error: Signing FAILED but was continued. All failed blocks are left unsigned.)  ]]
	run test -f test/out/dummy-signed.logsig
	[ "$status" -ne 0 ]
}

@test "Try to continue signing in case of missing mandatory TLV 901.01. It must fail and stop signing." {
	run ./src/logksi sign test/resource/continue-verification/log-missing-tlv-901.01  -ddd --continue-on-fail -o test/out/dummy-signed.logsig
	[ "$status" -eq 4 ]
	[[ "$output" =~ "Block no.   1: processing block header... failed"  ]]
	[[ "$output" =~ "Error: Block no. 1: missing hash algorithm in block header"  ]]
	[[ ! "$output" =~ (Block no.   2)  ]]
	[[ ! "$output" =~ (Error: Signing FAILED but was continued. All failed blocks are left unsigned.)  ]]
	run test -f test/out/dummy-signed.logsig
	[ "$status" -ne 0 ]
}

@test "Try to continue signing in case of missing mandatory TLV 904.905. It must fail and stop signing." {
	run ./src/logksi sign test/resource/continue-verification/log-missing-tlv-904.905 -ddd --continue-on-fail -o test/out/dummy-signed.logsig
	[ "$status" -eq 4 ]
	[[ "$output" =~ "Block no.   1: processing partial signature data... failed."  ]]
	[[ "$output" =~ "Error: Block no. 1: block signature missing in signatures file."  ]]
	[[ ! "$output" =~ (Block no.   2)  ]]
	[[ ! "$output" =~ (Error: Signing FAILED but was continued. All failed blocks are left unsigned.)  ]]
	run test -f test/out/dummy-signed.logsig
	[ "$status" -ne 0 ]
}

@test "Try to continue signing in case of missing mandatory TLV 904.02. It must fail and stop signing." {
	run ./src/logksi sign test/resource/continue-verification/log-missing-tlv-911.02 -ddd --continue-on-fail -o test/out/dummy-signed.logsig
	[ "$status" -eq 1 ]
	[[ "$output" =~ "Block no.   4: {M X"  ]]
	[[ "$output" =~ "Error: Block no. 4: Unable to get TLV 911.02.01 (Meta record key)"  ]]
	[[ ! "$output" =~ (Block no.   4: processing block signature data... ok)  ]]
	[[ ! "$output" =~ (Error: Signing FAILED but was continued. All failed blocks are left unsigned.)  ]]
	run test -f test/out/dummy-signed.logsig
	[ "$status" -ne 0 ]
}