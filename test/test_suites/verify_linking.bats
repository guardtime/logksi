#!/bin/bash

export KSI_CONF=test/test.cfg

echo SHA-512:dd4e870e7e0c998f160688b97c7bdeef3d6d01b1c5f02db117018058ad51996777ae3dc8008d70b3e11c172b0049e8158571cea1b8a439593b67c41ebbe2b137 > test/out/input-hash.txt

@test "verify unsigned.logsig with input hash from command line." {
	run ./src/logksi verify test/out/unsigned -d --input-hash SHA-512:dd4e870e7e0c998f160688b97c7bdeef3d6d01b1c5f02db117018058ad51996777ae3dc8008d70b3e11c172b0049e8158571cea1b8a439593b67c41ebbe2b137
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok" ]]
}

@test "verify unsigned.logsig with input hash from file." {
	run ./src/logksi verify test/out/unsigned -d --input-hash test/out/input-hash.txt
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok" ]]
}

@test "verify unsigned.logsig output last leaf hash to file." {
	run ./src/logksi verify test/out/unsigned -d --output-hash test/out/output-hash.txt
	[ "$status" -eq 0 ]
	[[ "$output" =~ "Finalizing log signature... ok" ]]
	run cat test/out/output-hash.txt
	[[ "$output" =~ "SHA-512:7f5a178f581de2aed0d36739f908733643b316aac8bed0c9f89c040ad1d1e601ae8fd1ae1e177c2cdf9ebf59a2f43df00614893723d5019b6326b225bbcd7827" ]]
}

@test "verify unsigned.logsig output last leaf hash to stdout." {
	run ./src/logksi verify test/out/unsigned -d --output-hash -
	[ "$status" -eq 0 ]
	[[ "$output" =~ "SHA-512:7f5a178f581de2aed0d36739f908733643b316aac8bed0c9f89c040ad1d1e601ae8fd1ae1e177c2cdf9ebf59a2f43df00614893723d5019b6326b225bbcd7827" ]]
}

@test "verify unsigned.logsig with wrong input hash." {
	run ./src/logksi verify test/out/unsigned -d --input-hash SHA-512:dd4e870e7e0c998f160688b97c7bdeef3d6d01b1c5f02db117018058ad51996777ae3dc8008d70b3e11c172b0049e8158571cea1b8a439593b67c41ebbe2b138
	[ "$status" -eq 6 ]
	[[ "$output" =~ "Error: The last leaf from the previous block does not match with the current first block." ]]
}

@test "try to write excerpt signature output hash to stdout. It must fail." {
	run ./src/logksi verify test/out/extract.base.10.excerpt --output-hash -
	[[ "$output" =~ "Error: --output-hash does not work with excerpt signature file" ]]
}