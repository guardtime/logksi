#!/bin/bash

rm -rf test/out
mkdir test/out

bats test/test_suites/integrate.bats test/test_suites/verify.bats test/test_suites/sign.bats

exit_code=$?

exit $exit_code
