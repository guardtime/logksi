# KSI log signature command-line tool TEST-README

This document will describe how to properly configure and run the KSI log signature command-line tool tests. Also the dependencies and brief overview of files related to the tests will be described.


## DEPENDENCIES

* [bats](https://github.com/sstephenson/bats) - Mandatory for every test.


## TEST RELATED FILES

All files related to the tests can be found from directory `test` that is located in KSI log signature command-line tool root directory.

```
 resource         - directory containing all test resource files
                    (e.g. signatures, files to be signed, server responses);
 test_suites      - directory containing all test suites;
 test.cfg.sample  - sample of the configuration file you must create to run tests;
 TEST-README      - the document you are reading right now;
 test.sh          - use to run tests.
```


## CONFIGURING TESTS

To configure tests a configuration file must be specified with valid publications file, aggregator and extender URLs with corresponding access credentials. See `test.cfg.sample` and read `logksi conf -h` or `man logksi-conf` for instructions. The file must be located in the `test` directory.


## RUNNING TESTS

Tests must be run from KSI log signature command-line tool root directory and the output is generated to `test/out`. Tests must be run by corresponding test script found from test folder to ensure that test environment is configured properly. The exit code is `0` on success and `1` on failure.

To run tests on RHEL/CentOS:
```
test/test.sh
```
