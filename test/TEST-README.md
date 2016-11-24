# KSI COMMAND-LINE TOOL TEST README

 This document will describe how to configure and run the KSI command-line tool
 tests properly. Also the dependences and brief overview of files related to the
 tests will be described.

 Tests can be run with KSI built within the project or with KSI installed on the
 machine. On unix platforms KSI binary file is located in `src` and on Windoes
 in `bin` directory. If the platform specific binary exists the tests are run
 with the corresponding binary, otherwise the installed binary is used.


## DEPENDECES

 * shelltestrunner - Mandatory for every test.
 * valgrind - For memory tests only, unix.
 * gttlvutil - When available extra tests for metadata and masking are performed.


## TEST RELATED FILES

 All files related to the tests can be found from directory `test` that is
 located in KSI comman-line root directory.

```
 resource         - directory containing all test resource files
                    (e.g. signatures, files to be signed, server responses).
 test_suites      - directory containing all test suites.
 
 test.cfg.sample  - sample configurations file that is needed to run tests.
 TEST-README      - You are reading it right now.
 convert-to-memory-test.sh 
                  - helper scrip that converts regular test to valgrind
                    memory test (unix only). Should not be called by the user.
                    Is used by memory-test.sh internally.
 windows-test.bat - run tests on windows platform.
 test.sh          - run tests on unix platform.
 memory-test.sh   - run valgrind memory tests.
```

## CONFIGURING TESTS

 To configure tests a configuration file must be specified with valid
 publications file, aggregator and extender URL's with corresponding access
 credentials. See `test.cfg.sample` and read `ksi conf -h` or `man conf`
 to learn how to write the KSI configurations file. The file must be located
 in `test` directory.
 
 
## RUNNING TESTS

 Tests must be run from KSI comman-line root directory and the output is
 generated to `test/out`. Tests must be run by corresponding test script
 found from test folder to ensure that test environment is configured
 properly. The exit code is `0` on success and `1` on failure.
 
 To run tests on windows call:
```
    test\windows-test.bat
```
 To run tests on centos:
```
    test/test.sh
    test/memory-test.sh
```