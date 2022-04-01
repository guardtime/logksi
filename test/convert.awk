#!/bin/awk -f

#
# Copyright 2022 Guardtime, Inc.
#
# This file is part of the Guardtime client SDK.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime, Inc., and no license to trademarks is granted; Guardtime
# reserves and retains all trademark rights.


# This file is awk script to transform regular bats test to memory test
# using valgrind. Special annotations can be applied to change how the
# original test is transformed. Annotations are set right before the test
# case and it must start with # (comment).
#
#  # <Annotation>
#  @test "Test description" {
#  ...
#  }
#
# Supported annotations:
#   # @SKIP_MEMORY_TEST              - skip entire test.
#   # @NOT_MODIFIED_BY_MEMORY_TEST   - do not change the test but run it as it is.


BEGIN {
	leftOut = 0
	hasOutput = 0
	isTestOpened = 0
	isSkipping = 0
	isNotModified = 0
	isRunOnMultipleLines = 0
}

{
	# Handle annotations.
	if (!isTestOpened && !isSkipping &&
	   ((NF == 1 && $1 == "#@SKIP_MEMORY_TEST") ||
	   (NF == 2 && $1 == "#" && $2 == "@SKIP_MEMORY_TEST"))) {
		isSkipping = 1;
		print
	}

	if (!isTestOpened && !isNotModified &&
	   ((NF == 1 && $1 == "#@NOT_MODIFIED_BY_MEMORY_TEST") ||
	   (NF == 2 && $1 == "#" && $2 == "@NOT_MODIFIED_BY_MEMORY_TEST"))) {
		isNotModified = 1;
	}

	if (isNotModified) {
		print
	}

	if ($1 == "@test" && !isNotModified) {
		if (!isSkipping) {
			leftOut = 0;
			hasOutput = 0;
			isTestOpened = 1;
			print
		} else {
			printf("# ")
			print
			print "# }"
		}
	}

	if (isTestOpened) {
		if ($1 == "run" && $2 == "bash") {
			leftOut = 1;
		} else if (($1 == "run" && $2 != "bash") || isRunOnMultipleLines) {
			leftOut = 0;
			hasOutput = 0;

			if (!isRunOnMultipleLines) {
				printf("\trun valgrind --leak-check=full --fair-sched=yes ");
				for (i = 1; i < NF; i++) {
					printf(" %s", $(i+1));
				}
				print ""

				if ($(NF) == "\\") {
					isRunOnMultipleLines = 1
				}
			} else {
				if ($(NF) != "\\") {
					isRunOnMultipleLines = 0
				}
				print
			}
		} else if (!leftOut && $1 == "[" && $2 == "\"$status\"") {
			print
		} else if (!leftOut && !hasOutput && $1 == "[[" && $2 == "\"$output\"") {
			print "\t[[ \"$output\" =~ (definitely lost. 0 bytes in 0 blocks.*indirectly lost: 0 bytes in 0 blocks.*possibly lost: 0 bytes in 0 blocks)|(All heap blocks were freed -- no leaks are possible) ]]"
			hasOutput = 1;
		} else if (NF == 1 && $1 == "}") {
			print "}\n"
			isTestOpened = 0;
		} else {
			;
		}
	} else if (isSkipping || isNotModified) {
		if (NF == 1 && $1 == "}") {
			isSkipping = 0;
			isNotModified = 0;
		}
	} else {
		print
	}
}

END {;}