/*
 * Copyright 2013-2019 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#ifndef REGEXPWRAP_H
#define	REGEXPWRAP_H

#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct REGEXP_st REGEXP;
#define REGEXP_ERR_BASE 0x050001

enum {
	REGEXP_OK = 0x00,
	REGEXP_INVALID_ARGUMENT = REGEXP_ERR_BASE,
	REGEXP_OUT_OF_MEMORY,
	REGEXP_INVALID_PATTER,
	REGEXP_INDEX_OVF,
	REGEXP_BUF_TOO_SMALL,
	REGEXP_NO_MATCH,
	REGEXP_NO_PATTERN,
	REGEXP_END,
	REGEXP_UNIMPLEMENTED,
	REGEXP_HAS_NO_INPUT_STRING,
	REGEXP_UNDEFINED_BEHAVIOUR,
	REGEXP_GROUP_NOT_FOUND,
	REGEXP_UNKNOWN_ERROR,
};

/**
 * Create a new regular expression object with the specified pattern. See \ref
 * REGEXP_processString to parse a string with the regular expression processor.
 *
 * \param pattern - Pattern of regular expression.
 * \param obj     - Returned regular expression processor.
 * \return REGEXP_OK if successful, error code otherwise.
 */
int REGEXP_new(const char *pattern, REGEXP **obj);

/**
 * Free the regular expression object.
 * \param obj     - Regular expression processor to be freed.
 */
void REGEXP_free(REGEXP *obj);

/**
 * Parse a string with the regular expression processor and predefined pattern.
 * See \ref REGEXP_new to create a new processor with different pattern. After
 * successful call \ref REGEXP_getMatchingGroup can be used to extract matching
 * substrings (groups). If output parameter \c next is set, the first string
 * after pattern is returned. If the there are multiple sequential occurrences
 * of the pattern, the function can be called multiple times to walk through the
 * entire string. The next call may use the string as NULL to continue searching
 * the next match or output parameters \c next value from previous call can be used
 * as \c strng.
 * string as NULL
 * \param obj     - Regular expression processor to be used.
 * \param string  - String to be parsed.
 * \param next    - The pointer should point to the next character after the match.
 * \return REGEXP_OK if successful, error code otherwise.
 */
int REGEXP_processString(REGEXP *obj, const char *string, const char **next);

/**
 * After successful call of function \ref REGEXP_processString this function can
 * be used to extract the matching substrings. At index 0, the full match is
 * returned. With index > 0 the sub groups are returned.
 *
 * For example:
 *   pattern == "v([0-9]{1,2})[.]([0-9]{1,2})"
 *   string == "Version: v1.12"
 *   match[0] == "v1.12"
 *   match[1] == "1"
 *   match[2] == "12"
 *
 *
 * \param obj     - Regular expression processor.
 * \param at      - The index of the substring.
 * \param buf     - The buffer for output value.
 * \param buf_len - The size of the buffer.
 * \return REGEXP_OK if successful, error code otherwise.
 */
int REGEXP_getMatchingGroup(REGEXP *obj, size_t at, char *buf, size_t buf_len);

int REGEXP_getMatchingGroupCount(REGEXP *obj, size_t *count);

const char* REGEXP_getPattern(REGEXP *obj);

const char* REGEXP_errToString(int err);

#ifdef	__cplusplus
}
#endif

#endif	/* REGEXPWRAP_H */

