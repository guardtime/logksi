/*
 * Copyright 2013-2022 Guardtime, Inc.
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

#include "regexpwrap.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include "param_set/param_set.h"
#include "common.h"
#include <unistd.h>
#include <regex.h>

struct REGEXP_st {
	char *regexp;
	const char *string;
	const char *next;
	int match;

	/**
	 * Feed a string to abstract regexp processor.
	 * \param impl_ctx - regexp processor abstract implementation structure.
	 * \param string   - Original input string.
	 * \param next     - Pointer to the first character that is left out from the last group.
	 *                   Can be used to search multiple patterns in sequence.
	 * \return Returns \c REGEXP_OK or error code.
	 */
	int (*process_string)(void *impl_ctx, const char *string, const char **next);

	/**
	 * After the regexp matching is performed can be used to extract matched groups.
	 * The group with index 0 is the whole match. Matching values from index 1
	 * are all smaller matching groups.
	 * \param impl_ctx - regexp processor abstract implementation structure.
	 * \param string   - String to be searced.
	 * \param at       - The index of the matching group.
	 * \param buf      - The output buffer.
	 * \param buf_size - The size of the output buffer.
	 * \return Returns \c REGEXP_OK or error code.
	 */
	int (*get_group)(void *impl_ctx, const char *source, size_t at, char *buf, size_t buf_size);

	/**
	 * After the regexp matching is performed can be used to extract the count of
	 * matched groups. On successful processing the count is always >= 1.
	 * \param impl_ctx - regexp processor abstract implementation structure.
	 * \param string   - String to be searced.
	 * \param at       - The index of the matching group.
	 * \param buf      - The output buffer.
	 * \param buf_size - The size of the output buffer.
	 * \return Returns \c REGEXP_OK or error code.
	 */
	int (*get_group_count)(void *impl_ctx, size_t *buf_size);

	/**
	 * Is there a match?
	 * \return Returns 0 if there is no match or impl_ctx == NULL. If there is
	 * a match return 1.
	 */
	int (*is_match)(void *impl_ctx);

	void *impl_ctx;
	void (*impl_ctx_free)(void*);
};

typedef struct GNU_REGEX_WRAPPER_st {
	size_t max_group_count;
	regex_t regexp_obj;
	regmatch_t *groups;
	int free_reg_match;
} GNU_REGEX_WRAPPER;

static void gnu_regex_wrapper_free(void *obj) {
	GNU_REGEX_WRAPPER *ctx = obj;
	if (ctx == NULL) return;
	if (ctx->free_reg_match) regfree(&ctx->regexp_obj);
	if (ctx->groups != NULL) free(ctx->groups);
	free(obj);
}

static int gnu_regex_wrapper_new(const char *pattern, size_t max_group_count, void **obj) {
	int res;
	GNU_REGEX_WRAPPER *tmp = NULL;

	if (max_group_count == 0 || obj == NULL) {
		res = REGEXP_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (GNU_REGEX_WRAPPER*)malloc(sizeof(GNU_REGEX_WRAPPER));
	if (tmp == NULL) {
		res = REGEXP_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Initialize the helper data structure. */
	tmp->free_reg_match = 0;
	tmp->groups = NULL;
	tmp->max_group_count = max_group_count;
	tmp->groups = (regmatch_t*)calloc(max_group_count, sizeof(regmatch_t));

	/* Parse the regexp string. */
	if (regcomp(&tmp->regexp_obj, pattern, REG_EXTENDED) != 0) {
		res = REGEXP_INVALID_PATTER;
		goto cleanup;
	}

	tmp->free_reg_match = 1;

	*obj = tmp;
	tmp = NULL;
	res = REGEXP_OK;

cleanup:

	gnu_regex_wrapper_free(tmp);

	return res;
}

static int gnu_regex_wrapper_process_string(void *impl_ctx, const char *string, const char **next) {
	int res;
	int res_regex;
	GNU_REGEX_WRAPPER *regexp = impl_ctx;
	size_t offset = 0;

	if (impl_ctx == NULL || string == NULL) {
		res = REGEXP_INVALID_ARGUMENT;
		goto cleanup;
	}

	// int regexec(const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags);
    if ((res_regex = regexec(&regexp->regexp_obj, string, regexp->max_group_count, regexp->groups, 0)) != 0) {
		res = (res_regex == REG_NOMATCH) ? REGEXP_NO_MATCH : REGEXP_UNKNOWN_ERROR;
		goto cleanup;
	}

	if (next != NULL) {
		offset = regexp->groups[0].rm_eo;
		*next = string + offset;
	}

	res = REGEXP_OK;

cleanup:
	return res;
}

static int gnu_regex_wrapper_get_group(void *impl_ctx, const char *source, size_t at, char *buf, size_t buf_size) {
	GNU_REGEX_WRAPPER *regexp = impl_ctx;
	int res;
	size_t to_be_copied = 0;

	if (impl_ctx == NULL || buf == NULL || buf_size == 0) {
		res = REGEXP_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (at >= regexp->max_group_count) {
		res = REGEXP_INDEX_OVF;
		goto cleanup;
	}

	/* If start of string is "out of range" it is the end. */
	if (regexp->groups[at].rm_so == ((size_t)-1)) {
		res = REGEXP_END;
		goto cleanup;
	}

	/* Add offset to original string and copy the string in specified len. */
	to_be_copied = regexp->groups[at].rm_eo - regexp->groups[at].rm_so;
	if (to_be_copied + 1 > buf_size) {
		res = REGEXP_BUF_TOO_SMALL;
		goto cleanup;
	}

	 /* Copy and add NUL character to the end of the string (to be extra sure). */
	strncpy(buf, source + regexp->groups[at].rm_so, to_be_copied);
	buf[to_be_copied] = '\0';

	res = REGEXP_OK;

cleanup:

	return res;
}

static int gnu_regex_wrapper_get_group_count(void *impl_ctx, size_t *count) {
	int res;
	GNU_REGEX_WRAPPER *regexp = impl_ctx;
	size_t i = 0;

	if (impl_ctx == NULL || count == NULL) {
		res = REGEXP_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* If start of string is "out of range" it is the end. */
	while (i < regexp->max_group_count) {
		if (regexp->groups[i].rm_so == ((size_t)-1)) {
			break;
		}
		i++;
	}

	*count = i;
	res = REGEXP_OK;

cleanup:

	return res;
}

static int gnu_regex_wrapper_is_match(void *impl_ctx) {
	GNU_REGEX_WRAPPER *regexp = impl_ctx;
	if (impl_ctx == NULL) return -0;

	if (regexp->groups[0].rm_so == ((size_t)-1)) {
		return 0;
	} else {
		return 1;
	}
}

const char* REGEXP_errToString(int err) {
	switch(err) {
		case REGEXP_OK:
			return "OK";
		case REGEXP_INVALID_ARGUMENT:
			return "Regexp Invalid Argument";
		case REGEXP_OUT_OF_MEMORY:
			return "Regexp out of memory";
		case REGEXP_INVALID_PATTER:
			return "Regexp invalid pattern";
		case REGEXP_INDEX_OVF:
			return "Regexp index too large";
		case REGEXP_BUF_TOO_SMALL:
			return "Regexp buffer too small";
		case REGEXP_NO_MATCH:
			return "Regexp no match";
		case REGEXP_NO_PATTERN:
			return "Regexp has no pattern";
		case REGEXP_END:
			return "Regexp end";
		case REGEXP_UNIMPLEMENTED:
			return "Regexp has no implementation";
		case REGEXP_GROUP_NOT_FOUND:
			return "Regexp group not found";
		case REGEXP_UNDEFINED_BEHAVIOUR:
			return "Regexp undefined behaviour";
		case REGEXP_HAS_NO_INPUT_STRING:
			return "Regexp has no input string";
		case REGEXP_UNKNOWN_ERROR:
		default:
			return "Regexp unknown error";
	};
}

void REGEXP_free(REGEXP *obj) {
	if (obj == NULL) return;

	if (obj->impl_ctx != NULL && obj->impl_ctx_free != NULL) {
		obj->impl_ctx_free(obj->impl_ctx);
	}

	if (obj->regexp != NULL ) free(obj->regexp);
	free(obj);
	return;
}

int REGEXP_new(const char *pattern, REGEXP **obj) {
	int res;
	REGEXP *tmp = NULL;
	void *ctx = NULL;
	char *pattern_copy = NULL;
	size_t pattern_size;

	if (pattern == NULL || obj == NULL) {
		res = REGEXP_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Initialize REGEXP obj. */
	tmp = (REGEXP*)malloc(sizeof(REGEXP));
	if (tmp == NULL) {
		res = REGEXP_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->impl_ctx = NULL;
	tmp->impl_ctx_free = NULL;
	tmp->process_string = NULL;
	tmp->get_group = NULL;
	tmp->is_match = NULL;
	tmp->string = NULL;
	tmp->regexp = NULL;
	tmp->match = 0;
	tmp->next = 0;

	pattern_size = strlen(pattern);
	pattern_copy = (char*)malloc(sizeof(char) * (pattern_size + 1));
	if (pattern_copy == NULL) {
		res = REGEXP_OUT_OF_MEMORY;
		goto cleanup;
	}

	strcpy(pattern_copy, pattern);
	tmp->regexp = pattern_copy;
	pattern_copy = NULL;

	/* Add the implementation. */
	res = gnu_regex_wrapper_new(pattern, 32, &ctx);
	if (res != REGEXP_OK) goto cleanup;

	tmp->process_string = gnu_regex_wrapper_process_string;
	tmp->get_group = gnu_regex_wrapper_get_group;
	tmp->get_group_count = gnu_regex_wrapper_get_group_count;
	tmp->is_match = gnu_regex_wrapper_is_match;
	tmp->impl_ctx_free = gnu_regex_wrapper_free;

	tmp->impl_ctx = ctx;
	ctx = NULL;

	/* Return the initialized regexp obj ready for processing strings. */
	*obj = tmp;
	tmp = NULL;
	res = REGEXP_OK;

cleanup:

	gnu_regex_wrapper_free(ctx);

	free(pattern_copy);
	REGEXP_free(tmp);

	return res;
}

int REGEXP_processString(REGEXP *obj, const char *string, const char **next) {
	int res;
	const char *tmp_next = NULL;

	if (obj == NULL) {
		res = REGEXP_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (obj->impl_ctx == NULL || obj->process_string == NULL || obj->is_match == NULL) {
		res = REGEXP_UNIMPLEMENTED;
		goto cleanup;
	}

	/* Set NO regexp match before processing. */
	obj->match = 0;
	if (string != NULL) {
		obj->next = NULL;
		obj->string = NULL;

		res = obj->process_string(obj->impl_ctx, string, &tmp_next);
		if (res != REGEXP_OK) goto cleanup;

		obj->string = string;
	} else {
		res = obj->process_string(obj->impl_ctx, obj->next, &tmp_next);
		if (res != REGEXP_OK) goto cleanup;

		obj->string = obj->next;
	}

	obj->next = tmp_next;

	obj->match = obj->is_match(obj->impl_ctx);
	if (!obj->match) {
		res = REGEXP_NO_MATCH;
		goto cleanup;
	}

	if (next != NULL) {
		*next = tmp_next;
	}

cleanup:

	return res;
}

int REGEXP_getMatchingGroup(REGEXP *obj, size_t at, char *buf, size_t buf_len) {
	int res;

	if (obj == NULL || buf == NULL || buf_len == 0) {
		res = REGEXP_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (obj->impl_ctx == NULL || obj->get_group == NULL) {
		res = REGEXP_UNIMPLEMENTED;
		goto cleanup;
	}

	if (obj->string == NULL) {
		res = REGEXP_HAS_NO_INPUT_STRING;
		goto cleanup;
	}

	if (obj->match == 0) {
		res = REGEXP_NO_MATCH;
		goto cleanup;
	}

	res = obj->get_group(obj->impl_ctx, obj->string, at, buf, buf_len);
	if (res != REGEXP_OK) goto cleanup;

cleanup:

	return res;
}

int REGEXP_getMatchingGroupCount(REGEXP *obj, size_t *count) {
	int res;
	size_t tmp = 0;

	if (obj == NULL || count == NULL) {
		res = REGEXP_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (obj->impl_ctx == NULL || obj->get_group == NULL) {
		res = REGEXP_UNIMPLEMENTED;
		goto cleanup;
	}

	if (obj->string == NULL) {
		res = REGEXP_HAS_NO_INPUT_STRING;
		goto cleanup;
	}

	if (obj->match == 0) {
		res = REGEXP_NO_MATCH;
		goto cleanup;
	}

	res = obj->get_group_count(obj->impl_ctx, &tmp);
	if (res != REGEXP_OK) goto cleanup;

	*count = tmp;

cleanup:

	return res;
}

const char* REGEXP_getPattern(REGEXP *obj) {
	if (obj == NULL) return NULL;
	return obj->regexp;
}