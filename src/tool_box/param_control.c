/*
 * Copyright 2013-2016 Guardtime, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include "tool_box.h"
#include "err_trckr.h"
#include "tool_box/param_control.h"
#include "param_set/param_value.h"
#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "smart_file.h"
#include "obj_printer.h"
#include "api_wrapper.h"
#include "common.h"
#include "param_set/strn.h"
#include "debug_print.h"
#include "param_set/parameter.h"

static int x(char c){
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	abort(); // isxdigit lies.
	return -1; // makes compiler happy
}

static int xx(char c1, char c2){
	if (!isxdigit(c1) || !isxdigit(c2))
		return -1;
	return x(c1) * 16 + x(c2);
}

static int hex_string_to_bin(const char *hexin, unsigned char *buf, size_t buf_len, size_t *lenout){
	int res;
	size_t len;
	size_t arraySize;
	unsigned int i, j;
	int tmp;

	if (hexin == NULL || buf == NULL || lenout == NULL || buf_len == 0) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	len = strlen(hexin);
	arraySize = len / 2;

	if (len%2 != 0) {
		res = KT_HASH_LENGTH_IS_NOT_EVEN;
		goto cleanup;
	}

	for (i = 0, j = 0; i < arraySize; i++, j += 2){
		tmp = xx(hexin[j], hexin[j+1]);
		if (tmp == -1) {
			res = KT_INVALID_HEX_CHAR;
			goto cleanup;
		}

		if (i < buf_len) {
			buf[i] = (unsigned char)tmp;
		} else {
			res = KT_INDEX_OVF;
			goto cleanup;
		}
	}

	*lenout = arraySize;
	res = KT_OK;

cleanup:

	return res;
}

int isFormatOk_hex(const char *hexin){
	size_t len;
	size_t arraySize;
	unsigned int i, j;
	int tmp;

	if (hexin == NULL) return FORMAT_NULLPTR;
	if (*hexin == '\0') return FORMAT_NOCONTENT;

	len = strlen(hexin);
	arraySize = len / 2;

	if (len%2 != 0) return FORMAT_ODD_NUMBER_OF_HEX_CHARACTERS;

	for (i = 0, j = 0; i < arraySize; i++, j += 2){
		tmp = xx(hexin[j], hexin[j+1]);

		if (tmp == -1) return FORMAT_INVALID_HEX_CHAR;
	}

	return FORMAT_OK;
}

int extract_OctetString(void *extra, const char* str, void** obj) {
	int res;
	void **extra_array = (void**)extra;
	COMPOSITE *comp = NULL;
	KSI_CTX *ctx = NULL;
	KSI_OctetString *tmp = NULL;
	unsigned char binary[0xffff];
	size_t binary_len = 0;

	comp = (COMPOSITE*)extra_array[1];
	ctx = comp->ctx;

	res = hex_string_to_bin(str, binary, sizeof(binary), &binary_len);
	if (res != KT_OK && res != KT_INDEX_OVF) goto cleanup;

	res = KSI_OctetString_new(ctx, binary, binary_len, &tmp);
	if (res != KT_OK) goto cleanup;

	*obj = (void*)tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_OctetString_free(tmp);

	return res;
}

static int date_is_valid(struct tm *time_st) {
	int days = 31;
	int dd = time_st->tm_mday;
	int mm = time_st->tm_mon + 1;
	int yy = time_st->tm_year + 1900;

	if (mm < 1 || mm > 12 || dd < 1 || yy < 2007 || yy >= 2036) {
		return 0;
	}

	if (mm == 2) {
		days = 28;
		/* Its a leap year */
		if (yy % 400 == 0 || (yy % 4 == 0 && yy % 100 != 0)) {
			days = 29;
		}
	} else if (mm == 4 || mm == 6 || mm == 9 || mm == 11) {
		days = 30;
	}

	if (dd > days) {
		return 0;
	}
	return 1;
}

static int string_to_tm(const char *time, struct tm *time_st) {
	const char *ret = NULL;
	const char *next = NULL;
	/* If its not possible to convert date string with such a buffer, there is something wrong! */
	char buf[1024];

	if (time == NULL || time_st == NULL) return FORMAT_NULLPTR;

	memset(time_st, 0, sizeof(struct tm));


	next = time;
	ret = STRING_extractAbstract(next, NULL, "-", buf, sizeof(buf), NULL, find_charBeforeStrn, &next);
	if (ret != buf || next == NULL || *buf == '\0' || strlen(buf) > 4 || isFormatOk_int(buf) != FORMAT_OK) return FORMAT_INVALID_UTC;
	time_st->tm_year = atoi(buf) - 1900;

	ret = STRING_extractAbstract(next, "-", "-", buf, sizeof(buf), find_charAfterStrn, find_charBeforeLastStrn, &next);
	if (ret != buf || next == NULL || strlen(buf) > 2 || isFormatOk_int(buf) != FORMAT_OK) return FORMAT_INVALID_UTC;
	time_st->tm_mon = atoi(buf) - 1;

	ret = STRING_extractAbstract(next, "-", " ", buf, sizeof(buf), find_charAfterStrn, find_charBeforeLastStrn, &next);
	if (ret != buf || next == NULL || strlen(buf) > 2 || isFormatOk_int(buf) != FORMAT_OK) return FORMAT_INVALID_UTC;
	time_st->tm_mday = atoi(buf);

	if (date_is_valid(time_st) == 0) return FORMAT_INVALID_UTC_OUT_OF_RANGE;

	ret = STRING_extractAbstract(next, " ", ":", buf, sizeof(buf), find_charAfterStrn, find_charBeforeStrn, &next);
	if (ret != buf || next == NULL || *buf == '\0' || strlen(buf) > 2 || isFormatOk_int(buf) != FORMAT_OK) return FORMAT_INVALID_UTC;
	time_st->tm_hour = atoi(buf);
	if (time_st->tm_hour < 0 || time_st->tm_hour > 23) return FORMAT_INVALID_UTC_OUT_OF_RANGE;

	ret = STRING_extractAbstract(next, ":", ":", buf, sizeof(buf), find_charAfterStrn, find_charBeforeLastStrn, &next);
	if (ret != buf || next == NULL || strlen(buf) > 2 || isFormatOk_int(buf) != FORMAT_OK) return FORMAT_INVALID_UTC;
	time_st->tm_min = atoi(buf);
	if (time_st->tm_min < 0 || time_st->tm_min > 59) return FORMAT_INVALID_UTC_OUT_OF_RANGE;

	ret = STRING_extractAbstract(next, ":", NULL, buf, sizeof(buf), find_charAfterStrn, find_charBeforeLastStrn, &next);
	if (ret != buf || strlen(buf) > 2 || isFormatOk_int(buf) != FORMAT_OK) return FORMAT_INVALID_UTC;
	time_st->tm_sec = atoi(buf);
	if (time_st->tm_sec < 0 || time_st->tm_sec > 59) return FORMAT_INVALID_UTC_OUT_OF_RANGE;

	return FORMAT_OK;
}

static int convert_UTC_to_UNIX2(const char* arg, time_t *time) {
	int res;
	struct tm time_st;
	time_t t;

	if (arg == NULL || time == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (string_to_tm(arg, &time_st) != FORMAT_OK) {
		res = KT_INVALID_INPUT_FORMAT;
		goto cleanup;
	}

	t = KSI_CalendarTimeToUnixTime(&time_st);
	if (t == -1) {
		res = KT_INVALID_INPUT_FORMAT;
		goto cleanup;
	}

	*time = t;
	res = KT_OK;

cleanup:

	return res;
}

int isInteger(const char *str) {
	int i = 0;
	int C;
	if (str == NULL) return 0;
	if (str[0] == '\0') return 0;

	while ((C = 0xff & str[i++]) != '\0') {
		if (!isdigit(C)) return 0;
	}
	return 1;
}

int isFormatOk_url(const char *url) {
	if (url == NULL) return FORMAT_NULLPTR;
	if (strlen(url) == 0) return FORMAT_NOCONTENT;

	if (strstr(url, "ksi://") == url)
		return FORMAT_OK;
	else if (strstr(url, "http://") == url || strstr(url, "ksi+http://") == url)
		return FORMAT_OK;
	else if (strstr(url, "https://") == url || strstr(url, "ksi+https://") == url)
		return FORMAT_OK;
	else if (strstr(url, "ksi+tcp://") == url)
		return FORMAT_OK;
	else if (strstr(url, "file://") == url)
		return FORMAT_OK;
	else
		return FORMAT_URL_UNKNOWN_SCHEME;
}

int convertRepair_url(const char* arg, char* buf, unsigned len) {
	char *scheme = NULL;
	unsigned i = 0;
	int isFile;

	if (arg == NULL || buf == NULL) return 0;
	scheme = strstr(arg, "://");
	isFile = (strstr(arg, "file://") == arg);

	if (scheme == NULL) {
		KSI_strncpy(buf, "http://", len-1);
		if (strlen(buf)+strlen(arg) < len)
			strcat(buf, arg);
		else
			return 0;
	} else {
		while (arg[i] && i < len - 1) {
			if (&arg[i] < scheme) {
				buf[i] = (char)tolower(arg[i]);
				VARIABLE_IS_NOT_USED(isFile);
			} else {
				buf[i] = arg[i];
			}

			i++;
		}
		buf[i] = 0;
	}
	return 1;
}


int isFormatOk_int(const char *integer) {
	int i = 0;
	int C;
	if (integer == NULL) return FORMAT_NULLPTR;
	if (strlen(integer) == 0) return FORMAT_NOCONTENT;

	while ((C = integer[i++]) != '\0') {
		if ((i - 1 == 0 && C != '-' && !isdigit(C)) ||
			(i - 1 > 0 && !isdigit(C))) {
			return FORMAT_NOT_INTEGER;
		}
	}
	return FORMAT_OK;
}

int isFormatOk_int_can_be_null(const char *integer) {
	if (integer == NULL) return FORMAT_OK;
	else return isFormatOk_int(integer);
}

static int isContentOk_int_limits(const char* integer, int no_zero, int not_negative) {
	long tmp;

	if (integer == NULL) return FORMAT_NULLPTR;
	if (integer[0] == '\0') return FORMAT_NOCONTENT;

	tmp = strtol(integer, NULL, 10);
	if (no_zero && tmp == 0) return INTEGER_TOO_SMALL;
	if (not_negative && tmp < 0) return INTEGER_UNSIGNED;
	if (tmp > INT_MAX) return INTEGER_TOO_LARGE;

	return PARAM_OK;
}

int isContentOk_uint(const char* integer) {
	return isContentOk_int_limits(integer, 0,1);
}

int isContentOk_uint_not_zero(const char* integer) {
	return isContentOk_int_limits(integer, 1,1);
}

int isContentOk_uint_can_be_null(const char *integer) {
	if (integer == NULL) return FORMAT_OK;
	else return isContentOk_uint(integer);
}

int isContentOk_int(const char* integer) {
	long tmp;

	if (integer == NULL) return FORMAT_NULLPTR;
	if (integer[0] == '\0') return FORMAT_NOCONTENT;

	tmp = strtol(integer, NULL, 10);
	if (tmp < INT_MIN) return INTEGER_TOO_SMALL;
	if (tmp > INT_MAX) return INTEGER_TOO_LARGE;

	return PARAM_OK;
}

int extract_int(void *extra, const char* str,  void** obj){
	long tmp;
	int *pI = (int*)obj;
	VARIABLE_IS_NOT_USED(extra);
	tmp = strtol(str, NULL, 10);
	if (tmp < INT_MIN || tmp > INT_MAX) return KT_INVALID_CMD_PARAM;
	*pI = (int)tmp;
	return PST_OK;
}

int isFormatOk_inputFile(const char *path){
	if (path == NULL) return FORMAT_NULLPTR;
	if (strlen(path) == 0) return FORMAT_NOCONTENT;
	return FORMAT_OK;
}

int isContentOk_inputFile(const char* path){
	if (isFormatOk_inputFile(path) != FORMAT_OK) {
		return FILE_INVALID_PATH;
	}

	if (!SMART_FILE_doFileExist(path)) {
		return FILE_DOES_NOT_EXIST;
	}

	if (!SMART_FILE_isReadAccess(path)) {
		return FILE_ACCESS_DENIED;
	}

	return PARAM_OK;
}

int isContentOk_inputFileWithPipe(const char* path){
	if (path == NULL) return FORMAT_NULLPTR;
	if (strcmp(path, "-") == 0)	return PARAM_OK;
	return isContentOk_inputFile(path);
}

int isContentOk_inputFileRestrictPipe(const char* path){
	if (path == NULL) return FORMAT_NULLPTR;
	if (strcmp(path, "-") == 0)	return ONLY_REGULAR_FILES;
	return isContentOk_inputFile(path);
}

int convertRepair_path(const char* arg, char* buf, unsigned len){
	char *toBeReplaced = NULL;

	if (arg == NULL || buf == NULL) return 0;
	KSI_strncpy(buf, arg, len - 1);


	toBeReplaced = buf;
	while ((toBeReplaced = strchr(toBeReplaced, '\\')) != NULL){
		*toBeReplaced = '/';
		toBeReplaced++;
	}

	return 1;
}

int isFormatOk_path(const char *path) {
	if (path == NULL) return FORMAT_NULLPTR;
	if (path[0] == '\0') return FORMAT_NOCONTENT;
	return FORMAT_OK;
}

int isFormatOk_pubString(const char *str) {
	int C;
	int i = 0;
	const char base32EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567-";

	if (str == NULL) return FORMAT_NULLPTR;
	if (str[0] == '\0') return FORMAT_NOCONTENT;

	while ((C = 0xff & str[i++]) != '\0') {
		if (strchr(base32EncodeTable, C) == NULL) {
			return FORMAT_INVALID_BASE32_CHAR;
		}
	}
	return FORMAT_OK;
}

int extract_pubString(void *extra, const char* str, void** obj) {
	int res;
	void **extra_array = extra;
	COMPOSITE *comp = (COMPOSITE*)(extra_array[1]);
	KSI_CTX *ctx = comp->ctx;
	ERR_TRCKR *err = comp->err;
	KSI_PublicationData *tmp = NULL;

	if (obj == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_PublicationData_fromBase32(ctx, str, &tmp);
	ERR_CATCH_MSG(err, res, "Error: Unable parse publication string.");

	*obj = (void*)tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_PublicationData_free(tmp);

	return res;
}


int isFormatOk_timeString(const char *time) {
	struct tm time_st;
	return string_to_tm(time, &time_st);
}

int isFormatOk_utcTime(const char *time) {
	if (isInteger(time)) {
		return isFormatOk_int(time);
	} else {
		return isFormatOk_timeString(time);
	}
}

int isContentOk_utcTime(const char *time) {
	if (isInteger(time)) {
		return isContentOk_uint(time);
	} else {
		return PARAM_OK;
	}
}

int extract_utcTime(void *extra, const char* str, void** obj) {
	int res;
	void **extra_array = extra;
	COMPOSITE *comp = (COMPOSITE*)(extra_array[1]);
	KSI_CTX *ctx = NULL;
	ERR_TRCKR *err = NULL;
	KSI_Integer *tmp = NULL;
	int time = 0;

	if (obj == NULL || comp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* TODO: make all extractors to not fail if comp is NULL */
	ctx = comp->ctx;
	err = comp->err;

	/**
	 * If input is integer, extract its value. If input is time string convert it
	 * to time.
	 */
	if (isInteger(str)) {
		int t = 0;
		res = extract_int(extra, str,  (void**)&t);
		if (res != KT_OK) goto cleanup;
		time = t;
	} else {
		time_t t;
		res = convert_UTC_to_UNIX2(str, &t);
		if (res != KT_OK) goto cleanup;
		time = (int)t;
	}


	/**
	 * Create KSI_Integer for output parameter.
	 */

	res = KSI_Integer_new(ctx, time, &tmp);
	ERR_CATCH_MSG(err, res, "Error: %s.", LOGKSI_errToString(res));

	*obj = (void*)tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_Integer_free(tmp);

	return res;
}


int isFormatOk_flag(const char *flag) {
	if (flag == NULL) return FORMAT_OK;
	else return FORMAT_FLAG_HAS_ARGUMENT;
}

int isFormatOk_userPass(const char *uss_pass) {
	if (uss_pass == NULL) return FORMAT_NULLPTR;
	if (strlen(uss_pass) == 0) return FORMAT_NOCONTENT;
	return FORMAT_OK;
}

int isFormatOk_string(const char *str) {
	if (str == NULL) return FORMAT_NULLPTR;
	if (strlen(str) == 0) return FORMAT_NOCONTENT;
	return FORMAT_OK;
}


int isFormatOk_constraint(const char *constraint) {
	char *at = NULL;
	unsigned i = 0;

	if (constraint == NULL) return FORMAT_NULLPTR;
	if (strlen(constraint) == 0) return FORMAT_NOCONTENT;

	if ((at = strchr(constraint,'=')) == NULL) return FORMAT_INVALID;
	if (at == constraint || *(at + 1) == 0) return FORMAT_INVALID;

	while (constraint[i] != 0 && constraint[i] != '=') {
		if (!isdigit(constraint[i]) && constraint[i] != '.')
			return FORMAT_INVALID_OID;
		i++;
	}

	return FORMAT_OK;
}

int convertRepair_constraint(const char* arg, char* buf, unsigned len) {
	char *value = NULL;
	const char *oid = NULL;

	if (arg == NULL || buf == NULL) return 0;
	KSI_strncpy(buf, arg, len-1);

	value = strchr(arg, '=');
	if (value == NULL) return 0;
	else value++;

	oid = OID_getFromString(arg);

	if (oid != NULL && value != NULL)
		KSI_snprintf(buf, len, "%s=%s", oid, value);

	return 1;
}



const char *getParameterErrorString(int res) {
	switch (res) {
		case PARAM_OK: return "OK";
		case FORMAT_NULLPTR: return "Format error: Parameter must have value";
		case FORMAT_NOCONTENT: return "Parameter has no content";
		case FORMAT_INVALID: return "Parameter is invalid";
		case FORMAT_INVALID_OID: return "OID is invalid";
		case FORMAT_URL_UNKNOWN_SCHEME: return "URL scheme is unknown";
		case FORMAT_FLAG_HAS_ARGUMENT: return "Parameter must not have arguments";
		case FORMAT_INVALID_UTC: return "Time not formatted as YYYY-MM-DD hh:mm:ss";
		case FORMAT_INVALID_UTC_OUT_OF_RANGE: return "Time out of range";
		case PARAM_INVALID: return "Parameter is invalid";
		case FORMAT_NOT_INTEGER: return "Invalid integer";
		case HASH_ALG_INVALID_NAME: return "Algorithm name is incorrect";
		case HASH_IMPRINT_INVALID_LEN: return "Hash length is incorrect";
		case FORMAT_INVALID_HEX_CHAR: return "Invalid hex character";
		case FORMAT_ODD_NUMBER_OF_HEX_CHARACTERS: return "There must be even number of hex characters";
		case FORMAT_INVALID_BASE32_CHAR: return "Invalid base32 character";
		case FORMAT_IMPRINT_NO_COLON: return "Imprint format must be <alg>:<hash>. ':' missing";
		case FORMAT_IMPRINT_NO_HASH_ALG: return "Imprint format must be <alg>:<hash>. <alg> missing";
		case FORMAT_IMPRINT_NO_HASH: return "Imprint format must be <alg>:<hash>. <hash> missing";
		case FILE_ACCESS_DENIED: return "File access denied";
		case FILE_DOES_NOT_EXIST: return "File does not exist";
		case FILE_INVALID_PATH: return "Invalid path";
		case INTEGER_TOO_LARGE: return "Integer value is too large";
		case INTEGER_TOO_SMALL: return "Integer value is too small";
		case INTEGER_UNSIGNED: return "Integer must be unsigned";
		case ONLY_REGULAR_FILES: return "Data from stdin not supported";
		case TREE_DEPTH_OUT_OF_RANGE: return "Tree depth out of range [0 - 255]";
		case UNKNOWN_FUNCTION: return "Unknown function";
		case FUNCTION_INVALID_ARG_COUNT: return "Invalid function argument count";
		case FUNCTION_INVALID_ARG_1: return "Argument 1 is invalid";
		case FUNCTION_INVALID_ARG_2: return "Argument 2 is invalid";
		default: return "Unknown error";
	}
}

static int isValidNameChar(int c) {
	if ((ispunct(c) || isspace(c)) && c != '_' && c != '-') return 0;
	else return 1;
}


static int get_io_pipe_error(PARAM_SET *set, ERR_TRCKR *err, int isStdin, const char *check_all_files, const char *io_file_names, const char *io_flag_names) {
	int res;
	char buf[1024];
	const char *pName = io_file_names;
	char *pValue = NULL;
	size_t count = 0;
	size_t c = 0;
	char err_msg[1024];


	if (err == NULL || set == NULL || (io_file_names == NULL && check_all_files == NULL && io_flag_names == NULL)) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	pName = check_all_files;
	while (pName != NULL && pName[0] != '\0') {
		int i = 0;
		int value_count = 0;

		pValue = NULL;
		pName = extract_next_name(pName, isValidNameChar, buf, sizeof(buf), NULL);

		res = PARAM_SET_getValueCount(set, buf, NULL, PST_PRIORITY_NONE, &value_count);
		if (res != PST_OK) goto cleanup;

		for (i = 0; i < value_count; i++) {
			res = PARAM_SET_getStr(set, buf, NULL, PST_PRIORITY_NONE, i, &pValue);
			if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

			if (pValue == NULL) continue;

			if (strcmp(pValue, "-") == 0) {
				c += KSI_snprintf(err_msg + c, sizeof(err_msg) - c, "%s%s%s -",
						count > 0 ? ", " : "",
						strlen(buf) > 1 ? "--" : "-",
						buf);
				count++;
			}
		}
	}

	pName = io_file_names;
	while (pName != NULL && pName[0] != '\0') {
		pValue = NULL;
		pName = extract_next_name(pName, isValidNameChar, buf, sizeof(buf), NULL);

		res = PARAM_SET_getStr(set, buf, NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &pValue);
		if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

		if (pValue == NULL) continue;

		if (strcmp(pValue, "-") == 0) {
			c += KSI_snprintf(err_msg + c, sizeof(err_msg) - c, "%s%s%s -",
					count > 0 ? ", " : "",
					strlen(buf) > 1 ? "--" : "-",
					buf);
			count++;
		}
	}

	pName = io_flag_names;
	while (pName != NULL && pName[0] != '\0') {
		pName = extract_next_name(pName, isValidNameChar, buf, sizeof(buf), NULL);

		if (PARAM_SET_isSetByName(set, buf)) {
			c += KSI_snprintf(err_msg + c, sizeof(err_msg) - c, "%s%s%s",
					count > 0 ? ", " : "",
					strlen(buf) > 1 ? "--" : "-",
					buf);

			count++;
		}
	}
	if (count > 1) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Multiple different simultaneous %s (%s).",
				isStdin ? "inputs from stdin" : "outputs to stdout",
				err_msg);
		goto cleanup;
	}
	res = KT_OK;

cleanup:

	return res;
}

int get_pipe_out_error(PARAM_SET *set, ERR_TRCKR *err, const char *check_all_files, const char *out_file_names, const char *print_out_names) {
	return get_io_pipe_error(set, err, 0, check_all_files, out_file_names, print_out_names);
}

int get_pipe_in_error(PARAM_SET *set, ERR_TRCKR *err, const char *check_all_files, const char *in_file_names, const char *read_in_flags) {
	return get_io_pipe_error(set, err, 1, check_all_files, in_file_names, read_in_flags);
}
