/*
 * Copyright 2013-2017 Guardtime, Inc.
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

int isFormatOk_recordExtract(const char *rec) {
	long last = -1;
	int expectingInteger = 1;
	int expectingSeparator = 0;
	int isRangeOpen = 0;
	int isRangeJustClosed = 0;
	const char *pRec = rec;
	size_t i = 0;


	if (rec == NULL) return FORMAT_NULLPTR;
	if (strlen(rec) == 0) return FORMAT_NOCONTENT;

	/* Check character set. */
	while(rec[i]) {
		if (isspace(rec[i])) return FORMAT_RECORD_WHITESPACE;
		if (!isdigit(rec[i]) && rec[i] != '-' && rec[i] != ',') return FORMAT_INVALID_RECORD;
		i++;
	}

	/* Check parsebility. */
	while(*pRec) {
		if (expectingInteger) {
			long next = 0;
			char *pEnd = NULL;

			next = strtol(pRec, &pEnd, 10);

			if (next <= 0) return FORMAT_INVALID_RECORD;
			if (pRec == pEnd) return FORMAT_INVALID_RECORD;
			if (last >= next) return FORMAT_RECORD_DESC_ORDER;

			last = next;
			pRec = pEnd;
			expectingSeparator = 1;
			expectingInteger = 0;

			if (isRangeOpen) {
				isRangeOpen = 0;
				isRangeJustClosed = 1;
			}
			continue;
		}

		if (expectingSeparator) {
			expectingSeparator = 0;
			expectingInteger = 1;
			if (*pRec == ',') {
				isRangeJustClosed = 0;
			} else if (*pRec == '-' && !isRangeJustClosed) {
				isRangeOpen = 1;
			} else {
				return FORMAT_INVALID_RECORD;
			}
		}

		pRec++;
	}

	if (isRangeOpen || expectingInteger || last == -1) return FORMAT_INVALID_RECORD;

	return FORMAT_OK;
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

	if (arg == NULL) return PST_PARAM_CONVERT_NOT_PERFORMED;
	if (buf == NULL) return PST_INVALID_ARGUMENT;
	scheme = strstr(arg, "://");
	isFile = (strstr(arg, "file://") == arg);

	if (scheme == NULL) {
		KSI_strncpy(buf, "http://", len-1);
		if (strlen(buf)+strlen(arg) < len)
			strcat(buf, arg);
		else
			return PST_PARAM_CONVERT_NOT_PERFORMED;
	} else {
		while (arg[i] && i < len - 1) {
			if (&arg[i] < scheme) {
				buf[i] = (char)tolower(arg[i]);
#ifdef _WIN32
			} else if (arg[i] == '\\' && isFile) {
				buf[i] = '/';
#else
				VARIABLE_IS_NOT_USED(isFile);
#endif
			} else {
				buf[i] = arg[i];
			}

			i++;
		}
		buf[i] = 0;
	}
	return PST_OK;
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

int extract_int(void **extra, const char* str, void** obj){
	long tmp;
	int *pI = (int*)obj;
	VARIABLE_IS_NOT_USED(extra);
	tmp = str != NULL ? strtol(str, NULL, 10) : 0;
	if (tmp < INT_MIN || tmp > INT_MAX) return KT_INVALID_CMD_PARAM;
	*pI = (int)tmp;
	return PST_OK;
}

int isContentOk_pduVersion(const char* version) {
	if (version == NULL) return FORMAT_NULLPTR;

	if (strcmp(version, "v1") == 0) {
		return PARAM_OK;
	} else if (strcmp(version, "v2") == 0) {
		return PARAM_OK;
	}

	return INVALID_VERSION;
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

	if (arg == NULL) return PST_PARAM_CONVERT_NOT_PERFORMED;
	if (buf == NULL) return PST_INVALID_ARGUMENT;
	KSI_strncpy(buf, arg, len - 1);


	toBeReplaced = buf;
	while ((toBeReplaced = strchr(toBeReplaced, '\\')) != NULL){
		*toBeReplaced = '/';
		toBeReplaced++;
	}

	return PST_OK;
}

int isFormatOk_path(const char *path) {
	if (path == NULL) return FORMAT_NULLPTR;
	if (path[0] == '\0') return FORMAT_NOCONTENT;
	return FORMAT_OK;
}

int isFormatOk_hashAlg(const char *hashAlg){
	if (hashAlg == NULL) return FORMAT_NULLPTR;
	if (strlen(hashAlg) == 0) return FORMAT_NOCONTENT;
	return FORMAT_OK;
}

int isContentOk_hashAlg(const char *alg){
	if (KSI_isHashAlgorithmSupported(KSI_getHashAlgorithmByName(alg))) return PARAM_OK;
	else return HASH_ALG_INVALID_NAME;
}

int extract_hashAlg(void **extra, const char* str, void** obj) {
	const char *hash_alg_name = NULL;
	KSI_HashAlgorithm *hash_id = (KSI_HashAlgorithm*)obj;
	VARIABLE_IS_NOT_USED(extra);

	hash_alg_name = str != NULL ? (str) : ("default");
	*hash_id = KSI_getHashAlgorithmByName(hash_alg_name);

	if (!KSI_isHashAlgorithmSupported(*hash_id)) return KT_UNKNOWN_HASH_ALG;

	return PST_OK;
}

static int imprint_extract_fields(const char *imprint, KSI_HashAlgorithm *ID, int *isColon, char *hash, size_t buf_len) {
	int res;
	const char *colon = NULL;
	char alg[1024];

	if (imprint == NULL || hash == NULL || buf_len == 0) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	colon = strchr(imprint, ':');

	if (colon != NULL) {
		int i = 0;
		int n = 0;
		int reading_alg = 1;
		size_t size_limit = sizeof(alg);

		while (imprint[i] != '\0') {
			if (colon == &imprint[i]) {
				reading_alg = 0;
				alg[n] = '\0';
				size_limit = buf_len;
				n = 0;
				i++;
			}

			if (n < size_limit - 1) {
				if (reading_alg) {
					alg[n] = imprint[i];
				} else {
					hash[n] = imprint[i];
				}
				n++;
			}
		i++;
		}

		hash[n] = '\0';
	} else {
		alg[0] = '\0';
		hash[0] = '\0';
	}

	if (ID != NULL) {
		*ID = KSI_getHashAlgorithmByName(alg);
	}

	if (isColon != NULL) {
		*isColon = colon == NULL ? 0 : 1;
	}

	res = KT_OK;

cleanup:

	return res;
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

static int imprint_get_hash_obj(const char *imprint, KSI_CTX *ksi, ERR_TRCKR *err, KSI_DataHash **hash){
	int res;
	char hash_hex[1024];
	unsigned char bin[1024];
	size_t bin_len = 0;
	KSI_HashAlgorithm alg_id = KSI_HASHALG_INVALID_VALUE;
	KSI_DataHash *tmp = NULL;

	if (imprint == NULL || ksi == NULL || err == NULL || hash == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = imprint_extract_fields(imprint, &alg_id, NULL, hash_hex, sizeof(hash_hex));
	if (res != KT_OK) goto cleanup;

	res = hex_string_to_bin(hash_hex, bin, sizeof(bin), &bin_len);
	if (res != KT_OK) goto cleanup;

	if (!KSI_isHashAlgorithmSupported(alg_id)) {
		res = KT_UNKNOWN_HASH_ALG;
		goto cleanup;
	}

	res = KSI_DataHash_fromDigest(ksi, alg_id, bin, bin_len, &tmp);
	if (res != KSI_OK) goto cleanup;

	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);

	if (res != KT_OK) {
		ERR_TRCKR_ADD(err, res, "Error: Unable to get hash from command-line");
		ERR_TRCKR_ADD(err, res, "Error: %s", LOGKSI_errToString(res));
	}

	return res;
}

static int analyze_hexstring_format(const char *hex, double *cor) {
	int i = 0;
	int C;
	size_t count = 0;
	size_t valid_count = 0;
	double tmp = 0;

	if (hex == NULL) {
		return FORMAT_NULLPTR;
	}

	while ((C = 0xff & hex[i++]) != '\0') {
		count++;
		if (isxdigit(C)) {
			valid_count++;
		}
	}
	if (count > 0) {
		tmp = (double)valid_count / (double)count;
	}

	if (cor != NULL) {
		*cor = tmp;
	}

	if (valid_count == count && count > 0) {
		return FORMAT_OK;
	} else if (count == 0) {
		return FORMAT_NOCONTENT;
	} else if (valid_count != count) {
		return FORMAT_INVALID_HEX_CHAR;
	} else {
		return FORMAT_INVALID;
	}

}

int isFormatOk_imprint(const char *imprint){
	char *colon;

	if (imprint == NULL) return FORMAT_NULLPTR;
	if (strlen(imprint) == 0) return FORMAT_NOCONTENT;

	colon = strchr(imprint, ':');

	if (colon == NULL) return FORMAT_IMPRINT_NO_COLON;
	if (colon != NULL && colon == imprint) return FORMAT_IMPRINT_NO_HASH_ALG;
	if (*(colon + 1) == '\0') return FORMAT_IMPRINT_NO_HASH;

	return analyze_hexstring_format(colon + 1, NULL);
}

int isContentOk_imprint(const char *imprint) {
	int res = PARAM_INVALID;
	char hash[1024];
	KSI_HashAlgorithm alg_id = KSI_HASHALG_INVALID_VALUE;
	unsigned len = 0;
	unsigned expected_len = 0;

	if (imprint == NULL) return PARAM_INVALID;

	res = imprint_extract_fields(imprint, &alg_id, NULL, hash, sizeof(hash));
	if (res != KT_OK) {
		res = PARAM_INVALID;
		goto cleanup;
	}

	if (!KSI_isHashAlgorithmSupported(alg_id)) {
		res = HASH_ALG_INVALID_NAME;
		goto cleanup;
	}

	expected_len = KSI_getHashLength(alg_id);
	len = (unsigned)strlen(hash);

	if (len%2 != 0 && len/2 != expected_len) {
		res = HASH_IMPRINT_INVALID_LEN;
		goto cleanup;
	}

	res = PARAM_OK;
cleanup:

	return res;
}

int extract_imprint(void **extra, const char* str, void** obj) {
	int res;
	void **extra_array = (void**)extra;
	COMPOSITE *comp = NULL;
	KSI_CTX *ctx = NULL;
	ERR_TRCKR *err = NULL;
	KSI_DataHash *tmp = NULL;

	comp = (COMPOSITE*)extra_array[1];
	ctx = comp->ctx;
	err = comp->err;


	res = imprint_get_hash_obj(str, ctx, err, &tmp);
	if (res != KT_OK) goto cleanup;

	*obj = (void*)tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);

	return res;
}

int is_imprint(const char *str) {
	int res;
	KSI_HashAlgorithm alg = KSI_HASHALG_INVALID_VALUE;
	int isColon = 0;
	char hex[1024];
	double correctness = 1;
	double tmp = 0;

	res = imprint_extract_fields(str, &alg, &isColon, hex, sizeof(hex));
	if (res != KT_OK) return 0;
	if (!isColon) correctness = 0;
	if (!KSI_isHashAlgorithmSupported(alg)) correctness = 0;

	analyze_hexstring_format(hex, &tmp);
	if (tmp < 1.0) correctness = 0;

	if (isContentOk_imprint(str) != PARAM_OK) correctness = 0;

	if (correctness > 0.5) return 1;
	else return 0;
}

int isFormatOk_inputHash(const char *str) {
	if (str == NULL) return FORMAT_NULLPTR;
	if (strlen(str) == 0) return FORMAT_NOCONTENT;

	if (is_imprint(str)) {
		return isFormatOk_imprint(str);
	} else {
		return isFormatOk_inputFile(str);
	}
}

int isContentOk_inputHash(const char *str) {
	if (str == NULL) return FORMAT_NULLPTR;
	if (strlen(str) == 0) return FORMAT_NOCONTENT;

	if (is_imprint(str)) {
		return isContentOk_imprint(str);
	} else {
		return isContentOk_inputFileWithPipe(str);
	}
}

static int file_get_hash_from_imprint_stored_in_file(ERR_TRCKR *err, KSI_CTX *ctx, const char *open_mode, const char *fname_in, KSI_DataHash **hash) {
	int res;
	SMART_FILE *in = NULL;
	char buf[0xffff];
	char imprint[1024];
	int imprint_is_extracted = 0;
	size_t read_count = 0;
	KSI_DataHash *tmp = NULL;
	size_t row = 0;


	if (err == NULL || ctx == NULL || open_mode == NULL || fname_in == NULL || hash == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	/**
	 * Open the file, read extract hash from imprint.
	 */
	res = SMART_FILE_open(fname_in, open_mode, &in);
	if (res != KT_OK) {
		ERR_TRCKR_ADD(err, res, "Error: Unable to open file for reading. '%s'", LOGKSI_errToString(res));
		goto cleanup;
	}

	while(!SMART_FILE_isEof(in)) {
		char *trim = NULL;
		buf[0] = '\0';
		res = SMART_FILE_readLine(in, buf, sizeof(buf) - 1, &row, &read_count);
		ERR_CATCH_MSG(err, res, "Error: Unable get line.");

		/* Remove leading whitespace. */
		trim = buf;
		while (isspace(*trim) && *trim != '\0') {
			trim++;
		}

		if (read_count == 0) break;
		else if (buf[0] == '#') continue;
		else if (imprint_is_extracted == 0) {
			int i = 0;
			imprint_is_extracted = 1;

			/* Remove trailing whitespace. */
			for (i = read_count - 1; i >= 0; i--) {
				if (isspace(buf[i])) buf[i] = '\0';
				else break;
			}

			KSI_strncpy(imprint, trim, sizeof(imprint));
		} else {
			res = KT_INVALID_INPUT_FORMAT;
			ERR_TRCKR_ADD(err, res, "Error: Unexpected line %zu while parsing input hash. '%s'", row, buf);
			goto cleanup;
		}
	}

	if (imprint_is_extracted) {
		res = imprint_get_hash_obj(imprint, ctx, err, &tmp);
		ERR_CATCH_MSG(err, res, "Error: Unable to extract imprint.");
	}

	*hash = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:

	SMART_FILE_close(in);
	KSI_DataHash_free(tmp);

	return res;
}


static int extract_input_hash(void **extra, const char* str, void** obj, int no_imprint, int no_stream) {
	int res;
	void **extra_array = (void**)extra;
	COMPOSITE *comp = (COMPOSITE*)(extra_array[1]);
	KSI_CTX *ctx = comp->ctx;
	ERR_TRCKR *err = comp->err;

	KSI_DataHash *tmp = NULL;

	if (obj == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	if (!no_imprint && is_imprint(str)) {
		res = extract_imprint(extra, str, (void**)&tmp);
		if (res != KT_OK) goto cleanup;
	} else {
		res = file_get_hash_from_imprint_stored_in_file(err, ctx, no_stream ? "rb" : "rbs", str, &tmp);
		if (res != KT_OK) goto cleanup;
	}


	*obj = (void*)tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);

	return res;
}

int extract_inputHashFromImprintOrImprintInFile(void **extra, const char* str, void** obj) {
	return extract_input_hash(extra, str, obj, 0, 0);
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

int extract_pubString(void **extra, const char* str, void** obj) {
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

static int is_format_ok_time_seconds(const char *time_diff, int allow2values, int allow_negative, int allow_infinity, int restrict_same_sign) {
	int res = 0;
	int i = 0;
	int base = 0;
	int is_d = 0;
	int is_H = 0;
	int is_M = 0;
	int is_S = 0;
	int is_value_extracted = 0;	/* Actual value has been extracted (e.g. number, +/-infinity). */
	int has_comma = 0;			/* A comma has been encountered. */
	int has_minus = 0;			/* Last value already has a minus.*/
	int is_minus = 0;			/* Current value has a minus. */
	int has_infinity = 0;		/* Las value was infinity. */
	int infinity_counter = 0;	/* Infinity value is being parsed. */
	char c = 0;
	int lastWasDigit = 0;		/* Last char was a digit. */
	int general_error = 0;

	res = isFormatOk_string(time_diff);
	if (res != FORMAT_OK) return res;

	while (time_diff[base + i]) {
		int both_values_same_sign = 0;
		c = time_diff[base + i];
		if (!allow2values && c ==',') return FORMAT_NO_TIME_RANGE_SUPPORTED;
		if (!allow_negative && c =='-') return FORMAT_ONLY_UNSIGNED_VALUE;
		if (!allow_infinity && c == 'o') return FORMAT_INVALID_TIME_DIFF_FORMAT;

		/* First value is extracted and a comma is encountered - it must be the second value. */
		if (c == ',') {
			if (!has_comma && i > 0 && is_value_extracted) {
				has_comma = 1;
				i++;
				base = i;
				i = 0;
				has_minus = is_minus;
				is_minus = 0;
				is_value_extracted = 0;
				lastWasDigit = 0;
				infinity_counter = 0;
				is_d = 0;
				is_H = 0;
				is_M = 0;
				is_S = 0;
				continue;
			}

			return FORMAT_INVALID_TIME_RANGE;
		}

		/* There can be only 1 negative or 1 positive, but not 2 negative and 2 positive values. */
		if (c == '-' && i == 0 && !is_minus) {
			is_minus = 1;
			i++;
			continue;
		}

		both_values_same_sign = has_comma && ((!has_minus && !is_minus) || (has_minus && is_minus));

		/* There has been a comma, one of the values must be negative. */
		if (restrict_same_sign && allow_negative && both_values_same_sign) {
			return FORMAT_INVALID_TIME_RANGE;
		} else if (has_infinity && infinity_counter > 0 && both_values_same_sign) {
			return FORMAT_INVALID_INFINIT_TIME_RANGE;
		}

		/* If infinity is extracted, it can be at the beginning of the string,
		   there can not follow any characters other than comma. */
		if ((c == 'o' && (i - is_minus) != infinity_counter) || (infinity_counter > 0 && (is_value_extracted || c != 'o'))) return FORMAT_INVALID_TIME_DIFF_FORMAT_INFINITY;


		/* Infinity can occupy 2 + 1. */
		if (c == 'o') {
			if (++infinity_counter == 2) {
				has_infinity = 1;
				is_value_extracted = 1;
			}
		} else if (!isdigit(c)) {
			if (c == 'd' && lastWasDigit && !is_d ) is_d = 1;
			else if (toupper(c) == 'H' && lastWasDigit && !is_H) is_H = 1;
			else if (toupper(c) == 'M' && lastWasDigit && !is_M) is_M = 1;
			else if (toupper(c) == 'S' && lastWasDigit && !is_S) is_S = 1;
			else return FORMAT_INVALID_TIME_DIFF_FORMAT;
			lastWasDigit = 0;
		} else {
			lastWasDigit++;
			is_value_extracted++;
			if (is_value_extracted > 10) return FORMAT_TOO_LARGE_VALUE;
		}

		i++;
	}

	general_error = allow_infinity ? FORMAT_INVALID_TIME_DIFF_FORMAT_INFINITY : FORMAT_INVALID_TIME_DIFF_FORMAT;

	/* S is specified and last integer does not end with any marker - it must be
	   double specification of seconds! */
	if (is_S && isdigit(c)) return general_error;

	/* No actual numeric value is extracted. */
	if (has_comma && !is_value_extracted) return has_infinity ? FORMAT_INVALID_INFINIT_TIME_RANGE : FORMAT_INVALID_TIME_RANGE;
	if (!is_value_extracted) return general_error;

	return FORMAT_OK;
}

int isFormatOk_timeDiff(const char *time_diff) {
	return is_format_ok_time_seconds(time_diff, 1, 1, 0, 1);
}

int isFormatOk_timeDiffInfinity(const char *time_diff) {
	return is_format_ok_time_seconds(time_diff, 1, 1, 1, 0);
}

int isFormatOk_timeValue(const char *time_diff) {
	return is_format_ok_time_seconds(time_diff, 0, 0, 0, 0);
}

static const char* extract_seconds(const char *str, int64_t *value, int *isInfinity) {
	int64_t result = 0;
	int64_t tmp = 0;
	int sign = 1;
	size_t i = 0;
	int infinity = 0;

	if (str == NULL || value == NULL || isInfinity == NULL) return NULL;

	while (str[i] != '\0' && str[i] != ',') {
			int c = str[i];

			if (c == '-' && i == 0) {
				i++;
				sign = -1;
				continue;
			}

			if (c == 'o' && i < 2) {
				infinity = 1;
				i++;
				continue;
			}

			if (toupper(c) == 'S') {
				result += tmp;
				tmp = 0;
			} else if (toupper(c) == 'M') {
				result += tmp * 60;
				tmp = 0;
			} else if (toupper(c) == 'H') {
				result += tmp * 3600;
				tmp = 0;
			} else if (c == 'd') {
				result += tmp * 24 * 3600;
				tmp = 0;
			} else {
				tmp *= 10;
				tmp += c - '0';
			}
			i++;
	}

	if (infinity) {
		*value = sign;
		*isInfinity = 1;
	} else {
		result += tmp;
		*value = sign * result;
		*isInfinity = 0;
	}

	return (str[i] == '\0') ? NULL : &str[i];
}

int extract_timeDiff(void **extra, const char* time_diff,  void** obj) {
	int64_t result_1 = 0;
	int64_t result_2 = 0;
	MIN_MAX_INT *pObj = (MIN_MAX_INT*)obj;
	const char *pStr = time_diff;
	int infinity_1 = 0;
	int infinity_2 = 0;

	VARIABLE_IS_NOT_USED(extra);
	if (obj == NULL) return PST_INVALID_ARGUMENT;

	pObj->count = 0;
	pStr = extract_seconds(pStr, &result_1, &infinity_1);
	pObj->count++;
	infinity_1 *= result_1;
	if (pStr != NULL && *pStr == ',') {
		pStr++;
		pObj->count++;
		extract_seconds(pStr, &result_2, &infinity_2);
		infinity_2 *= result_2;
	}

	/* Limit the size with boundaries with int (time diff ~ +/- 68 years or more).
	   In case of infinity, value is set to the highest / lowest value possible
	   and infinity flags are set. */
	if (result_1 > INT_MAX || infinity_1 == 1) result_1 = INT_MAX;
	if (result_1 < INT_MIN || infinity_1 == -1) result_1 = INT_MIN;
	if (result_2 > INT_MAX || infinity_2 == 1) result_2 = INT_MAX;
	if (result_2 < INT_MIN || infinity_2 == -1) result_2 = INT_MIN;

	/* Which value is max and min. */
	if (pObj->count == 2) {
		pObj->min = result_1 < result_2 ? (int)(result_1) : (int)(result_2);
		pObj->max = result_1 > result_2 ? (int)(result_1) : (int)(result_2);
	} else {
		pObj->min = (int)(result_1);
		pObj->max = (int)(result_1);
	}

	/* Set infinity flags. */
	pObj->neg_inf = (infinity_1 == -1 || infinity_2 == -1);
	pObj->pos_inf = (infinity_1 == 1 || infinity_2 == 1);

	return PST_OK;
}

int extract_timeValue(void **extra, const char* time_diff,  void** obj) {
	int64_t result = 0;
	int isInfinity = 0;
	int *pI = (int*)obj;
	VARIABLE_IS_NOT_USED(extra);
	if (obj == NULL) return PST_INVALID_ARGUMENT;
	extract_seconds(time_diff, &result, &isInfinity);
	if (result > INT_MAX || (result == 1 && isInfinity)) result = INT_MAX;
	if (result < INT_MIN || (result == -1 && isInfinity)) result = INT_MIN;
	*pI = (int)result;
	return PST_OK;
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

int extract_utcTime(void **extra, const char* str, void** obj) {
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

	if (arg == NULL) return PST_PARAM_CONVERT_NOT_PERFORMED;
	if (buf == NULL) return PST_INVALID_ARGUMENT;

	value = strchr(arg, '=');
	if (value == NULL) return PST_PARAM_CONVERT_NOT_PERFORMED;
	else value++;

	oid = OID_getFromString(arg);

	if (oid != NULL && value != NULL) {
		KSI_snprintf(buf, len, "%s=%s", oid, value);
	} else {
		return PST_PARAM_CONVERT_NOT_PERFORMED;
	}

	return PST_OK;
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
		case FORMAT_INVALID_TIME_DIFF_FORMAT: return "Only digits and 1x d, H, M and S allowed";
		case FORMAT_INVALID_TIME_DIFF_FORMAT_INFINITY: return "Only digits, oo and 1x d, H, M and S allowed";
		case FORMAT_ONLY_UNSIGNED_VALUE: return "Only unsigned value allowed";
		case FORMAT_TOO_LARGE_VALUE: return "Value is too large";
		case FORMAT_NO_TIME_RANGE_SUPPORTED: return "No comma (,) supported for range";
		case FORMAT_INVALID_TIME_RANGE: return "Time range should be -<int>,<int>";
		case FORMAT_INVALID_INFINIT_TIME_RANGE: return "Time range with infinity can be -oo,oo, <int>,oo or -oo,<int>";
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
		case INVALID_VERSION: return "Invalid version";
		case FORMAT_RECORD_WHITESPACE: return "List of positions must not contain whitespace. Use ',' and '-' as separators";
		case FORMAT_INVALID_RECORD: return "Positions must be represented by positive decimal integers, using a list of comma-separated ranges";
		case FORMAT_RECORD_DESC_ORDER: return "List of positions must be given in strictly ascending order";
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
