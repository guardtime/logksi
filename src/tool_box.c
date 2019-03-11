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

#include "tool_box.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include "err_trckr.h"
#include "param_set/param_set.h"
#include "printer.h"



static char *OID_EMAIL[] = {KSI_CERT_EMAIL, "E", "email", "e-mail", "e_mail", "emailAddress", NULL};
static char *OID_COMMON_NAME[] = {KSI_CERT_COMMON_NAME, "CN", "common name", "common_name", "cname", NULL};
static char *OID_COUNTRY[] = {KSI_CERT_COUNTRY, "C", "country", NULL};
static char *OID_ORGANIZATION[] = {KSI_CERT_ORGANIZATION, "O", "org", "organization", NULL};
static char **OID_INFO[] = {OID_EMAIL, OID_COMMON_NAME, OID_COUNTRY, OID_ORGANIZATION, NULL};

const char *OID_getShortDescriptionString(const char *OID) {
	unsigned i = 0;

	if (OID == NULL) return NULL;

	while (OID_INFO[i] != NULL) {
		if (strcmp(OID_INFO[i][0], OID) == 0) return OID_INFO[i][1];
		i++;
	}

	return OID;
}

const char *OID_getFromString(const char *str) {
	unsigned i = 0;
	unsigned n = 0;
	const char *OID = NULL;
	size_t len;

	if (str == NULL) {
		OID = NULL;
		goto cleanup;
	};

	while (OID_INFO[i] != NULL) {
		n = 1;
		while (OID_INFO[i][n] != NULL) {
			len = strlen(OID_INFO[i][n]);
			if (strncmp(OID_INFO[i][n], str, len) == 0 && str[len] == '=') {
				OID = OID_INFO[i][0];
				goto cleanup;
			}
			n++;
		}
		i++;
	}

cleanup:
	return OID;
}

const char *getPublicationsFileRetrieveDescriptionString(PARAM_SET *set) {
	int res;
	const char *pub_desc_str = "Receiving publications file... ";
	char *pubfile_uri = NULL;

	if (set == NULL) goto cleanup;

	res = PARAM_SET_getStr(set, "P", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &pubfile_uri);
	if (res != PST_OK) goto cleanup;

	if (strstr(pubfile_uri, "file://") != NULL) {
		pub_desc_str = "Loading publications file from file... ";
	}

cleanup:

	return pub_desc_str;
}

char *STRING_getBetweenWhitespace(const char *strn, char *buf, size_t buf_len) {
	const char *beginning = NULL;
	const char *end = NULL;
	size_t strn_len;
	size_t new_len;

	if (strn == NULL || buf == NULL || buf_len == 0) return NULL;

	strn_len = strlen(strn);
	beginning = strn;
	end = strn + strn_len; //End should be at terminating NUL


	while (beginning != end && isspace(*beginning)) beginning++;
	while (end != beginning && (isspace(*end) || *end == '\0')) end--;


	new_len = end + 1 - beginning;
	if (KSI_strncpy(buf, beginning, new_len + 1) == NULL) return NULL;

	return buf;
}

const char * STRING_locateLastOccurance(const char *str, const char *findIt) {
	const char * ret = NULL;
	const char * isFound = NULL;
	const char *searchFrom = NULL;

	if (str == NULL || findIt == NULL) return NULL;
	if (*str == '\0' && *findIt == '\0') return str;


	searchFrom = str;

	while (*searchFrom != '\0' && (isFound = strstr(searchFrom, findIt)) != NULL) {
		searchFrom = isFound + 1;
		ret = isFound;
	}
	return ret;
}

const char* find_charAfterStrn(const char *str, const char *findIt) {
	size_t findIt_len = 0;
	const char * beginning = NULL;
	findIt_len = strlen(findIt);
	beginning = strstr(str, findIt);
	return (beginning == NULL) ? NULL : beginning + findIt_len;
}

static const char* find_charAfter_abstract(const char *str, const char *findIt, const char* (*find)(const char *str, const char *findIt)) {
	size_t findIt_len = 0;
	const char * beginning = NULL;
	const char * ret = NULL;
	findIt_len = strlen(findIt);
	beginning = find(str, findIt);
	if (beginning == NULL) return NULL;
	ret = beginning + findIt_len;
	return ret;
}

const char* find_charAfterLastStrn(const char* str, const char* findIt) {
	return find_charAfter_abstract(str, findIt, STRING_locateLastOccurance);
}

static const char* find_charBefore_abstract(const char *str, const char *findIt, const char* (*find)(const char *str, const char *findIt)) {
	const char *right = NULL;
	right = find(str, findIt);
	if (right == NULL) return NULL;
	right = right -1;
	return right;
}

const char* find_charBeforeStrn(const char* str, const char* findIt) {
	return find_charBefore_abstract(str, findIt,
			(const char* (*)(const char *, const char *))strstr);
}

const char* find_charBeforeLastStrn(const char* str, const char* findIt) {
	return find_charBefore_abstract(str, findIt, STRING_locateLastOccurance);
}

char *STRING_extractAbstract(const char *strn, const char *from, const char *to, char *buf, size_t buf_len,
		const char* (*find_from)(const char *str, const char *findIt),
		const char* (*find_to)(const char *str, const char *findIt),
		const char** firstChar) {
	const char *beginning = NULL;
	const char *end = NULL;
	size_t new_len;

	if (strn == NULL || buf == NULL || buf_len == 0) return NULL;

	if (find_from == NULL) find_from = find_charAfterStrn;
	if (find_to == NULL) find_to = find_charBeforeStrn;

	beginning = (from == NULL) ? strn : find_from(strn, from);
	end = (to == NULL) ? (strn + strlen(strn) - 1) : find_to(strn, to);

	if (beginning == NULL || end == NULL) return NULL;

	/**
	 * If the beginning or end is "out of the string" there might be
	 * a case where empty string is extracted.
	 */
	if (beginning == strn -1 || end == strn -1) {
		if (beginning == strn && end == strn -1) new_len = 0;
		else if (beginning == strn - 1 && end == strn) new_len = 0;
		else if (beginning == strn - 1 && end == strn - 1) new_len = 0;
		else return NULL;
	} else {
		if (end < beginning) return NULL;
		if ((end + 1) < beginning) new_len = 0;
		else new_len = end + 1 - beginning;
	}

	new_len = (new_len + 1 > buf_len) ? buf_len - 1 : new_len;
	if (KSI_strncpy(buf, beginning, new_len + 1) == NULL) return NULL;

	if (firstChar != NULL) {
		*firstChar = (*end == '\0') ? NULL : end + 1;
	}

	return buf;
}

char *STRING_extract(const char *strn, const char *from, const char *to, char *buf, size_t buf_len) {
	return STRING_extractAbstract(strn, from, to ,buf, buf_len,
			NULL,
			find_charBeforeLastStrn,
			NULL);
}

char *STRING_extractRmWhite(const char *strn, const char *from, const char *to, char *buf, size_t buf_len) {
	char *tmp = NULL;
	char *ret = NULL;
	char *isBuf = NULL;

	if (strn == NULL || buf == NULL || buf_len == 0) goto cleanup;

	tmp = (char *)malloc(buf_len);
	if (tmp == NULL) goto cleanup;

	isBuf = STRING_extract(strn, from, to, tmp, buf_len);
	if (isBuf != tmp) goto cleanup;

	isBuf = STRING_getBetweenWhitespace(tmp, buf, buf_len);
	if (isBuf != buf) goto cleanup;

	ret = buf;

cleanup:

	free(tmp);

	return ret;
}

static const char* find_group_start(const char *str, const char *ignore) {
	size_t i = 0;
	if (ignore);
	while (str[i] && isspace(str[i])) i++;
	return (i == 0) ? str : &str[i];
}

static const char* find_group_end(const char *str, const char *ignore) {
	int is_quato_opend = 0;
	int is_firs_non_whsp_found = 0;
	size_t i = 0;

	if (ignore);
	while (str[i]) {
		if (!isspace(str[i])) is_firs_non_whsp_found = 1;
		if (isspace(str[i]) && is_quato_opend == 0 && is_firs_non_whsp_found) return &str[i - 1];

		if (str[i] == '"' && is_quato_opend == 0) is_quato_opend = 1;
		else if (str[i] == '"' && is_quato_opend == 1) return &str[i];

		i++;
	}

	return i == 0 ? str : &str[i];
}


static void string_removeChars(char *str, char rem) {
	size_t i = 0;
	size_t str_index = 0;
	char *itr = str;

	if (itr == NULL) return;

	while (itr[i]) {
		if (itr[i] != rem) {
			str[str_index] = itr[i];
			str_index++;
		}
		i++;
	}
	str[str_index] = '\0';
}

const char *STRING_getChunks(const char *strn, char *buf, size_t buf_len) {
	const char *next = NULL;
	STRING_extractAbstract(strn, "", "", buf, buf_len, find_group_start, find_group_end, &next);
	string_removeChars(buf, '"');
	return next;
}

static const char *path_removeFile(const char *origPath, char *buf, size_t buf_len) {
	char *beginingOfFile = NULL;
	size_t path_len;
	char *ret = NULL;

	beginingOfFile = strrchr(origPath, '/');
	if (beginingOfFile ==  NULL) {
		buf[0] = '\0';
		return buf;
	}

	path_len = beginingOfFile - origPath;
	if (path_len + 1 > buf_len) return NULL;

	ret = KSI_strncpy(buf, origPath, path_len + 1);
	buf[path_len + 1] = 0;
	return  ret;
}

const char *PATH_getPathRelativeToFile(const char *refFilePath, const char *origPath, char *buf, size_t buf_len) {
	size_t origPath_len;
	size_t refPath_len;
	char refPath_last_char;
	char refPathAppend[2] = {0,0};
	int isAbsolute = 0;
	char path_buf[2048];
	const char *refPath = NULL;

	refPath = path_removeFile(refFilePath, path_buf, sizeof(path_buf));
	refPath_len = strlen(refPath);
	origPath_len = strlen(origPath);
	if (origPath_len == 0) return NULL;

	/**
	 * Check if origPath is relative or absolute path.
	 */
	if (origPath[0] == '/') isAbsolute = 1;
	else isAbsolute = 0;

	if (isAbsolute == 1) {
		return origPath;
	} else {
		/**
		 * If ref path has last char as \ or / then do nothing
		 */
		refPath_last_char = (refPath_len == 0) ? '\0' : refPath[refPath_len - 1];

		if (refPath_last_char != '\0' && refPath_last_char != '/' && refPath_last_char != '\\') {
			refPathAppend[0] = '/';
		} else {
			refPathAppend[0] = '\0';
		}
		KSI_snprintf(buf, buf_len, "%s%s%s", refPath, refPathAppend, origPath);
		path_buf[buf_len - 1] = '\0';
		return buf;
	}
}

const char *PATH_URI_getPathRelativeToFile(const char *refFilePath, const char *origPath, char *buf, size_t buf_len) {
	int isFileUri = 0;
	const char *pOrigPath = origPath;
	char buf_inner[2048];

	/**
	 * Check if uri scheme is file, if not return the original uri.
	 */
	if (origPath == NULL) return NULL;
	isFileUri = (strstr(origPath, "file://") == origPath) ? 1 : 0;
	if (isFileUri && strlen(origPath) == 7) return origPath;
	if (!isFileUri) return origPath;

	/**
	 * If uri scheme is file, cut the files path and convert. Append to file scheme.
	 */
	pOrigPath = isFileUri ? origPath + 7 : origPath;
	KSI_snprintf(buf, buf_len, "file://%s", PATH_getPathRelativeToFile(refFilePath, pOrigPath, buf_inner, sizeof(buf_inner)));
	return buf;
}
