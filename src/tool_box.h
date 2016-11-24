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

#ifndef TOOL_BOX_H
#define	TOOL_BOX_H

#include "param_set/param_set.h"

#ifdef	__cplusplus
extern "C" {
#endif

	
const char *OID_getShortDescriptionString(const char *OID);
const char *OID_getFromString(const char *str);

const char *getPublicationsFileRetrieveDescriptionString(PARAM_SET *set);

char *STRING_getBetweenWhitespace(const char *strn, char *buf, size_t buf_len);

const char * STRING_locateLastOccurance(const char *str, const char *findIt);

/**
 * Extract a substring from given string. String is extracted using two substrings
 * from and to. Extracted string is located as <from><extracted string><to>.
 * Strings from and to are located using abstract functions \find_from and \find_to.
 * If one of the substrings is missing the result is not extracted. When from is
 * set as NULL the string is extracted from the beginning of the input string.
 * When to is set as NULL the string is extracted from <from> until the end of
 * the input strings.
 * 
 * Abstract functions must have following format:
 * const char* (*find_to)(const char *str, const char *findIt)
 * This function searches a location from str according to findIt and must return
 * pointer to the first or last character that is extracted from the str or NULL if
 * locations is not found or an error occurred. 
 * 
 * Abstract functions can be NULL as in this case default search is performed.
 * 
 * @param strn[in]			Input string.
 * @param from[in]			The first border string.
 * @param to[in]			The last border string.
 * @param buf[in/out]		The buffer where substring is extracted.
 * @param buf_len[in]		The size of the buffer.
 * @param find_from[in]		Abstract function to find <from>. 	
 * @param find_to[in]		Abstract functions to find <to>.
 * @param firstChar[in/out]	The pointer to the pointer of first character not extracted from string. Can be NULL.
 * @return Returns buf is successful, NULL otherwise.
 * @note buf is only changed on successful extraction.
 */
char *STRING_extractAbstract(const char *strn, const char *from, const char *to, char *buf, size_t buf_len,
		const char* (*find_from)(const char *str, const char *findIt),
		const char* (*find_to)(const char *str, const char *findIt),
		const char** firstChar);

/**
 * Extract a substring from given string. String is extracted using two substrings
 * from and to. Extracted string is located as <from><extracted string><to>.
 * For example when using from as "[" and to as "]" on input string "[test]" the
 * extracted value is "test". If one of the substrings is missing the result is 
 * not extracted. When from is set as NULL the string is extracted from the
 * beginning of the input string. When to is set as NULL the string is extracted
 * until the end of the input strings. For example from = "->", to = NULL, input
 * string is "->test test", the resulting output is "test test".
 * 
 * When searching "from" substring always the first occurrence is used, when searching
 * "to" string, always the last one is used.
 * 
 * @param strn[in]		Input string.
 * @param from[in]		The first border string.
 * @param to[in]		The last border string.
 * @param buf[in]		The buffer where substring is extracted.
 * @param buf_len[in]	The size of the buffer.
 * 
 * @return Returns buf is successful, NULL otherwise.
 */
char *STRING_extract(const char *strn, const char *from, const char *to, char *buf, size_t buf_len);

/**
 * Same as STRING_extract, but the white space characters from the beginning and
 * end are removed.
 * @param strn[in]		Input string.
 * @param from[in]		The first border string.
 * @param to[in]		The last border string.
 * @param buf[in]		The buffer where substring is extracted.
 * @param buf_len[in]	The size of the buffer.
 * 
 * @return Returns buf is successful, NULL otherwise.
 */
char *STRING_extractRmWhite(const char *strn, const char *from, const char *to, char *buf, size_t buf_len);

/**
 * This function extracts "chunks" from the input string. Input string is cut into
 * peaces by whitespace characters. If there are opening '"' inside the input string
 * next whitespace characters are ignored until closing '"'. Function returns a 
 * pointer (inside input string) that can be feed to the same function to extract
 * the next chunk. If the end of input string is reached NULL is returned.
 * For example:
 * 
 * @param	strn[in]	Pointer to NUL terminated C string.
 * @param	buf[out]	Pointer to receiving buffer.
 * @param	buf_len[in]	The size of the buffer.
 * 
 * @return Pointer for next iteration or NULL on error or end of string.
 */
const char *STRING_getChunks(const char *strn, char *buf, size_t buf_len);

/**
 * Functions for using with STRING_extractAbstract
 */

/**
 * Searching		XX
 * From				aXXbcXXd
 * Return value points to b.
 */
const char* find_charAfterStrn(const char *str, const char *findIt);

/**
 * Searching		XX
 * From				aXXbcXXd
 * Return value points to a.
 */
const char* find_charBeforeStrn(const char* str, const char* findIt);

/**
 * Searching		XX
 * From				aXXbcXXd
 * Return value points to c.
 */
const char* find_charBeforeLastStrn(const char* str, const char* findIt);

/**
 * Searching		XX
 * From				aXXbcXXd
 * Return value points to d.
 */
const char* find_charAfterLastStrn(const char* str, const char* findIt);

/**
 * Converts a path relative to a reference path if original path is not a full path.
 * \param refFilePah	A reference path.
 * \param origPath		Original path.
 * \param buf			Buffer that is used fit the relative path.
 * \param buf_len		Size of the buffer.
 * \return \c origPath or buf if successful, NULL if an error occurred.
 */
const char *PATH_getPathRelativeToFile(const char *refFilePath, const char *origPath, char *buf, size_t buf_len);

const char *PATH_URI_getPathRelativeToFile(const char *refFilePath, const char *origPath, char *buf, size_t buf_len);
#ifdef	__cplusplus
}
#endif

#endif	/* TOOL_BOX_H */

