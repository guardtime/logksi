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

#ifndef IO_FILES_H
#define	IO_FILES_H

#include <stddef.h>
#include "smart_file.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
	char *inLog;
	char *inSig;
	char *outLog;
	char *outSig;
	char *outProof;
	char *outBase;
	char bStdinLog;
	char bStdinSig;
} USER_FILE_NAMES;

typedef struct {
	char *inLog;
	char *inSig;
	char *outSig;
	char *outProof;
	char *outKSIBase;
	char *outLineBase;
	char *outLog;
	char *partsBlk;
	char *partsSig;
	char bStdout;
	char bStdoutLog;
	char bStdoutProof;
	char bOverwrite;
} INTERNAL_FILE_NAMES;

typedef struct {
	SMART_FILE *inLog;
	SMART_FILE *inSig;
	SMART_FILE *outSig;
	SMART_FILE *outProof;
	SMART_FILE *outLog;
	SMART_FILE *partsBlk;
	SMART_FILE *partsSig;
} INTERNAL_FILE_HANDLES;

typedef struct {
	/* File names received as parameters from the user. */
	USER_FILE_NAMES user;
	/* File names generated and allocated by logksi. */
	INTERNAL_FILE_NAMES internal;
	/* Files opened by logksi. */
	INTERNAL_FILE_HANDLES files;

	char previousLogFile[4096];
	char previousSigFile[4096];
} IO_FILES;


int concat_names(char *org, const char *extension, char **derived);
int duplicate_name(char *in, char **out);
void logksi_internal_filenames_free(INTERNAL_FILE_NAMES *internal);
void logksi_file_close(SMART_FILE **ptr);
void logksi_files_close(INTERNAL_FILE_HANDLES *files);

void IO_FILES_init(IO_FILES *files);
void IO_FILES_StorePreviousFileNames(IO_FILES *files);

#ifdef	__cplusplus
}
#endif

#endif	/* IO_FILES_H */