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

#include <string.h>
#include <stdlib.h>
#include <ksi/ksi.h>
#include <ksi/tlv_element.h>
#include "io_files.h"
#include "logksi_err.h"
#include "param_set/strn.h"


int concat_names(char *org, const char *extension, char **derived) {
	int res;
	char *buf = NULL;

	if (org == NULL || extension == NULL || derived == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}
	buf = (char*)KSI_malloc(strlen(org) + strlen(extension) + 1);
	if (buf == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}
	sprintf(buf, "%s%s", org, extension);
	*derived = buf;
	res = KT_OK;

cleanup:

	return res;
}

int duplicate_name(char *in, char **out) {
	int res;
	char *tmp = NULL;

	if (in == NULL || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = strdup(in);
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	*out = tmp;
	res = KT_OK;

cleanup:

	return res;
}

static void logksi_filename_free(char **ptr) {
	if (ptr != NULL && *ptr != NULL) {
		KSI_free(*ptr);
		*ptr = NULL;
	}
}

void logksi_internal_filenames_free(INTERNAL_FILE_NAMES *internal) {
	if (internal != NULL) {
		logksi_filename_free(&internal->inLog);
		logksi_filename_free(&internal->inSig);
		logksi_filename_free(&internal->outSig);
		logksi_filename_free(&internal->outProof);
		logksi_filename_free(&internal->outLog);
		logksi_filename_free(&internal->partsBlk);
		logksi_filename_free(&internal->partsSig);
	}
}

void logksi_file_close(SMART_FILE **ptr) {
	if (ptr != NULL && *ptr != NULL) {
		SMART_FILE_close(*ptr);
		*ptr = NULL;
	}
}

void logksi_files_close(INTERNAL_FILE_HANDLES *files) {
	if (files != NULL) {

		logksi_file_close(&files->inLog);
		logksi_file_close(&files->inSig);
		logksi_file_close(&files->outSig);
		logksi_file_close(&files->outProof);
		logksi_file_close(&files->outLog);
		logksi_file_close(&files->partsBlk);
		logksi_file_close(&files->partsSig);
	}
}

void IO_FILES_init(IO_FILES *files) {
	if (files != NULL) {
		memset(&files->user, 0, sizeof(USER_FILE_NAMES));
		memset(&files->internal, 0, sizeof(INTERNAL_FILE_NAMES));
		memset(&files->files, 0, sizeof(INTERNAL_FILE_HANDLES));

		files->previousLogFile[0] = '\0';
		files->previousSigFile[0] = '\0';
	}
}

void IO_FILES_StorePreviousFileNames(IO_FILES *files) {
	if (files == NULL) return;

	/* Make copy of previous file names. */
	if (files->internal.inLog == NULL) {
		PST_strncpy(files->previousLogFile, "stdin", sizeof(files->previousLogFile));
	} else {
		PST_strncpy(files->previousLogFile, files->internal.inLog, sizeof(files->previousLogFile));
	}

	if (files->internal.inSig == NULL) {
		PST_strncpy(files->previousSigFile, "stdin", sizeof(files->previousSigFile));
	} else {
		PST_strncpy(files->previousSigFile, files->internal.inSig, sizeof(files->previousSigFile));
	}
}
