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
#include <ksi/hash.h>
#include "err_trckr.h"
#include "io_files.h"
#include "logksi_err.h"
#include "param_set/strn.h"
#include "api_wrapper.h"


int merge_path(const char *path[], size_t path_count, const char *fname[], size_t fname_count, char **path_out) {
	size_t i = 0;
	size_t c = 0;
	size_t total_size = 0;	// Terminating NUL char.
	char *buf = NULL;
	int firstValue = -1;

	if ((path == NULL && fname == NULL) || path_out == NULL) return KT_INVALID_ARGUMENT;

	for (i = 0; path != NULL && i < path_count; i++) {
		size_t len = 0;

		if (path[i] != NULL) {
			len = strlen(path[i]) + 1;
		}

		total_size += len;
	}

	for (i = 0; fname != NULL && i < fname_count; i++) {
		if (fname[i] != NULL) total_size += strlen(fname[i]);
	}

	if (total_size == 0) return KT_INVALID_INPUT_FORMAT;

	total_size += 1;
	buf = malloc(total_size);
	if (buf == NULL) return KT_OUT_OF_MEMORY;

	for (i = 0; path != NULL && i < path_count; i++) {
		if (path[i] != NULL) {
			if (c > 0) {
				if (buf[c - 1] != '/') {
					c += PST_snprintf(buf + c, total_size - c, "/");
				}
			}

			c += PST_snprintf(buf + c, total_size - c, "%s", path[i]);
		}
	}
	firstValue = -1;
	for (i = 0; fname != NULL && i < fname_count; i++) {
		if (fname[i] != NULL) {
			if (c > 0 && firstValue < 0) {
				if (buf[c - 1] != '/') {
					c += PST_snprintf(buf + c, total_size - c, "/");
				}
			}
			firstValue = i;

			c += PST_snprintf(buf + c, total_size - c, "%s", fname[i]);
		}
	}

	*path_out = buf;

	return KT_OK;
}

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
		logksi_filename_free(&internal->inRandom);
		logksi_filename_free(&internal->inLog);
		logksi_filename_free(&internal->inSig);
		logksi_filename_free(&internal->outSig);
		logksi_filename_free(&internal->outProof);
		logksi_filename_free(&internal->outKSIBase);
		logksi_filename_free(&internal->outLineBase);
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

		logksi_file_close(&files->inRandom);
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
		files->previousSigFileIn[0] = '\0';
		files->previousSigFileOut[0] = '\0';
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
		PST_strncpy(files->previousSigFileIn, "stdin", sizeof(files->previousSigFileIn));
	} else {
		PST_strncpy(files->previousSigFileIn, files->internal.inSig, sizeof(files->previousSigFileIn));
	}

	if (files->internal.outSig == NULL) {
		PST_strncpy(files->previousSigFileOut, "stdout", sizeof(files->previousSigFileOut));
	} else {
		PST_strncpy(files->previousSigFileOut, files->internal.outSig, sizeof(files->previousSigFileOut));
	}
}

const char *IO_FILES_getCurrentLogFilePrintRepresentation(IO_FILES *files) {
	int logStdin = 0;

	if (files == NULL) return NULL;

	logStdin = files->internal.inLog == NULL;
	return logStdin ? "stdin" : files->internal.inLog;
}

int logksi_save_output_hash(ERR_TRCKR *err, KSI_DataHash *hash, const char *fnameOut, const char *logFile, const char *sigFile) {
	int res;
	SMART_FILE *out = NULL;
	char buf[0xfff];
	char imprint[1024];
	size_t count = 0;
	size_t write_count = 0;

	if (err == NULL || hash == NULL || fnameOut == NULL || logFile == NULL || sigFile == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (hash == NULL) {
		res = KT_INVALID_CMD_PARAM;
		ERR_TRCKR_ADD(err, res, "Error: --output-hash does not work with excerpt signature file.");
		goto cleanup;
	}

	LOGKSI_DataHash_toString(hash, imprint, sizeof(imprint));

	count += PST_snprintf(buf + count, sizeof(buf) - count, "# Log file (%s).\n", logFile);
	count += PST_snprintf(buf + count, sizeof(buf) - count, "# Last leaf from log signature (%s).\n", sigFile);
	count += PST_snprintf(buf + count, sizeof(buf) - count, "%s", imprint);


	res = SMART_FILE_open(fnameOut, "ws", &out);
	ERR_CATCH_MSG(err, res, "Error: Unable to open file '%s'.", fnameOut);

	res = SMART_FILE_write(out, (unsigned char*)buf, count, &write_count);
	ERR_CATCH_MSG(err, res, "Error: Unable to write to file '%s'.", fnameOut);

	if (write_count != count) {
		res = KT_IO_ERROR;
		ERR_TRCKR_ADD(err, res, "Error: Only %zu bytes from %zu written.", write_count, count);
		goto cleanup;
	}

	res = KT_OK;

cleanup:

	SMART_FILE_close(out);

	return res;
}