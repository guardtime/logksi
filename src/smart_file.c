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
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ksi/compatibility.h>
#include "smart_file.h"
#include "tool_box.h"

#include <unistd.h>
#define OPENF

#include <sys/types.h>
#include <sys/stat.h>

struct SMART_FILE_st {
	char fname[1024];
	void *file;

	int (*file_open)(const char *fname, const char *mode, void **file);
	int (*file_write)(void *file, char *raw, size_t raw_len, size_t *count);
	int (*file_read)(void *file, char *raw, size_t raw_len, size_t *count);
	int (*file_read_line)(void *file, char *raw, size_t raw_len, size_t *row_pointer, size_t *count);
	int (*file_get_stream)(const char *mode, void **stream, int *is_close_mandatory);
	void (*file_close)(void *file);

	int isEOF;
	int isOpen;
	int mustBeFreed;
};

static int smart_file_open(const char *fname, const char *mode, void **file);
static void smart_file_close(void *file);
static int smart_file_read(void *file, char *raw, size_t raw_len, size_t *count);
static int smart_file_read_line(void *file, char *buf, size_t len, size_t *row_pointer, size_t *count);
static int smart_file_write(void *file, char *raw, size_t raw_len, size_t *count);
static int smart_file_get_stream(const char *mode, void **stream, int *is_close_mandatory);
static int smart_file_get_error(void);


static int is_access(const char *path, int mode) {
	int res;
	if (path == NULL) return 0;
	res = access(path, mode) == 0 ? 1 : 0;
	return res;
}

static int smart_file_init(SMART_FILE *file) {
	int res;

	if (file == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	file->file = NULL;
	file->file_open = smart_file_open;
	file->file_close = smart_file_close;
	file->file_read = smart_file_read;
	file->file_read_line = smart_file_read_line;
	file->file_write = smart_file_write;
	file->file_get_stream = smart_file_get_stream;

	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_open(const char *fname, const char *mode, void **file) {
	int res;
	FILE *tmp = NULL;

	if (fname == NULL || mode == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}


	if (fname == NULL || mode == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	tmp = fopen(fname, mode);
	if (tmp == NULL) {
		res = smart_file_get_error();
		res = (res == SMART_FILE_UNKNOWN_ERROR) ? SMART_FILE_UNABLE_TO_OPEN : res;
		goto cleanup;
	}

	*file = (void*)tmp;
	tmp = NULL;
	res = SMART_FILE_OK;

cleanup:

	smart_file_close(tmp);

	return res;
}

static void smart_file_close(void *file) {
	FILE *tmp = file;
	if (file == NULL) return;
	fclose(tmp);
}

static int smart_file_read(void *file, char *raw, size_t raw_len, size_t *count) {
	int res;
	FILE *fp = file;
	size_t read_count = 0;

	if (file == NULL || raw == NULL || raw_len == 0) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	read_count = fread(raw, 1, raw_len, fp);
	/* TODO: Improve error handling.*/
	if (read_count == 0 && !feof(fp)) {
		res = smart_file_get_error();
		res = (res == SMART_FILE_UNKNOWN_ERROR) ? SMART_FILE_UNABLE_TO_READ : res;
		goto cleanup;
	}


	if (count != NULL) {
		*count = (size_t)read_count;
	}

	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_read_line(void *file, char *buf, size_t len, size_t *row_pointer, size_t *count) {
	int res = SMART_FILE_UNKNOWN_ERROR;
	int c;
	FILE *fp = file;
	size_t lineSize = 0;
	size_t line_count = 0;
	int is_line_open = 0;

	if (file == NULL || buf == NULL || len == 0 || count == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}
	buf[0] = '\0';

	/**
	 * Unix LF 0x0A \n.
	 * Windows CR LF 0x0D 0x0A \r \n.
	 * Mac LF and possibly CR.
	 */
	while ((c = fgetc(fp)) != 0 && lineSize < len - 1) {
		if (c == EOF || (c == 0x0D || c == 0x0A)) {
			if (c == '\r') {
				fpos_t position;
				int next_char;

				fgetpos(fp, &position);
				next_char = fgetc(fp);
				if (next_char != '\n') {
					fsetpos(fp, &position);
				}
			}

			line_count++;
			if (c == EOF) break;
		}

		if (c != '\r' && c != '\n') {
			is_line_open = 1;
			buf[lineSize++] = 0xff & c;
		} else if (is_line_open) {
			break;
		}
	}
	buf[lineSize] = '\0';

	if (row_pointer != NULL) {
		*row_pointer += line_count;
	}

	*count = lineSize;
	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_write(void *file, char *raw, size_t raw_len, size_t *count) {
	int res;
	FILE *fp = file;
	size_t write_count = 0;

	if (file == NULL || raw == NULL || raw_len == 0) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	write_count = fwrite(raw, 1, raw_len, fp);

	if (write_count != raw_len) {
		res = smart_file_get_error();
		res = (res == SMART_FILE_UNKNOWN_ERROR) ? SMART_FILE_UNABLE_TO_WRITE : res;
		goto cleanup;
	}

	if (count != NULL) {
		*count = (size_t)write_count;
	}

	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_get_stream(const char *mode, void **stream, int *is_close_mandatory) {
	int res;
	int is_r = 0;
	int is_w = 0;
	FILE *fp = NULL;

	if (mode == NULL || stream == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	is_r = strchr(mode, 'r') == NULL ? 0 : 1;
	is_w = strchr(mode, 'w') == NULL ? 0 : 1;


	if (is_r) {
		fp = stdin;
	} else if (is_w) {
		fp = stdout;
	} else {
		res = SMART_FILE_INVALID_MODE;
		goto cleanup;
	}

	*is_close_mandatory = 0;
	*stream = fp;
	fp = NULL;

	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_get_error(void) {
	int error_code = 0;
	int smart_file_error_code = 0;


	error_code = errno;

	switch(error_code) {
		case 0:
			smart_file_error_code =  SMART_FILE_OK;
		break;

		case ENOENT:
			smart_file_error_code =  SMART_FILE_DOES_NOT_EXIST;
		break;

		case EACCES:
			smart_file_error_code =  SMART_FILE_ACCESS_DENIED;
		break;

		case EINVAL:
			smart_file_error_code =  SMART_FILE_INVALID_PATH;
		break;

		default:
			smart_file_error_code = SMART_FILE_UNKNOWN_ERROR;
		break;
	}

	return smart_file_error_code;
}

static int file_get_type(const char *path, int *type) {
	int res = 0;
	struct stat status;
	int tmp = SMART_FILE_TYPE_UNKNOWN;

	if (path == NULL || type == NULL) return SMART_FILE_INVALID_ARG;

	res = stat(path, &status);
	if (res != 0) return SMART_FILE_UNABLE_TO_GET_STATUS;

	if (S_ISDIR(status.st_mode)) tmp = SMART_FILE_TYPE_DIR;
	else if (S_ISREG(status.st_mode)) tmp = SMART_FILE_TYPE_REGULAR;
	else tmp = SMART_FILE_TYPE_UNKNOWN;

	*type = tmp;

	return SMART_FILE_OK;
}

char *generate_file_name(const char *fname, int count, char *buf, size_t buf_len) {
	char *ret = NULL;
	char ext[1024] = "";
	char root[1024] = "";
	int is_extension = 0;
	int root_offset = 0;

	/**
	 * Extract the files extension.
	 */
	ret = STRING_extractAbstract(fname, ".", NULL, ext, sizeof(ext), find_charAfterLastStrn, NULL, NULL);
	is_extension = (ret == ext) ? 1 : 0;

	if (is_extension) {
		root_offset += (int)strlen(ext);
	}

	KSI_strncpy(root, fname, strlen(fname) - root_offset);

	KSI_snprintf(buf, buf_len, "%s_%i%s%s", root, count,
		is_extension ? "." : "",
		is_extension ? ext : "");
	return buf;
}

const char *generate_not_existing_file_name(const char *fname, char *buf, size_t buf_len, int use_binary_search) {
	const char *pFname = fname;
	int i = 1;
	unsigned ceil = 16;
	int j = 1;
	int a = 0;
	int b = 0;
	int d = 0;

	if (fname == NULL || buf == NULL || buf_len == 0) return NULL;

	/**
	 * Support for binary search algorithm.
	 */
	if (use_binary_search) {
		/**
		 * Search the highest file name that does not exist.
		 */
		do {
			ceil <<=1;
			pFname = generate_file_name(fname, ceil, buf, buf_len);
			if (pFname == NULL) return NULL;
		} while (SMART_FILE_doFileExist(pFname));

		/**
		 * Use the binary search algorithm to find file name range.
		 */
		a = j;
		b = ceil;
		do {
			j = (a + b) / 2;
			d = b - a;

			pFname = generate_file_name(fname, j, buf, buf_len);
			if (pFname == NULL) return NULL;


			if (SMART_FILE_doFileExist(pFname)) {
				a = j;
			} else {
				b = j;
			}
		} while (d > 2);
		i = a;
	}

	do {
		pFname = generate_file_name(fname, i++, buf, buf_len);
		if (pFname == NULL) return NULL;
	} while (SMART_FILE_doFileExist(pFname));

	return pFname;
}


int SMART_FILE_open(const char *fname, const char *mode, SMART_FILE **file) {
	int res;
	SMART_FILE *tmp = NULL;
	int must_free = 0;
	int isStream = 0;
	const char *pFname = fname;
	char buf[2048];

	int is_w;
	int is_f;
	int is_i;

	if (fname == NULL || mode == NULL || file == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}


	isStream = (strcmp(fname, "-") == 0 && strchr(mode, 's') != NULL) ? 1 : 0;
	is_w = strchr(mode, 'w') == NULL ? 0 : 1;
	is_f = strchr(mode, 'f') == NULL ? 0 : 1;
	is_i = strchr(mode, 'i') == NULL ? 0 : 1;

	/**
	 * Some special flags that should be checked before going ahead.
	 */
	if (!isStream) {
		if (is_w && is_f && SMART_FILE_doFileExist(fname)) {
			res = SMART_FILE_OVERWRITE_RESTRICTED;
			goto cleanup;
		}

		if (is_w && is_i && SMART_FILE_doFileExist(fname)) {
			pFname = generate_not_existing_file_name(fname, buf, sizeof(buf), 1);
		}
	}


	tmp = (SMART_FILE*)malloc(sizeof(SMART_FILE));
	if (tmp == NULL) {
		res = SMART_FILE_OUT_OF_MEM;
		goto cleanup;
	}

		/**
	 * Initialize smart file.
	 */
	tmp->file = NULL;
	tmp->fname[0] = '\0';
	tmp->isEOF = 0;
	tmp->isOpen = 0;
	tmp->mustBeFreed = 0;

	KSI_snprintf(tmp->fname, sizeof(tmp->fname), "%s", pFname);


	/**
	 * Initialize implementations.
	 */
	res = smart_file_init(tmp);
	if (res != SMART_FILE_OK) goto cleanup;

	/**
	 * If standard strem is wanted, extract the stream object. Otherwise use
	 * smart file opener function.
	 */
	if (isStream) {
		res = tmp->file_get_stream(mode, &(tmp->file), &must_free);
		if (res != SMART_FILE_OK) goto cleanup;
		tmp->mustBeFreed = must_free;
	} else {
		res = tmp->file_open(pFname, mode, &(tmp->file));
		if (res != SMART_FILE_OK) goto cleanup;
		tmp->mustBeFreed = 1;
	}

	if (res != SMART_FILE_OK) goto cleanup;

	/**
	 * File is opened.
	 */
	tmp->isOpen = 1;
	*file = tmp;
	tmp = NULL;

	res = SMART_FILE_OK;

cleanup:

	SMART_FILE_close(tmp);

	return res;
}

void SMART_FILE_close(SMART_FILE *file) {
	if (file != NULL) {
		if (file->mustBeFreed && file->file != NULL && file->file_close != NULL) {
			file->file_close(file->file);
		}

		free(file);
	}
}

int SMART_FILE_write(SMART_FILE *file, char *raw, size_t raw_len, size_t *count) {
	int res;
	size_t c = 0;

	if (file == NULL || raw == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	if (file->file != NULL && file->isOpen) {
		res = file->file_write(file->file, raw, raw_len, &c);
		if (res != SMART_FILE_OK) goto cleanup;
	} else {
		return SMART_FILE_NOT_OPEND;
	}

	if (count != NULL) {
		*count = c;
	}

	if (c != raw_len) {
		res = SMART_FILE_UNABLE_TO_WRITE;
		goto cleanup;
	}

	res = SMART_FILE_OK;

cleanup:

	return res;
}

int SMART_FILE_read(SMART_FILE *file, char *raw, size_t raw_len, size_t *count) {
	int res;
	size_t c = 0;

	if (file == NULL || raw == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	if (file->file != NULL && file->isOpen) {
		res = file->file_read(file->file, raw, raw_len, &c);
		if (res != SMART_FILE_OK) goto cleanup;
	} else {
		return SMART_FILE_NOT_OPEND;
	}

	/**
	 * EOF is detected as Read finished without an error and read count is zero.
	 */
	if (c == 0) {
		file->isEOF = 1;
	}

	if (count != NULL) {
		*count = c;
	}
	res = SMART_FILE_OK;

cleanup:

	return res;
}
int SMART_FILE_readLine(SMART_FILE *file, char *raw, size_t raw_len, size_t *row_pointer, size_t *count) {
	int res;
	size_t c = 0;

	if (file == NULL || raw == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	if (file->file != NULL && file->isOpen) {
		res = file->file_read_line(file->file, raw, raw_len, row_pointer, &c);
		if (res != SMART_FILE_OK) goto cleanup;
	} else {
		return SMART_FILE_NOT_OPEND;
	}

	/**
	 * EOF is detected as Read finished without an error and read count is zero.
	 */
	if (c == 0) {
		file->isEOF = 1;
	}

	if (count != NULL) {
		*count = c;
	}
	res = SMART_FILE_OK;

cleanup:

	return res;
}

const char *SMART_FILE_getFname(SMART_FILE *file) {
	if (file == NULL) return NULL;
	if (file->isOpen == 0) return NULL;
	return file->fname;
}

int SMART_FILE_isEof(SMART_FILE *file) {
	if (file == NULL) return 0;
	if (file->isOpen == 0) return 0;
	return file->isEOF;
}

int SMART_FILE_doFileExist(const char *path) {
	int res = 0;
	if (path == NULL) return 0;
	res = is_access(path, F_OK);
	return res;
}

int SMART_FILE_isWriteAccess(const char *path) {
	int res = 0;
	if (path == NULL) return 0;
	res = is_access(path, F_OK | W_OK);
	return res;
}

int SMART_FILE_isReadAccess(const char *path) {
	int res = 0;
	if (path == NULL) return 0;
	res = is_access(path, F_OK | R_OK);
	return res;
}

int SMART_FILE_isFileType(const char *path, int ftype) {
	int res;
	int type = SMART_FILE_TYPE_UNKNOWN;

	if (path == NULL) return 0;

	res = file_get_type(path, &type);
	if (res != SMART_FILE_OK) return 0;

	if (type == ftype) return 1;

	return 0;
}

int SMART_FILE_hasFileExtension(const char *path, const char *ext) {
	size_t path_len = 0;
	size_t ext_len = 0;
	const char *pPath = NULL;

	if (path == NULL || ext == NULL) return 0;

	path_len = strlen(path);
	ext_len = strlen(ext);

	if (ext_len >= path_len) return 0;

	pPath = path + (path_len - ext_len);

	if ((*(pPath - 1) == '.') && strcmp(pPath, ext) == 0) {
		return 1;
	} else {
		return 0;
	}
}

const char* SMART_FILE_errorToString(int error_code) {
	switch (error_code) {
		case SMART_FILE_OK:
			return "OK.";
		case SMART_FILE_OUT_OF_MEM:
			return "Out of memory.";
		case SMART_FILE_INVALID_ARG:
			return "Invalid argument.";
		case SMART_FILE_INVALID_MODE:
			return "Invalid file open mode.";
		case SMART_FILE_UNABLE_TO_OPEN:
			return "Unable to open file.";
		case SMART_FILE_UNABLE_TO_READ:
			return "Unable to read from file.";
		case SMART_FILE_UNABLE_TO_WRITE:
			return "Unable to write to file.";
		case SMART_FILE_BUFFER_TOO_SMALL:
			return "Insufficient buffer size.";
		case SMART_FILE_NOT_OPEND:
			return "File is not opened.";
		case SMART_FILE_DOES_NOT_EXIST:
			return "File does not exist.";
		case SMART_FILE_OVERWRITE_RESTRICTED:
			return "Overwriting is restricted.";
		case SMART_FILE_ACCESS_DENIED:
			return "File access denied.";
		case SMART_FILE_PIPE_ERROR:
			return "Pipe error.";
		case SMART_FILE_INVALID_PATH:
			return "Invalid path.";
		case SMART_FILE_UNABLE_TO_GET_STATUS:
			return "Unable to get file status.";
		case SMART_FILE_UNKNOWN_ERROR:
		default:
			return "Unknown error.";
	}
}
