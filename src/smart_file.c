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
#include <fcntl.h>

struct SMART_FILE_st {
	char fname[1024];	/* Original file name. */
	char tmp_fname[1024];	/* Temporary file name derived from initial file name. */
	char bak_fname[1024];	/* Backup file name derived from initial file name. */
	char mode[256];
	size_t consistent_position;

	void *file;

	int (*file_open)(const char *fname, const char *mode, char* fname_out_buf, size_t fname_out_buf_len, void **file);
	int (*file_reposition)(void *file, size_t offset);
	int (*file_get_current_position)(void *file, size_t *pos);
	int (*file_truncate)(void *file, size_t pos);
	int (*file_write)(void *file, char *raw, size_t raw_len, size_t *count);
	int (*file_read)(void *file, char *raw, size_t raw_len, size_t *count);
	int (*file_read_line)(void *file, char *raw, size_t raw_len, size_t *row_pointer, size_t *count);
	int (*file_gets)(void *file, char *raw, size_t raw_len, int *eof);
	int (*file_set_lock)(void *file, int lockType);
	int (*file_get_stream)(const char *mode, void **stream, int *is_close_mandatory);
	void (*file_close)(void *file);

	int isEOF;
	int isOpen;
	int mustBeFreed;
	int isStream;

	int isConsistent;
	int isTempCreated;
	int isBackupCreated;
	int isTmpStreamBuffer;

};

static int smart_file_open(const char *fname, const char *mode, char* fname_out_buf, size_t fname_out_buf_len, void **file);
static void smart_file_close(void *file);
static int smart_file_reposition(void *file, size_t offset);
static int smart_file_read(void *file, char *raw, size_t raw_len, size_t *count);
static int smart_file_read_line(void *file, char *buf, size_t len, size_t *row_pointer, size_t *count);
static int smart_file_gets(void *file, char *raw, size_t raw_len, int *eof);
static int smart_file_write(void *file, char *raw, size_t raw_len, size_t *count);
static int smart_file_get_stream(const char *mode, void **stream, int *is_close_mandatory);
static int smart_file_get_error(void);
static char* get_pure_mode(const char *mode, char *buf, size_t buf_len);
static int smart_file_get_current_position(void *file, size_t *pos);
static int smart_file_truncate(void *file, size_t pos);
static int smart_file_set_lock(void *file, int lockType);

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
	file->file_gets = smart_file_gets;
	file->file_write = smart_file_write;
	file->file_get_stream = smart_file_get_stream;
	file->file_reposition = smart_file_reposition;
	file->file_get_current_position = smart_file_get_current_position;
	file->file_truncate = smart_file_truncate;
	file->file_set_lock = smart_file_set_lock;

	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_redirect_to_stream(void *from, void *to) {
	int res;
	char buf[0xffff];
	size_t readCount = 0;
	size_t writeCount = 0;

	if (from == NULL || to == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	do {
		res = smart_file_read(from, buf, sizeof(buf), &readCount);
		if (res != SMART_FILE_OK) goto cleanup;

		if (res == SMART_FILE_OK && readCount == 0) {
			break;
		}

		res = smart_file_write(to, buf, readCount, &writeCount);
		if (res != SMART_FILE_OK) goto cleanup;

		if (writeCount != readCount) {
			res = SMART_FILE_UNABLE_TO_WRITE;
			goto cleanup;
		}

	} while (readCount > 0);

	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_open(const char *fname, const char *mode, char* fname_out_buf, size_t fname_out_buf_len, void **file) {
	int res;
	FILE *tmp = NULL;
	char pure_mode[32];
	int is_T = 0;
	int fd = -1;

	if (mode != NULL) {
		is_T = strchr(mode, 'T') == NULL ? 0 : 1;
	}

	if ((fname == NULL && !is_T) || mode == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	if (fname_out_buf != NULL) {
		fname_out_buf[0] = '\0';
	}

	/* Open nameless temporary file. */
	if (fname == NULL && is_T) {
		tmp = tmpfile();
	/* Open temporary file with name. */
	} else if (is_T){
		char temporaryName[2048];
		mode_t prev;

		KSI_snprintf(temporaryName, sizeof(temporaryName), "%sXXXXXX", fname);

		prev = umask(077);
		fd = mkstemp(temporaryName);
		umask(prev);

		if (fd == -1) {
			res = SMART_FILE_UNABLE_TO_OPEN;
			goto cleanup;
		}

		close(fd);
		fd = -1;
		if (fname_out_buf != NULL) {
			KSI_strncpy(fname_out_buf, temporaryName, fname_out_buf_len);
		}

		tmp = fopen(temporaryName, get_pure_mode(mode, pure_mode, sizeof(pure_mode)));
	/* Open File with name. */
	} else {
		tmp = fopen(fname, get_pure_mode(mode, pure_mode, sizeof(pure_mode)));
	}

	if (tmp == NULL) {
		res = smart_file_get_error();
		res = (res == SMART_FILE_UNKNOWN_ERROR) ? SMART_FILE_UNABLE_TO_OPEN : res;
		goto cleanup;
	}

	*file = (void*)tmp;
	tmp = NULL;
	res = SMART_FILE_OK;

cleanup:

	if (fd != -1) close(fd);
	smart_file_close(tmp);

	return res;
}

static void smart_file_close(void *file) {
	FILE *tmp = file;
	if (file == NULL) return;
	fclose(tmp);
}

static int smart_file_reposition(void *file, size_t offset) {
	int res;
	FILE *fp = NULL;

	if (file == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	fp = file;
	res = fseeko(fp, (off_t)offset, SEEK_SET);
	if (res != 0) {
		res = SMART_FILE_UNABLE_TO_REPOSITION;
		goto cleanup;
	}

	res = SMART_FILE_OK;

cleanup:


	return res;
}

static int smart_file_get_current_position(void *file, size_t *pos) {
	int res;
	FILE *fp = NULL;
	off_t tmp;

	if (file == NULL || pos == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	fp = file;
	tmp = ftello(fp);

	if (tmp == -1) {
		res = SMART_FILE_UNABLE_TO_GET_POSITION;
		goto cleanup;
	}

	*pos = (size_t)tmp;

	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_truncate(void *file, size_t pos) {
	int res;
	FILE *fp = file;
	off_t position = pos;

	if (file == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	res = smart_file_reposition(file, pos);
	if (res != SMART_FILE_OK) goto cleanup;

	if(ftruncate(fileno(fp), position) != 0) {
		res = SMART_FILE_UNABLE_TO_TRUNCATE;
		goto cleanup;
	}

	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_set_lock(void *file, int lockType) {
	int res;
	FILE *fp = file;
	struct flock lock;

	if (file == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	lock.l_type = (lockType == SMART_FILE_READ_LOCK) ? F_RDLCK : F_WRLCK;;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0; /* From the beginning of the file. */
	lock.l_len = 0;	/* To the end of the file. */

	res = fcntl(fileno(fp), F_SETLK, &lock);
	if (res != 0) {
		res = SMART_FILE_UNABLE_TO_LOCK;
		goto cleanup;
	}

	res = SMART_FILE_OK;

cleanup:

	return res;
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
	while ((c = fgetc(fp)) != 0) {
		if (c != EOF && lineSize >= len - 1) {
			buf[len - 1] = '\0';
			*count = lineSize;
			res = SMART_FILE_BUFFER_TOO_SMALL;
			goto cleanup;
		}

		if (c == EOF || (c == '\r' || c == '\n')) {
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
			buf[lineSize++] = (char)c;
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


static int smart_file_gets(void *file, char *raw, size_t raw_len, int *eof) {
	int res;
	FILE *fp = file;
	char *ret = NULL;

	if (file == NULL || raw == NULL || raw_len == 0 || eof == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	*eof = 0;

	ret = fgets(raw, (int)raw_len, fp);
	if (ret == NULL && !feof(fp)) {
		res = SMART_FILE_UNABLE_TO_READ;
		goto cleanup;
	} else if (ret == NULL && feof(fp)) {
		res = SMART_FILE_OK;
		*eof = 1;
	}

	res = SMART_FILE_OK;

cleanup:

	return res;
}

static int smart_file_get_stream(const char *mode, void **stream, int *is_close_mandatory) {
	int res;
	int is_r = 0;
	int is_w = 0;
	int is_e = 0;
	FILE *fp = NULL;

	if (mode == NULL || stream == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	is_r = strchr(mode, 'r') == NULL ? 0 : 1;
	is_w = strchr(mode, 'w') == NULL ? 0 : 1;
	is_e = strchr(mode, 'e') == NULL ? 0 : 1;


	if (is_r) {
		fp = stdin;
	} else if (is_w) {
		fp = is_e ? stderr : stdout;
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
	int correction = 1;

	/**
	 * Extract the files extension.
	 */
	ret = STRING_extractAbstract(fname, ".", NULL, ext, sizeof(ext), find_charAfterLastStrn, NULL, NULL);
	is_extension = (ret == ext) ? 1 : 0;

	if (is_extension) {
		root_offset += (int)strlen(ext);
		correction = 0;
	}

	KSI_strncpy(root, fname, strlen(fname) - root_offset + correction);

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


static char* get_pure_mode(const char *mode, char *buf, size_t buf_len) {
	size_t i = 0;
	size_t n = 0;

	if (mode == NULL || buf == NULL || buf_len == 0) return NULL;

	buf[0] = '\0';
	for (i = 0; mode[i] != '\0' && n < (buf_len - 1); i++) {
		char m = mode[i];

		if (m == 'w' || m == 'r' || m == '+' || m == 'a' || m == 'b') {
			buf[n++] = m;
		}
	}
	buf[n] = '\0';

	return buf;
}

int SMART_FILE_open(const char *fname, const char *mode, SMART_FILE **file) {
	int res;
	SMART_FILE *tmp = NULL;
	int must_free = 0;
	int isStream = 0;
	const char *pFname = fname;
	const char *pBackupFname = NULL;
	char buf[2048];
	char backupName[2048];

	int is_e;
	int is_w;
	int is_f;
	int is_i;
	int is_B;
	int is_T;
	int is_X;


	if (fname == NULL || mode == NULL || file == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}


	isStream = (strcmp(fname, "-") == 0 && strchr(mode, 's') != NULL) ? 1 : 0;
	is_e = strchr(mode, 'e') == NULL ? 0 : 1;
	is_w = strchr(mode, 'w') == NULL ? 0 : 1;
	is_f = strchr(mode, 'f') == NULL ? 0 : 1;
	is_i = strchr(mode, 'i') == NULL ? 0 : 1;
	is_B = strchr(mode, 'B') == NULL ? 0 : 1;
	is_T = strchr(mode, 'T') == NULL ? 0 : 1;
	is_X = strchr(mode, 'X') == NULL ? 0 : 1;


	/* Reject bad combinations. */
	if (   (is_B && !(is_i || is_T)) /* Backup without temporary files or backup file indexing. */
		|| (is_B && isStream) /* Stream with backup file. */
		|| (!is_w && is_X) /* Read mode with X - it only works in write mode. */
		|| (!is_w && is_T && isStream) /* Read mode stream with output temporary file buffer. */
		|| (!is_w && (is_B || is_T || is_i || is_f)) /* Read mode with backups and temporary files is not logical. */
		|| (!is_w && is_e) /* Read mode from stderr does not work. */
		) {
		res = SMART_FILE_INVALID_MODE;
		goto cleanup;
	}

	/**
	 * Some special flags that should be checked before going ahead.
	 */
	if (!isStream) {
		/* If file already exists try to resolve the case.
		   By default file is overwritten! */
		if (is_w && SMART_FILE_doFileExist(fname)) {
			/* If overwrite is strictly restricted, raise the error! */
			if (is_f) {
				res = SMART_FILE_OVERWRITE_RESTRICTED;
				goto cleanup;
			/* If a backup is required, resolve its name. */
			} else if (is_B) {
				/* With i combination, there can be multiple backups. Otherwise last backup is replaced with new one. */
				if (is_i) {
					char initial_backup_file_name[2048];
					KSI_snprintf(initial_backup_file_name, sizeof(initial_backup_file_name), "%s.bak", fname);

					if (SMART_FILE_doFileExist(initial_backup_file_name)) {
						pBackupFname = generate_not_existing_file_name(initial_backup_file_name, backupName, sizeof(backupName), 1);
					} else {
						KSI_strncpy(backupName, initial_backup_file_name, sizeof(backupName));
						pBackupFname = backupName;
					}
				} else {
					KSI_snprintf(backupName, sizeof(backupName), "%s.bak", fname);
					pBackupFname = backupName;
				}
			/* With i all files are kept and index number is applied. */
			} else if (is_i) {
				pFname = generate_not_existing_file_name(fname, buf, sizeof(buf), 1);
			}
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
	tmp->bak_fname[0] = '\0';
	tmp->tmp_fname[0] = '\0';
	tmp->isEOF = 0;
	tmp->isOpen = 0;
	tmp->mustBeFreed = 0;
	tmp->isConsistent = 0;
	tmp->isTempCreated = 0;
	tmp->isBackupCreated = 0;
	tmp->isStream = isStream;
	tmp->isTmpStreamBuffer = isStream && is_T;
	tmp->consistent_position = 0;

	/* Make a copy from the file names. */
	KSI_strncpy(tmp->fname, pFname, sizeof(tmp->fname));
	KSI_strncpy(tmp->mode, mode, sizeof(tmp->mode));
	if (is_B && pBackupFname) KSI_strncpy(tmp->bak_fname, pBackupFname, sizeof(tmp->bak_fname));

	/**
	 * Initialize implementations.
	 */
	res = smart_file_init(tmp);
	if (res != SMART_FILE_OK) goto cleanup;

	/* If there is a need to create a backup IMMEDIATELY (no tmp file is used) do it NOW! */
	if (is_B && !is_T && tmp->bak_fname[0] != '\0') {
		res = SMART_FILE_rename(tmp->fname, tmp->bak_fname);
		if (res != SMART_FILE_OK) goto cleanup;

		tmp->isBackupCreated = 1;
	}

	/**
	 * If standard strem is wanted, extract the stream object. Otherwise use
	 * smart file opener function.
	 */
	if (isStream && !is_T) {
		res = tmp->file_get_stream(mode, &(tmp->file), &must_free);
		if (res != SMART_FILE_OK) goto cleanup;
		tmp->mustBeFreed = must_free;
	} else if (tmp->isTmpStreamBuffer) {
		res = tmp->file_open(NULL, mode, NULL, 0, &(tmp->file));
		if (res != SMART_FILE_OK) goto cleanup;
		tmp->mustBeFreed = 1;
		tmp->isTempCreated = 1;
	} else if (is_T) {
		res = tmp->file_open(pFname, mode, tmp->tmp_fname, sizeof(tmp->tmp_fname), &(tmp->file));
		if (res != SMART_FILE_OK) goto cleanup;
		tmp->mustBeFreed = 1;
		tmp->isTempCreated = 1;
	} else {
		res = tmp->file_open(pFname, mode, NULL, 0, &(tmp->file));
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

	/* In case of a failure rename the original file back. */
	if (tmp != NULL && tmp->isBackupCreated && res != SMART_FILE_OK) {
		// TODOD: Somehow make sure that original file is not corrupted!
		SMART_FILE_rename(tmp->bak_fname, tmp->fname);
	}

	SMART_FILE_close(tmp);

	return res;
}

int SMART_FILE_close(SMART_FILE *file) {
	int res = SMART_FILE_UNKNOWN_ERROR;
	int is_B = 0;
	int is_T = 0;
	int is_X = 0;
	void *stream = NULL;
	int is_stream_close_mandatory = 0;
	int need_to_close_the_file = 0;


	if (file != NULL) {
		is_B = strchr(file->mode, 'B') == NULL ? 0 : 1;
		is_T = strchr(file->mode, 'T') == NULL ? 0 : 1;
		is_X = strchr(file->mode, 'X') == NULL ? 0 : 1;

		need_to_close_the_file = file->mustBeFreed && file->file != NULL && file->file_close != NULL;

		/* Handle a stream that is buffered in nameless temporary file.
		   Get stream, rewind temporary file to beginning, redirect entire file to stream. */
		if (is_T && file->isTmpStreamBuffer && file->isConsistent) {
			/* Sanity check. */
			if (file->file == NULL || !file->isTempCreated) {
				res = SMART_FILE_UNKNOWN_ERROR;
				goto cleanup;
			}

			/* Get stream. */
			res = file->file_get_stream(file->mode, &stream, &is_stream_close_mandatory);
			if (res != SMART_FILE_OK) goto cleanup;

			/* Rewind temporary file. */
			res = file->file_reposition(file->file, 0);
			if (res != SMART_FILE_OK) goto cleanup;

			/* Print tmp file into stream. */
			res = smart_file_redirect_to_stream(file->file, stream);
			if (res != SMART_FILE_OK) goto cleanup;
		}

		if (need_to_close_the_file) {
			/* If there is a request and possibility to flush the not consistent end of the file, do it before close. */
			if (is_X && (!file->isStream || file->isTmpStreamBuffer)) {
				res = file->file_truncate(file->file, file->consistent_position);
				if (res != SMART_FILE_OK) goto cleanup;
			}

			file->file_close(file->file);
			need_to_close_the_file = 0;
		}

		/* After temporary nameless file is used and closed (also deleted) goto cleanup. */
		if (file->isTmpStreamBuffer) {
			res = SMART_FILE_OK;
			goto cleanup;
		}

		/* If file is not marked as consistent, there may be some extra cleanup to do. */
		if (file->isConsistent) {
			if (is_T && file->isTempCreated) {
				/* Make original file backup (if there is a need to backup anything) and tmp file persistent. */
				if (is_B && !file->isBackupCreated && file->bak_fname[0] != '\0') {
					res = SMART_FILE_rename(file->fname, file->bak_fname);
					if (res != SMART_FILE_OK) goto cleanup;
					file->isBackupCreated = 1;
				/* Make temporary file persistent, remove existing file. */
				} else if (!is_B) {
					if (SMART_FILE_doFileExist(file->fname)) {
						res = SMART_FILE_remove(file->fname);
						if (res != SMART_FILE_OK) goto cleanup;
					}
				}

				res = SMART_FILE_rename(file->tmp_fname, file->fname);
				if (res != SMART_FILE_OK) goto cleanup;
			}
		} else {
			/* A backup was created, remove inconsistent file and rename original file back. */
			if (file->isBackupCreated) {
				// TODOD: Somehow make sure that original file is not corrupted!

				res = SMART_FILE_remove(file->fname);
				if (res != SMART_FILE_OK) goto cleanup;

				res = SMART_FILE_rename(file->bak_fname, file->fname);
				if (res != SMART_FILE_OK) goto cleanup;
			}

			/* A temporary file was created, remove it as it is not used. */
			if (file->isTempCreated && file->tmp_fname[0] != '\0') {
				res = SMART_FILE_remove(file->tmp_fname);
				if (res != SMART_FILE_OK) goto cleanup;
			}
		}
	}

	res = SMART_FILE_OK;

cleanup:
	if (need_to_close_the_file) file->file_close(file->file);
	if (file != NULL) free(file);

	if (is_stream_close_mandatory && stream != NULL && file != NULL && file->file_close != NULL) {
		file->file_close(stream);
	}

	return res;
}

int SMART_FILE_markConsistent(SMART_FILE *file) {
	int res;
	size_t tmp = 0;
	int is_X = 0;

	if (file == NULL) return SMART_FILE_INVALID_ARG;
	if (!file->isOpen) return SMART_FILE_NOT_OPEND;
	file->isConsistent = 1;

	is_X = strchr(file->mode, 'X') == NULL ? 0 : 1;

	if (is_X && (!file->isStream || file->isTmpStreamBuffer)) {
		res = file->file_get_current_position(file->file, &tmp);
		if (res != SMART_FILE_OK) return res;

		file->consistent_position = tmp;
	}

	return SMART_FILE_OK;
}

int SMART_FILE_markInconsistent(SMART_FILE *file) {
	if (file == NULL) return SMART_FILE_INVALID_ARG;
	if (!file->isOpen) return SMART_FILE_NOT_OPEND;
	file->isConsistent = 0;
	return SMART_FILE_OK;
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

int SMART_FILE_gets(SMART_FILE *file, char *raw, size_t raw_len, size_t *count) {
	int res;
	int isEof = 0;

	if (file == NULL || raw == NULL || raw_len == 0) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	if (file->file != NULL && file->isOpen) {
		res = file->file_gets(file->file, raw, raw_len, &isEof);
		if (res != SMART_FILE_OK) goto cleanup;

		file->isEOF = isEof;
	} else {
		return SMART_FILE_NOT_OPEND;
	}

	if (count != NULL) {
		*count = strlen(raw);
	}

	res = SMART_FILE_OK;

cleanup:

	return res;
}

int SMART_FILE_lock(SMART_FILE *file, int lock) {
	int res;

	if (file == NULL || (lock != SMART_FILE_READ_LOCK && lock != SMART_FILE_WRITE_LOCK)) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	if (file->file != NULL && file->isOpen) {
		res = file->file_set_lock(file->file, lock);
		if (res != SMART_FILE_OK) goto cleanup;
	} else {
		return SMART_FILE_NOT_OPEND;
	}

	res = SMART_FILE_OK;

cleanup:

	return res;
}

int SMART_FILE_rewind(SMART_FILE *file) {
	int res;

	if (file == NULL) {
		res = SMART_FILE_INVALID_ARG;
		goto cleanup;
	}

	if (file->file != NULL && file->isOpen) {
		res = file->file_reposition(file->file, 0);
		if (res != SMART_FILE_OK) goto cleanup;
	} else {
		return SMART_FILE_NOT_OPEND;
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

const char *SMART_FILE_getTmpFname(SMART_FILE *file) {
	if (file == NULL) return NULL;
	if (file->isOpen == 0 || file->isTempCreated == 0) return NULL;

	return file->tmp_fname;
}

int SMART_FILE_isEof(SMART_FILE *file) {
	if (file == NULL) return 0;
	if (file->isOpen == 0) return 0;
	return file->isEOF;
}

int SMART_FILE_isStream(SMART_FILE *file) {
	if (file == NULL) return 0;
	if (file->isOpen == 0) return 0;
	return file->isStream;
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

int SMART_FILE_rename(const char *old_path, const char *new_path) {
	int res;

	if (old_path == NULL || new_path == NULL) return SMART_FILE_INVALID_ARG;

	res = rename(old_path, new_path);
	res = (res != 0) ? smart_file_get_error() : SMART_FILE_OK;

	return res;
}

int SMART_FILE_remove(const char *fname) {
	int res;

	if (fname == NULL) return SMART_FILE_INVALID_ARG;

	res = remove(fname);
	res = (res != 0) ? smart_file_get_error() : SMART_FILE_OK;

	return res;
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
		case SMART_FILE_UNABLE_TO_GET_POSITION:
			return "Unable to get file internal pointer.";
		case SMART_FILE_UNABLE_TO_REPOSITION:
			return "Unable to reposition file internal pointer.";
		case SMART_FILE_UNABLE_TO_TRUNCATE:
			return "Unable truncate file.";
		case SMART_FILE_UNABLE_TO_LOCK:
			return "Unable set file lock.";
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
