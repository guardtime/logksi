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

#ifndef SMART_FILE_H
#define	SMART_FILE_H

#define SMART_FILE_ERROR_BASE 0x40001

enum smart_file_enum {
	SMART_FILE_OK = 0x00,
	SMART_FILE_INVALID_ARG = SMART_FILE_ERROR_BASE,
	SMART_FILE_INVALID_PATH,
	SMART_FILE_OUT_OF_MEM,
	SMART_FILE_INVALID_MODE,
	SMART_FILE_UNABLE_TO_OPEN,
	SMART_FILE_UNABLE_TO_READ,
	SMART_FILE_UNABLE_TO_WRITE,
	SMART_FILE_UNABLE_TO_GET_POSITION,
	SMART_FILE_UNABLE_TO_REPOSITION,
	SMART_FILE_UNABLE_TO_TRUNCATE,
	SMART_FILE_UNABLE_TO_LOCK,
	SMART_FILE_BUFFER_TOO_SMALL,
	SMART_FILE_NOT_OPEND,
	SMART_FILE_DOES_NOT_EXIST,
	SMART_FILE_OVERWRITE_RESTRICTED,
	SMART_FILE_ACCESS_DENIED,
	SMART_FILE_PIPE_ERROR,
	SMART_FILE_UNABLE_TO_GET_STATUS,
	SMART_FILE_UNKNOWN_ERROR
};

enum {
	SMART_FILE_TYPE_REGULAR = 0x01,
	SMART_FILE_TYPE_DIR,
	SMART_FILE_TYPE_UNKNOWN,
};

enum {
	SMART_FILE_READ_LOCK = 0x01,
	SMART_FILE_WRITE_LOCK = 0x02
};

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct SMART_FILE_st SMART_FILE;

/**
 * Smart file object that is used to open, read and write files and streams. If user
 * wants to read from stdin or write to stdout, file name '-' must be used with mode
 * r or w accordingly together with s. Output stream is stdout by default but can be
 * changed to stderr with e. If output stream is combined with T a nameless temporary
 * file is created and in case of success it is redirected to output steam.
 *
 * Smart file can handle backup and temporary files. Backup files can be used to create
 * a backup file (keep old file) and in case of failure restore the original file
 * automatically on file close. Temporary file can be used to buffer the working file
 * without touching already existing files until the file is closed. In case of failure
 * temporary file is discarded. A backup file gains a file extension '.bak' and temporary
 * file gains 6 random characters at the end of the files name.
 *
 * What is the difference between i and B? Mode i is meant to be used to save and keep
 * multiple file without overwriting the others and without RENAMING original file.
 * Also it needs no original file restoring as it creates a new file with incremented
 * file name. B is meant to be used to replace existing file with the most recent
 * one and rename the old one to backup. Note that mode B only stores on backup, but
 * nevertheless it can be combined with i to store multiple backups.
 *
 * Note that just mode B is not safe as the backup file may be corrupted thus it
 * is not allowed. B can be used together with T and i (it guarantees that backup file
 * is buffered and is only replaced or created on success).
 *
 * Mode X can be used to to clear not consistent end of the file on close. It may be useful
 * when writing some larger data structure into a file in multiple write cycles. Using
 * #SMART_FILE_markConsistent a consistent point in file marked. If something happens
 * and there is corrupted or not complete data at the end of the file, closing file
 * will drop the data.
 *
 * Success is marked with function #SMART_FILE_markConsistent. If it is not called
 * before #SMART_FILE_close, original file is restored from backup, temporary files
 * are discarded, stream buffered with temporary file is "flushed". With X this
 * marks that up to this position content of the file is consistent.
 *
 * Possible file open modes:
 * r   - for reading.
 * w   - for writing.
 * wf  - fail if exists.
 * wi  - generate new file name as name[num++].ext
 * rs  - enable operations on stdin.
 * ws  - enable operations on stdout.
 * wse - enable operations on stderr.
 * wsT[e]
 *     - Use nameless temporary file to store all the data before redirecting it
 *       to stdout or stderr. In case of success data is redirected to stream and
 *       temporary file is removed. In case of failure data is discarded.
 * wBi, wBT[i]
 *     - Original file is kept as backup file and can be restored. Note that when
 *       a backup already exists with just T it is overwritten or with i multiple
 *       backups are kept.
 * wT[i]
 *     - Temporary file is used until file close. In case of success temporary
 *       file is renamed.
 * wX[T]
 *     - Possibility to clear not consistent end of the file. Can be combined
 *       with modes where output is directly written to a file (yes it works with
 *       wsT combination). Suggest to use with T.
 * \param fname file name to be used.
 * \param mode	file open mode.
 * \param file	smart file return pointer.
 * \return SMART_FILE_OK if successful, error code otherwise.
 */
int SMART_FILE_open(const char *fname, const char *mode, SMART_FILE **file);

int SMART_FILE_close(SMART_FILE *file);
int SMART_FILE_write(SMART_FILE *file, unsigned char *raw, size_t raw_len, size_t *count);
int SMART_FILE_read(SMART_FILE *file, unsigned char *raw, size_t raw_len, size_t *count);

/**
 * This function is used to read not empty lines from a file. The newline character
 * (linux/mac/win) is dropped. The \c row_pointer is incremented with the count
 * of lines processed (note that empty lines are skipped). When buffer is too small
 * (SMART_FILE_BUFFER_TOO_SMALL) it is still filled with valid data and next read
 * operation will continue reading the line.
 * \param file			SMART_FILE object.
 * \param raw			Buffer to store the line.
 * \param raw_len		Size of the buffer.
 * \param row_pointer	A pointer to increment the line number. Must start with 0.
 * \param count			Return pointer of he size of the output string.
 * \return SMART_FILE_OK if successful, error code otherwise. When buffer is too small
 * SMART_FILE_BUFFER_TOO_SMALL is returned.
 */
int SMART_FILE_readLineSkipEmpty(SMART_FILE *file, char *raw, size_t raw_len, size_t *row_pointer, size_t *count);

/**
 * This function is used to read lines. The newline character (linux/mac/win)
 * is dropped. When buffer is too small (SMART_FILE_BUFFER_TOO_SMALL) it is still
 * filled with valid data and next read operation will continue reading the line.
 * \param file			SMART_FILE object.
 * \param raw			Buffer to store the line.
 * \param raw_len		Size of the buffer.
 * \param count			Return pointer of he size of the output string.
 * \return SMART_FILE_OK if successful, error code otherwise. When buffer is too small
 * SMART_FILE_BUFFER_TOO_SMALL is returned.
 */
int SMART_FILE_readLine(SMART_FILE *file, char *raw, size_t raw_len, size_t *count);
int SMART_FILE_gets(SMART_FILE *file, char *raw, size_t raw_len, size_t *count);
int SMART_FILE_rewind(SMART_FILE *file);
int SMART_FILE_lock(SMART_FILE *file, int lock);
int SMART_FILE_markConsistent(SMART_FILE *file);
int SMART_FILE_markInconsistent(SMART_FILE *file);

const char *SMART_FILE_getFname(SMART_FILE *file);
const char *SMART_FILE_getTmpFname(SMART_FILE *file);

/**
 *
 * @param file
 * @return A non-zero value is returned in the case that the end-of-file indicator associated with the stream is set.
 * Otherwise, zero is returned.
 */
int SMART_FILE_isEof(SMART_FILE *file);
int SMART_FILE_isStream(SMART_FILE *file);

int SMART_FILE_doFileExist(const char *path);
int SMART_FILE_isWriteAccess(const char *path);
int SMART_FILE_isReadAccess(const char *path);
int SMART_FILE_hasFileExtension(const char *path, const char *ext);
int SMART_FILE_isFileType(const char *path, int ftype);
int SMART_FILE_rename(const char *old_path, const char *new_path);
int SMART_FILE_remove(const char *fname);

const char* SMART_FILE_errorToString(int error_code);

#ifdef	__cplusplus
}
#endif

#endif	/* SMART_FILE_H */

