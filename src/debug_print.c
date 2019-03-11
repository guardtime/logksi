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

#include "debug_print.h"
#include <string.h>
#include "printer.h"
#include "obj_printer.h"
#include "param_set/param_set.h"
#include "tool_box.h"
#include "ksi/compatibility.h"
#include "logksi_err.h"
#include <limits.h>
#include <sys/time.h>

typedef struct MULTI_PRINTER_CHANNEL_st MULTI_PRINTER_CHANNEL;
static int MULTI_PRINTER_CHANNEL_new(int ID, size_t bufferSize, int (*print_func)(const char*, ...), MULTI_PRINTER_CHANNEL **chn);
static void MULTI_PRINTER_CHANNEL_free(MULTI_PRINTER_CHANNEL *root);
static int MULTI_PRINTER_CHANNEL_print(MULTI_PRINTER_CHANNEL *chn);
static int MULTI_PRINTER_CHANNEL_vaWrite(MULTI_PRINTER_CHANNEL *chn, const char *format, va_list va);
static int MULTI_PRINTER_CHANNEL_write(MULTI_PRINTER_CHANNEL *chn, const char *format, ...);

static int MULTI_PRINTER_getChannel(MULTI_PRINTER *mp, int ID, MULTI_PRINTER_CHANNEL **channel);

struct MULTI_PRINTER_CHANNEL_st {
	int ID;

	char *buf;
	size_t buf_len;
	size_t buf_char_count;


	int (*print)(const char *buf, ...);

	unsigned int elapsed_time_ms;
	int inProgress;
	int timerOn;

	struct timespec lastCal;
};


struct MULTI_PRINTER_st {
	MULTI_PRINTER_CHANNEL *channel[MP_ID_COUNT];
	size_t count;

	size_t buf_size;
	int debug_lvl;
};

static unsigned int measureLastCall_(struct timespec *lastCall){
	unsigned int tmp;
	struct timespec thisCall;
	clock_gettime(CLOCK_MONOTONIC, &thisCall);

	tmp = (unsigned)((thisCall.tv_sec - lastCall->tv_sec) * 1000.0 + (thisCall.tv_nsec - lastCall->tv_nsec) / 1000000.0);
	lastCall->tv_sec = thisCall.tv_sec;
	lastCall->tv_nsec = thisCall.tv_nsec;

	return tmp;
}

static int is_print_enabled(int currenDebugLvl, int debugLvl) {
	int print = 0;
	int debugLevel = debugLvl & DEBUG_LEVEL_MASK;
	int debugOpt = debugLvl & DEBUG_OPT_MASK;

	if (debugOpt == 0) debugOpt = DEBUG_GREATER | DEBUG_EQUAL;


	if (debugOpt & DEBUG_GREATER) print = currenDebugLvl > debugLevel;
	else if (debugOpt & DEBUG_SMALLER) print = currenDebugLvl < debugLevel;

	if (!print && debugOpt & DEBUG_EQUAL) print = currenDebugLvl == debugLevel;

	return print;
}

void print_progressDesc(MULTI_PRINTER *mp, int ID, int showTiming, int debugLvl, const char *msg, ...) {
	va_list va;
	MULTI_PRINTER_CHANNEL *chn = NULL;

	if (mp == NULL) return;

	if (is_print_enabled(mp->debug_lvl, debugLvl)) {
		MULTI_PRINTER_getChannel(mp, ID, &chn);
		if (chn == NULL) return;

		if (chn->inProgress == 0) {
			chn->inProgress = 1;
			/*If timing info is needed, then measure time*/
			if (showTiming == 1) {
				chn->timerOn = 1;
				chn->elapsed_time_ms = measureLastCall_(&chn->lastCal);
			}

			va_start(va, msg);
			MULTI_PRINTER_CHANNEL_vaWrite(chn, msg, va);
			va_end(va);
		}
	}
}

void print_progressResult(MULTI_PRINTER *mp, int ID,  int debugLvl, int res) {
	static char time_str[32];
	MULTI_PRINTER_CHANNEL *chn = NULL;

	if (mp == NULL) return;

	if (is_print_enabled(mp->debug_lvl, debugLvl)) {
		MULTI_PRINTER_getChannel(mp, ID, &chn);
		if (chn == NULL) return;

		if (chn->inProgress == 1) {
			chn->inProgress = 0;

			if (chn->timerOn == 1) {
				chn->elapsed_time_ms = measureLastCall_(&chn->lastCal);

				KSI_snprintf(time_str, sizeof(time_str), " (%i ms)", chn->elapsed_time_ms);
			}

			if (res == KT_OK) {
				MULTI_PRINTER_CHANNEL_write(chn, "ok.%s\n", chn->timerOn ? time_str : "");
			} else {
				MULTI_PRINTER_CHANNEL_write(chn, "failed.%s\n", chn->timerOn ? time_str : "");
			}

			chn->timerOn = 0;
		}
	}
}

void print_debug_mp(MULTI_PRINTER *mp, int ID,  int debugLvl, const char *msg, ...) {
	va_list va;

	if (mp == NULL) return;

	if (is_print_enabled(mp->debug_lvl, debugLvl)) {
		va_start(va, msg);
		MULTI_PRINTER_vaWriteChannel(mp, ID, msg, va);
		va_end(va);
	}
}



int MULTI_PRINTER_new(int dbglvl, size_t bufferSize, MULTI_PRINTER **mp) {
	int res = KT_UNKNOWN_ERROR;
	MULTI_PRINTER *tmp = NULL;
	size_t i = 0;

	if (bufferSize == 0 || mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (MULTI_PRINTER*)malloc(sizeof(MULTI_PRINTER));
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Initialize all channels. */
	for (i = 0; i < MP_ID_COUNT; i++) {
		tmp->channel[i] = NULL;
	}

	tmp->buf_size = bufferSize;
	tmp->count = 0;
	tmp->debug_lvl = dbglvl;

	*mp = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:

	free(tmp);

	return res;
}

void MULTI_PRINTER_free(MULTI_PRINTER *mp) {
	size_t i = 0;
	if (mp != NULL) {
		for (i = 0; i < MP_ID_COUNT; i++) {
			/* Free all channels. If not opend (is NULL) do nothing. */
			MULTI_PRINTER_CHANNEL_free(mp->channel[i]);
		}
		 free(mp);
	 }
 }

int MULTI_PRINTER_print(MULTI_PRINTER *mp) {
	int res = KT_UNKNOWN_ERROR;
	size_t i = 0;
	if (mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Print all channels that contains some data. */
	for (i = 0; i < mp->count; i++) {
		res = MULTI_PRINTER_CHANNEL_print(mp->channel[i]);
		if (res != KT_OK) goto cleanup;
	}

	res = KT_OK;

cleanup:

	return res;
}

int MULTI_PRINTER_printByID(MULTI_PRINTER *mp, int ID) {
	int res = KT_UNKNOWN_ERROR;
	MULTI_PRINTER_CHANNEL *chn = NULL;

	if (mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = MULTI_PRINTER_getChannel(mp, ID, &chn);
	if (res != KT_OK) goto cleanup;

	res = MULTI_PRINTER_CHANNEL_print(chn);
	if (res != KT_OK) goto cleanup;

cleanup:

	return res;
}

int MULTI_PRINTER_getCharCountByID(MULTI_PRINTER *mp, int ID, size_t *count) {
	int res = KT_UNKNOWN_ERROR;
	MULTI_PRINTER_CHANNEL *chn = NULL;

	if (mp == NULL || count == 0) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = MULTI_PRINTER_getChannel(mp, ID, &chn);
	if (res != KT_OK) goto cleanup;

	*count = chn->buf_char_count;

cleanup:

	return res;
}

int MULTI_PRINTER_hasDataByID(MULTI_PRINTER *mp, int ID) {
	size_t count = 0;
	MULTI_PRINTER_getCharCountByID(mp, ID, &count);
	return count > 0;
}

int MULTI_PRINTER_openChannel(MULTI_PRINTER *mp, int ID, size_t buf_size, int (*print_func)(const char*, ...)) {
	int res = KT_UNKNOWN_ERROR;
	MULTI_PRINTER_CHANNEL *tmp = NULL;
	volatile size_t buf_size_to_use = 0;

	if (mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (mp->count == MP_ID_COUNT) {
		res = KT_INDEX_OVF;
		goto cleanup;
	}

	buf_size_to_use = buf_size == 0 ? mp->buf_size : buf_size;

	res = MULTI_PRINTER_CHANNEL_new(ID, buf_size_to_use, print_func, &tmp);
	if (res != KT_OK) goto cleanup;

	mp->channel[mp->count] = tmp;

	tmp = NULL;
	mp->count++;

	res = KT_OK;

cleanup:

	MULTI_PRINTER_CHANNEL_free(tmp);

	return res;
}

static int MULTI_PRINTER_getChannel(MULTI_PRINTER *mp, int ID, MULTI_PRINTER_CHANNEL **channel) {
	int res = KT_INVALID_ARGUMENT;
	size_t i = 0;
	MULTI_PRINTER_CHANNEL *match = NULL;

	if (mp == NULL || channel == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (mp->count == 0) {
		res = KT_CHANNEL_NOT_FOUND;
		goto cleanup;
	}

	/* Loop over fiew values. */
	for (i = 0; i < mp->count; i++) {
		/* A sanity check. */
		if (mp->channel[i] == NULL) {
			res = KT_UNKNOWN_ERROR;
			goto cleanup;
		}

		if (mp->channel[i]->ID == ID) {
			match = mp->channel[i];
			break;
		}
	}

	if (match == NULL) {
		res = KT_CHANNEL_NOT_FOUND;
		goto cleanup;
	}

	*channel = match;
	res = KT_OK;

cleanup:

	return res;
}

int MULTI_PRINTER_vaWriteChannel(MULTI_PRINTER *mp, int ID, const char *format, va_list va) {
	int res = KT_UNKNOWN_ERROR;
	MULTI_PRINTER_CHANNEL *match = NULL;

	if (mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Get channel. */
	res = MULTI_PRINTER_getChannel(mp, ID, &match);
	if (res != KT_OK) goto cleanup;

	res = MULTI_PRINTER_CHANNEL_vaWrite(match, format, va);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:


	return res;
}

int MULTI_PRINTER_writeChannel(MULTI_PRINTER *mp, int ID, const char *format, ...) {
	int res = KT_UNKNOWN_ERROR;
	va_list va;

	va_start(va, format);
	res = MULTI_PRINTER_vaWriteChannel(mp, ID, format, va);
	va_end(va);

	return res;
}



static int MULTI_PRINTER_CHANNEL_new(int ID, size_t bufferSize, int (*print_func)(const char*, ...), MULTI_PRINTER_CHANNEL **chn) {
	int res = KT_UNKNOWN_ERROR;
	MULTI_PRINTER_CHANNEL *tmp = NULL;
	char *tmp_buf = NULL;

	if (bufferSize == 0 || chn == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (MULTI_PRINTER_CHANNEL*)malloc(sizeof(MULTI_PRINTER_CHANNEL));
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}


	tmp_buf = (char*)malloc(sizeof(char) * bufferSize);
	if (tmp_buf == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp_buf[0] = '\0';

	tmp->buf = NULL;
	tmp->buf_len = 0;
	tmp->buf_char_count = 0;
	tmp->ID = ID;

	tmp->inProgress = 0;
	tmp->timerOn = 0;
	tmp->elapsed_time_ms = 0;

	tmp->lastCal.tv_sec = 0;
	tmp->lastCal.tv_nsec = 0;

	if (print_func == NULL) {
		tmp->print = print_result;
	} else {
		tmp->print = print_func;
	}

	tmp->buf_len = bufferSize;
	tmp->buf = tmp_buf;
	*chn = tmp;

	tmp_buf = NULL;
	tmp = NULL;

	res = KT_OK;

cleanup:

	free(tmp);
	free(tmp_buf);

	return res;
}

static void MULTI_PRINTER_CHANNEL_free(MULTI_PRINTER_CHANNEL *root) {
	 if (root != NULL) {
		free(root->buf);
		free(root);
	 }
 }

static int MULTI_PRINTER_CHANNEL_vaWrite(MULTI_PRINTER_CHANNEL *chn, const char *format, va_list va) {
	int res = KT_UNKNOWN_ERROR;
	size_t count;

	if (chn == NULL || format == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Format string. */
	count = chn->buf_char_count;
	count += KSI_vsnprintf(chn->buf + count, chn->buf_len - count, format, va);
	chn->buf_char_count = count;

cleanup:

	return res;
}

static int MULTI_PRINTER_CHANNEL_write(MULTI_PRINTER_CHANNEL *chn, const char *format, ...) {
	int res = KT_UNKNOWN_ERROR;
	va_list va;

	va_start(va, format);
	res = MULTI_PRINTER_CHANNEL_vaWrite(chn, format, va);
	va_end(va);

	return res;
}

static int MULTI_PRINTER_CHANNEL_print(MULTI_PRINTER_CHANNEL *chn) {
	int res = KT_UNKNOWN_ERROR;

	if (chn == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	chn->print(chn->buf, chn->buf_char_count);
	chn->buf[0] = '\0';
	chn->buf_char_count = 0;

	res = KT_OK;

cleanup:

	return res;
 }
