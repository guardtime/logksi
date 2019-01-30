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
#include "common.h"
#include <limits.h>
#include <sys/time.h>

typedef struct MULTI_PRINTER_CHANNEL_st MULTI_PRINTER_CHANNEL;
static int MULTI_PRINTER_CHANNEL_new(int ID, size_t bufferSize, int (*print_func)(const char*, ...), MULTI_PRINTER_CHANNEL **chn);
static void MULTI_PRINTER_CHANNEL_free(MULTI_PRINTER_CHANNEL *root);
static int MULTI_PRINTER_CHANNEL_print(MULTI_PRINTER_CHANNEL *chn, int *closeMe);
static int MULTI_PRINTER_CHANNEL_removeLink(MULTI_PRINTER_CHANNEL *chn);
static int MULTI_PRINTER_CHANNEL_insertLink(MULTI_PRINTER_CHANNEL **chn, MULTI_PRINTER_CHANNEL *newChn);
static int MULTI_PRINTER_CHANNEL_appendLink(MULTI_PRINTER_CHANNEL *chn, MULTI_PRINTER_CHANNEL *newChn);
static int MULTI_PRINTER_CHANNEL_vaWrite(MULTI_PRINTER_CHANNEL *chn, int signal, int options, const char *format, va_list va);
static int MULTI_PRINTER_CHANNEL_write(MULTI_PRINTER_CHANNEL *chn, int signal, int options, const char *format, ...);

static int MULTI_PRINTER_getChannel(MULTI_PRINTER *mp, int ID, MULTI_PRINTER_CHANNEL **channel);

struct MULTI_PRINTER_CHANNEL_st {
	int ID;

	char *buf;
	size_t buf_len;
	size_t buf_char_count;


	int signal;
	int (*print)(const char *buf, ...);

	unsigned int elapsed_time_ms;
	int inProgress;
	int timerOn;

	struct timeval thisCall;
	struct timeval lastCal;


	MULTI_PRINTER_CHANNEL *previous;
	MULTI_PRINTER_CHANNEL *next;
};


struct MULTI_PRINTER_st {
	MULTI_PRINTER_CHANNEL *channel;
	MULTI_PRINTER_CHANNEL *last;
	size_t count;
	size_t buf_size;
	int debug_lvl;
};

static unsigned int measureLastCall_(struct timeval *thisCall, struct timeval *lastCall){
	unsigned int tmp;
	gettimeofday(thisCall, NULL);

	tmp = (unsigned)((thisCall->tv_sec - lastCall->tv_sec) * 1000.0 + (thisCall->tv_usec - lastCall->tv_usec) / 1000.0);
	lastCall->tv_sec = thisCall->tv_sec;
	lastCall->tv_usec = thisCall->tv_usec;

	return tmp;;
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

void multi_print_progressDesc(MULTI_PRINTER *mp, int ID, int showTiming, int debugLvl, const char *msg, ...) {
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
				chn->elapsed_time_ms = measureLastCall_(&chn->thisCall, &chn->lastCal);
			}

			va_start(va, msg);
			MULTI_PRINTER_CHANNEL_vaWrite(chn, MULTI_PRINTER_SIGNAL_NONE, 0, msg, va);
			va_end(va);
		}
	}
}

void multi_print_progressResult(MULTI_PRINTER *mp, int ID,  int debugLvl, int res) {
	static char time_str[32];
	MULTI_PRINTER_CHANNEL *chn = NULL;

	if (mp == NULL) return;

	if (is_print_enabled(mp->debug_lvl, debugLvl)) {
		MULTI_PRINTER_getChannel(mp, ID, &chn);
		if (chn == NULL) return;

		if (chn->inProgress == 1) {
			chn->inProgress = 0;

			if (chn->timerOn == 1) {
				chn->elapsed_time_ms = measureLastCall_(&chn->thisCall, &chn->lastCal);

				KSI_snprintf(time_str, sizeof(time_str), " (%i ms)", chn->elapsed_time_ms);
			}

			if (res == KT_OK) {
				MULTI_PRINTER_CHANNEL_write(chn, MULTI_PRINTER_SIGNAL_NONE, 0, "ok.%s\n", chn->timerOn ? time_str : "");
			} else {
				MULTI_PRINTER_CHANNEL_write(chn, MULTI_PRINTER_SIGNAL_NONE, 0, "failed.%s\n", chn->timerOn ? time_str : "");
			}

			chn->timerOn = 0;
		}
	}
}

void multi_print_debug(MULTI_PRINTER *mp, int ID,  int debugLvl, const char *msg, ...) {
	va_list va;

	if (mp == NULL) return;

	if (is_print_enabled(mp->debug_lvl, debugLvl)) {
		va_start(va, msg);
		MULTI_PRINTER_vaWriteChannel(mp, ID, MULTI_PRINTER_SIGNAL_NONE, 0, msg, va);
		va_end(va);
	}
}



int MULTI_PRINTER_new(int dbglvl, size_t bufferSize, MULTI_PRINTER **mp) {
	int res = KT_UNKNOWN_ERROR;
	MULTI_PRINTER *tmp = NULL;

	if (bufferSize == 0 || mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (MULTI_PRINTER*)malloc(sizeof(MULTI_PRINTER));
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->buf_size = bufferSize;
	tmp->channel = NULL;
	tmp->last = NULL;
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
	 if (mp != NULL) {
		 if (mp->count > 0) MULTI_PRINTER_CHANNEL_free(mp->channel);
		 free(mp);
	 }
 }

int MULTI_PRINTER_print(MULTI_PRINTER *mp) {
	int res = KT_UNKNOWN_ERROR;
	int closeMe = 0;

	if (mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	} else if (mp->count == 0) {
		res = KT_OK;
		goto cleanup;
	}

	/* Print content of a channel. If channel is closed, take another printer
	   and print its content too.*/
	do {
		res = MULTI_PRINTER_CHANNEL_print(mp->channel, &closeMe);
		if (res != KT_OK) goto cleanup;

		if (closeMe) {
			MULTI_PRINTER_CHANNEL *nextRoot = mp->channel->next;
			res = MULTI_PRINTER_CHANNEL_removeLink(mp->channel);
			if (res != KT_OK) goto cleanup;

			mp->channel = nextRoot;
			mp->count--;
		}

	} while(closeMe && mp->count > 0);


	res = KT_OK;

cleanup:

	return res;
}

int MULTI_PRINTER_printByID(MULTI_PRINTER *mp, int ID) {
	int res = KT_UNKNOWN_ERROR;
	int closeMe = 0;
	MULTI_PRINTER_CHANNEL *chn = NULL;

	if (mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = MULTI_PRINTER_getChannel(mp, ID, &chn);
	if (res != KT_OK) goto cleanup;

	res = MULTI_PRINTER_CHANNEL_print(chn, &closeMe);
	if (res != KT_OK) goto cleanup;

	if (closeMe) {
		/* Fix multi printer internal pointers. */
		if(mp->channel == chn) {
			mp->channel = chn->next;
		}

		if (mp->last == chn) {
			mp->last = chn->previous;
		}


		mp->count--;

		/* Chain of multi printer channels is fixed after one node is removed. */
		res = MULTI_PRINTER_CHANNEL_removeLink(chn);
		if (res != KT_OK) goto cleanup;
	}


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

int MULTI_PRINTER_openChannel(MULTI_PRINTER *mp, int ID, int options, size_t buf_size,  int (*print_func)(const char*, ...)) {
	int res = KT_UNKNOWN_ERROR;
	MULTI_PRINTER_CHANNEL *tmp = NULL;
	volatile size_t buf_size_to_use = 0;

	if (mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	buf_size_to_use = buf_size == 0 ? mp->buf_size : buf_size;

	res = MULTI_PRINTER_CHANNEL_new(ID, buf_size_to_use, print_func, &tmp);
	if (res != KT_OK) goto cleanup;


	if (mp->count == 0) {
		res = MULTI_PRINTER_CHANNEL_insertLink(&mp->channel, tmp);
		if (res != KT_OK) goto cleanup;

		mp->last = tmp;
	} else {
		res = MULTI_PRINTER_CHANNEL_appendLink(mp->last, tmp);
		if (res != KT_OK) goto cleanup;

		mp->last = tmp;
	}

	tmp = NULL;
	mp->count++;

	res = KT_OK;

cleanup:

	MULTI_PRINTER_CHANNEL_free(tmp);

	return res;
}

static int MULTI_PRINTER_getChannel(MULTI_PRINTER *mp, int ID, MULTI_PRINTER_CHANNEL **channel) {
	int res = KT_INVALID_ARGUMENT;
	MULTI_PRINTER_CHANNEL *chn = NULL;
	MULTI_PRINTER_CHANNEL *match = NULL;

	if (mp == NULL || channel == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (mp->count == 0) {
		res = KT_CHANNEL_NOT_FOUND;
		goto cleanup;
	}

	chn = mp->channel;

	do {
		if (chn->ID == ID && !(chn->signal & (MULTI_PRINTER_SIGNAL_CLOSE_AND_PRINT | MULTI_PRINTER_SIGNAL_CLOSE_WITHOUT_PRINT))) {
			match = chn;
			break;
		}

		chn = chn->next;
	} while(chn != NULL);

	if (match == NULL) {
		res = KT_CHANNEL_NOT_FOUND;
		goto cleanup;
	}

	*channel = match;
	res = KT_OK;

cleanup:

	return res;
}

int MULTI_PRINTER_vaWriteChannel(MULTI_PRINTER *mp, int ID, int signal, int options, const char *format, va_list va) {
	int res = KT_UNKNOWN_ERROR;
	MULTI_PRINTER_CHANNEL *match = NULL;

	if (mp == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Get channel. */
	res = MULTI_PRINTER_getChannel(mp, ID, &match);
	if (res != KT_OK) goto cleanup;

	res = MULTI_PRINTER_CHANNEL_vaWrite(match, signal, options, format, va);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:


	return res;
}

int MULTI_PRINTER_writeChannel(MULTI_PRINTER *mp, int ID, int signal, int options, const char *format, ...) {
	int res = KT_UNKNOWN_ERROR;
	va_list va;

	va_start(va, format);
	res = MULTI_PRINTER_vaWriteChannel(mp, ID, signal, options, format, va);
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
	tmp->next = NULL;
	tmp->previous = NULL;
	tmp->signal = MULTI_PRINTER_SIGNAL_NONE;
	tmp->ID = ID;

	tmp->inProgress = 0;
	tmp->timerOn = 0;
	tmp->elapsed_time_ms = 0;

	tmp->thisCall.tv_sec = 0;
	tmp->thisCall.tv_usec = 0;
	tmp->lastCal.tv_sec = 0;
	tmp->lastCal.tv_usec = 0;

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

		 if (root->next != NULL) {
			 MULTI_PRINTER_CHANNEL_free(root->next);
		 }

		free(root);
	 }

 }

static int MULTI_PRINTER_CHANNEL_vaWrite(MULTI_PRINTER_CHANNEL *chn, int signal, int options, const char *format, va_list va) {
	int res = KT_UNKNOWN_ERROR;
	size_t count;
	VARIABLE_IS_NOT_USED(options);


	if (chn == NULL || format == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Format string. */
	count = chn->buf_char_count;
	count += KSI_vsnprintf(chn->buf + count, chn->buf_len - count, format, va);
	chn->buf_char_count = count;


	/* Set signal. */
	chn->signal |= signal;

cleanup:

	return res;
}

static int MULTI_PRINTER_CHANNEL_write(MULTI_PRINTER_CHANNEL *chn, int signal, int options, const char *format, ...) {
	int res = KT_UNKNOWN_ERROR;
	va_list va;

	va_start(va, format);
	res = MULTI_PRINTER_CHANNEL_vaWrite(chn, signal, options, format, va);
	va_end(va);

	return res;
}

static int MULTI_PRINTER_CHANNEL_print(MULTI_PRINTER_CHANNEL *chn, int *closeMe) {
	int res = KT_UNKNOWN_ERROR;

	if (chn == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (closeMe != NULL) *closeMe = 0;

	switch(chn->signal) {
		case MULTI_PRINTER_SIGNAL_CLOSE_AND_PRINT:
			chn->print(chn->buf, chn->buf_char_count);
		case MULTI_PRINTER_SIGNAL_CLOSE_WITHOUT_PRINT:
			if (closeMe != NULL) *closeMe = 1;
		break;

		case MULTI_PRINTER_SIGNAL_NONE:
			chn->print(chn->buf, chn->buf_char_count);
		break;

		default:
			res = KT_UNKNOWN_ERROR;
			goto cleanup;
	}

	chn->buf[0] = '\0';
	chn->buf_char_count = 0;


	res = KT_OK;

cleanup:

	return res;
 }

/* Removes the link and fixes its previous and next link. */
static int MULTI_PRINTER_CHANNEL_removeLink(MULTI_PRINTER_CHANNEL *chn) {
	int res = KT_UNKNOWN_ERROR;

	if (chn == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Fix the next link. */
	if (chn->next !=NULL) {
		chn->next->previous = chn->previous;
	}

	/* Fix the previous link. */
	if (chn->previous != NULL) {
		chn->previous->next = chn->next;
	}

	chn->next = NULL;
	chn->previous = NULL;

	MULTI_PRINTER_CHANNEL_free(chn);

	res = KT_OK;

cleanup:

	return res;
 }

/* Inserts a link to position and shifts a value *chn to right. */
static int MULTI_PRINTER_CHANNEL_insertLink(MULTI_PRINTER_CHANNEL **chn, MULTI_PRINTER_CHANNEL *newChn) {
	int res = KT_UNKNOWN_ERROR;

	if (chn == NULL || newChn == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (*chn == NULL) {
		*chn = newChn;
	} else {
		MULTI_PRINTER_CHANNEL *insertAt = NULL;

		insertAt = *chn;

		/* Link new channel with others. */
		newChn->next = insertAt;
		newChn->previous = insertAt->previous;

		/* Fix the link of previous link. */
		if (newChn->previous != NULL) {
			newChn->previous->next = newChn;
		}

		/* Fix the link of next link. */
		newChn->next->previous = newChn;
	}

	res = KT_OK;

cleanup:

	return res;
 }

static int MULTI_PRINTER_CHANNEL_appendLink(MULTI_PRINTER_CHANNEL *chn, MULTI_PRINTER_CHANNEL *newChn) {
	int res = KT_UNKNOWN_ERROR;

	if (chn == NULL || newChn == NULL || chn->next != NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	chn->next = newChn;
	newChn->previous = chn;

	res = KT_OK;

cleanup:

	return res;
 }
