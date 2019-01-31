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

#ifndef DEBUG_PRINT_H
#define	DEBUG_PRINT_H

#include <ksi/ksi.h>
#include <ksi/policy.h>
#include <ksi/compatibility.h>
#include "param_set/param_set.h"
#include <stdlib.h>

#ifdef	__cplusplus
extern "C" {
#endif


typedef struct MULTI_PRINTER_st MULTI_PRINTER;

enum debug_lvl {
	DEBUG_LEVEL_MASK = 0xffff,
	DEBUG_LEVEL_0 = 0x00,
	DEBUG_LEVEL_1 = 0x01,
	DEBUG_LEVEL_2 = 0x02,
	DEBUG_LEVEL_3 = 0x03,

	DEBUG_OPT_MASK = 0xffff0000,
	DEBUG_EQUAL = 0x10000,
	DEBUG_GREATER = 0x20000,
	DEBUG_SMALLER = 0x40000
};

enum MP_ID_enum {
	MP_ID_BLOCK = 0x01,
	MP_ID_BLOCK_ERRORS = 0x02,
	MP_ID_BLOCK_WARNINGS = 0x03,
	MP_ID_BLOCK_SUMMARY = 0x04,
	MP_ID_BLOCK_PARSING_TREE_NODES = 0x05,

	MP_ID_LOGFILE_WARNINGS = 0x06,
	MP_ID_LOGFILE_SUMMARY = 0x07,
	MP_ID_COUNT
};


void print_progressDesc(MULTI_PRINTER *mp, int ID, int showTiming, int debugLvl, const char *msg, ...);
void print_progressResult(MULTI_PRINTER *mp, int ID,  int debugLvl, int res);
void print_debug_mp(MULTI_PRINTER *mp, int ID,  int debugLvl, const char *msg, ...);


int MULTI_PRINTER_new(int dbglvl, size_t bufferSize, MULTI_PRINTER **mp);
void MULTI_PRINTER_free(MULTI_PRINTER *mp);
int MULTI_PRINTER_print(MULTI_PRINTER *mp);
int MULTI_PRINTER_printByID(MULTI_PRINTER *mp, int ID);
int MULTI_PRINTER_openChannel(MULTI_PRINTER *mp, int ID, size_t buf_size, int (*print_func)(const char*, ...));
int MULTI_PRINTER_writeChannel(MULTI_PRINTER *mp, int ID, const char *format, ...);
int MULTI_PRINTER_vaWriteChannel(MULTI_PRINTER *mp, int ID, const char *format, va_list va);
int MULTI_PRINTER_getCharCountByID(MULTI_PRINTER *mp, int ID, size_t *count);
int MULTI_PRINTER_hasDataByID(MULTI_PRINTER *mp, int ID);



#ifdef	__cplusplus
}
#endif

#endif	/* DEBUG_PRINT_H */

