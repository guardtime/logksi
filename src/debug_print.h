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
#include "param_set/param_set.h"

#ifdef	__cplusplus
extern "C" {
#endif

enum debug_lvl {
	DEBUG_LEVEL_MASK = 0xffff,
	DEBUG_LEVEL_1 = 0x01,
	DEBUG_LEVEL_2 = 0x02,
	DEBUG_LEVEL_3 = 0x03,

	DEBUG_OPT_MASK = 0xffff0000,
	DEBUG_EQUAL = 0x10000,
	DEBUG_GREATER = 0x20000,
	DEBUG_SMALLER = 0x40000
};

void print_progressDesc(int showTiming, const char *msg, ...) __attribute__ ((format(printf, 2, 3)));
void print_progressResult(int res);

void print_progressDescExtended(PARAM_SET *set, int showTiming, int debugLvl, const char *msg, ...);
void print_progressResultExtended(PARAM_SET *set, int debugLvl, int res);
void print_debugExtended(PARAM_SET *set, int debugLvl, const char *msg, ...);


#ifdef	__cplusplus
}
#endif

#endif	/* DEBUG_PRINT_H */

