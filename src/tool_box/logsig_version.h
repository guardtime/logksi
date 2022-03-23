/*
 * Copyright 2013-2022 Guardtime, Inc.
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

#ifndef LOGSIG_VERSION_H
#define LOGSIG_VERSION_H

#include <stddef.h>
#include <ctype.h>
#include "smart_file.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define MAGIC_SIZE 8

typedef enum {
	LOGSIG11 = 0,
	LOGSIG12 = 1,
	RECSIG11 = 2,
	RECSIG12 = 3,
	LOG12BLK = 4,
	LOG12SIG = 5,
	KSISTAT10 = 6,
	NOF_VERS,
	UNKN_VER = 0xff
} LOGSIG_VERSION;

const char* LOGSIG_VERSION_toString(LOGSIG_VERSION ver);
LOGSIG_VERSION LOGSIG_VERSION_getIntProofVer(LOGSIG_VERSION ver);
LOGSIG_VERSION LOGSIG_VERSION_getFileVer(SMART_FILE *in);

#ifdef	__cplusplus
}
#endif

#endif	/* LOGSIG_VERSION_H */