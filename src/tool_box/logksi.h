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

#ifndef LOGKSI_H
#define	LOGKSI_H

#include <ksi/ksi.h>
#include "logksi_impl.h"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef LINE_BUFFER_LIMIT
#	define LINE_BUFFER_LIMIT 0x100000
#endif

enum LOGSIG_VER_enum {
	/* Invalid value. */
	LOGKSI_VER_RES_INVALID = 0,

	/* Verification succeeded, which means there's a way to prove the correctness of the log signature. */
	LOGKSI_VER_RES_OK,

	/* Verification not possible, which means there is not enough data to prove or disprove the correctness of the log signature. */
	LOGKSI_VER_RES_NA,

	 /**
	  * Verification failed, which means the log signature is definitely invalid or the log lines does not match with the log signature.
	  * This result is also returned when some additional checks do fails (e.g. client id or signing time difference do not match with the
	  * configured values)
	  */
	LOGKSI_VER_RES_FAIL,

	/* Count of possible values. */
	LOGKSI_VER_RES_COUNT,
};

typedef struct STATE_FILE_st STATE_FILE;
int STATE_FILE_open(int readOnly, const char *fname, KSI_CTX *ksi, STATE_FILE **state);
int STATE_FILE_update(STATE_FILE *state, KSI_DataHash *hash);
void STATE_FILE_close(STATE_FILE *state);
KSI_DataHash* STATE_FILE_lastLeaf(STATE_FILE *state);
int STATE_FILE_setHashAlgo(STATE_FILE *state, KSI_HashAlgorithm algo);
KSI_HashAlgorithm STATE_FILE_hashAlgo(STATE_FILE *state);

void LOGKSI_initialize(LOGKSI *block);
int LOGKSI_readLine(LOGKSI *logksi, SMART_FILE *file);
void LOGKSI_freeAndClearInternals(LOGKSI *logksi);
int LOGKSI_initNextBlock(LOGKSI *logksi);
int LOGKSI_get_aggregation_level(LOGKSI *logksi);
int LOGKSI_hasWarnings(LOGKSI *logksi);
int LOGKSI_getMaxFinalHashes(LOGKSI *logksi);
size_t LOGKSI_getNofLines(LOGKSI *logksi);

int LOGKSI_setErrorLevel(LOGKSI *logksi, int lvl);
int LOGKSI_getErrorLevel(LOGKSI *logksi);

#ifdef	__cplusplus
}
#endif

#endif	/* LOGKSI_H */