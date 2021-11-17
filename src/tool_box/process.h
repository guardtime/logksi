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

#ifndef PROCESS_H
#define	PROCESS_H

#include <stddef.h>
#include <ctype.h>
#include <ksi/ksi.h>
#include "logksi_impl.h"
#include "io_files.h"
#include "debug_print.h"
#include "smart_file.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
	VERIFYING_FUNCTION verify_signature;
	EXTENDING_FUNCTION extend_signature;
	SIGNING_FUNCTION create_signature;
	int extract_signature;
} SIGNATURE_PROCESSORS;

#define SIZE_OF_SHORT_INDENTENTION 13
#define SIZE_OF_LONG_INDENTATION 29

void print_block_duration_summary(MULTI_PRINTER *mp, int indent, LOGKSI *logksi);
void print_block_sign_times(MULTI_PRINTER *mp, int indent, LOGKSI *logksi);

int process_magic_number(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files);
int process_record_chain(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi);
int process_partial_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, int progress);
int process_partial_block(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi);
int process_ksi_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi, KSI_PublicationsFile* pubFile, SIGNATURE_PROCESSORS *processors);
int process_log_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi);
int process_log_signature_with_block_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, KSI_PublicationsFile *pubFile);

int finalize_block(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi);
int finalize_log_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi, KSI_DataHash *inputHash);

#ifdef	__cplusplus
}
#endif

#endif	/* PROCESS_H */