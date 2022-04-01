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

#include <ksi/publicationsfile.h>
#include "smart_file.h"
#include "logksi_impl.h"
#include "param_set/param_set.h"
#include "debug_print.h"
#include "io_files.h"
#include "err_trckr.h"
#include "logksi.h"

#define SOF_FTLV_BUFFER (0xffff + 4)

#define META_DATA_BLOCK_CLOSE_REASON "com.guardtime.blockCloseReason"

typedef int (*EXTENDING_FUNCTION)(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, IO_FILES *files, KSI_Signature *sig,  KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext);
typedef int (*VERIFYING_FUNCTION)(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hash, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **verificationResult);
typedef int (*SIGNING_FUNCTION)(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, IO_FILES *files, KSI_DataHash *hash, KSI_uint64_t rootLevel, KSI_Signature **sig);


int logsignature_extend(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile* pubFile, EXTENDING_FUNCTION extend_signature, IO_FILES *files);
int logsignature_verify(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, KSI_DataHash *firstLink, VERIFYING_FUNCTION verify_signature, IO_FILES *files, KSI_DataHash **lastLeaf, uint64_t* last_rec_time);
int logsignature_extract(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files);
int logsignature_integrate(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI* blocks, IO_FILES *files);
int logsignature_sign(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files);
int logsignature_create(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, IO_FILES *files, KSI_HashAlgorithm aggrAlgo, STATE_FILE *state);
