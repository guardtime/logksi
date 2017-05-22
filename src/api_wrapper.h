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

#ifndef API_WRAPPER_H
#define	API_WRAPPER_H

#include "logksi_err.h"
#include <ksi/ksi.h>
#include <ksi/policy.h>
#include "err_trckr.h"

#ifdef	__cplusplus
extern "C" {
#endif



#define ERR_CATCH_MSG(err, res, msg, ...) \
	if (res != KT_OK) { \
		ERR_TRCKR_add(err, res, __FILE__, __LINE__, msg, ##__VA_ARGS__); \
		goto cleanup; \
	}

#define ERR_APPEND_KSI_ERR(err, res, ref_err) \
		if (res == ref_err) { \
			ERR_TRCKR_add(err, res, __FILE__, __LINE__, "Error: %s", KSI_getErrorString(res)); \
		}

int LOGKSI_extendSignature(ERR_TRCKR *err, KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext);
int LOGKSI_Signature_extendTo(ERR_TRCKR *err, const KSI_Signature *signature, KSI_CTX *ctx, KSI_Integer *to, KSI_VerificationContext *context, KSI_Signature **extended);
int LOGKSI_Signature_extend(ERR_TRCKR *err, const KSI_Signature *signature, KSI_CTX *ctx, const KSI_PublicationRecord *pubRec, KSI_VerificationContext *context, KSI_Signature **extended);
int LOGKSI_RequestHandle_getExtendResponse(ERR_TRCKR *err, KSI_CTX *ctx, KSI_RequestHandle *handle, KSI_ExtendResp **resp);
int LOGKSI_Signature_isCalendarAuthRecPresent(const KSI_Signature *sig);
int LOGKSI_Signature_isPublicationRecordPresent(const KSI_Signature *sig);
int LOGKSI_receivePublicationsFile(ERR_TRCKR *err ,KSI_CTX *ctx, KSI_PublicationsFile **pubFile);
int LOGKSI_verifyPublicationsFile(ERR_TRCKR *err, KSI_CTX *ctx, KSI_PublicationsFile *pubfile);
void LOGKSI_KSI_ERRTrace_save(KSI_CTX *ctx);
const char *LOGKSI_KSI_ERRTrace_get(void);
void LOGKSI_KSI_ERRTrace_LOG(KSI_CTX *ksi);

int LOGKSI_SignatureVerify_general(ERR_TRCKR *err, KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_PublicationData *pubdata, int extperm, KSI_PolicyVerificationResult **result);
int LOGKSI_SignatureVerify_internally(ERR_TRCKR *err, KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_PolicyVerificationResult **result);
int LOGKSI_SignatureVerify_calendarBased(ERR_TRCKR *err, KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_PolicyVerificationResult **result);
int LOGKSI_SignatureVerify_keyBased(ERR_TRCKR *err, KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_PolicyVerificationResult **result);
int LOGKSI_SignatureVerify_publicationsFileBased(ERR_TRCKR *err, KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, int extperm, KSI_PolicyVerificationResult **result);
int LOGKSI_SignatureVerify_userProvidedPublicationBased(ERR_TRCKR *err, KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_PublicationData *pubdata, int extperm, KSI_PolicyVerificationResult **result);

int LOGKSI_createSignature(ERR_TRCKR *err, KSI_CTX *ctx, KSI_DataHash *dataHash, KSI_uint64_t rootLevel, KSI_Signature **sig);

char *LOGKSI_DataHash_toString(KSI_DataHash *hsh, char *buf, size_t buf_len);
char *LOGKSI_PublicationData_toString(KSI_PublicationData *data, char *buf, size_t buf_len);
char *LOGKSI_PublicationRecord_toString(KSI_PublicationRecord *rec, char *buf, size_t buf_len);

int LOGKSI_LOG_SmartFile(void *logCtx, int logLevel, const char *message);

int LOGKSI_KSI_ERR_toExitCode(int error_code);

#ifdef	__cplusplus
}
#endif

#endif	/* API_WRAPPER_H */

