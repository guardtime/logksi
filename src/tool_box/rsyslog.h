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

#include <ksi/tlv_element.h>

typedef int (*EXTENDING_FUNCTION)(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext);
typedef int (*VERIFYING_FUNCTION)(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hash, KSI_PolicyVerificationResult **verificationResult);
typedef int (*SIGNING_FUNCTION)(ERR_TRCKR *err, KSI_CTX *ksi, KSI_DataHash *hash, KSI_uint64_t rootLevel, KSI_Signature **sig);

typedef struct {
	VERIFYING_FUNCTION verify_signature;
	EXTENDING_FUNCTION extend_signature;
	SIGNING_FUNCTION create_signature;
	int extract_signature;
} SIGNATURE_PROCESSORS;

typedef enum {
	LOGSIG11 = 0,
	LOGSIG12 = 1,
	RECSIG11 = 2,
	RECSIG12 = 3
} LOGSIG_VERSION;

typedef struct {
	char *log;
	char *sig;
} USER_FILE_NAMES;

typedef struct {
	char *log;
	char *inSig;
	char *outSig;
	char *outProof;
	char *outLog;
	char *tempSig;
	char *tempProof;
	char *tempLog;
	char *backupSig;
	char *partsBlk;
	char *partsSig;
	char bStdout;
} INTERNAL_FILE_NAMES;

typedef struct {
	FILE *log;
	FILE *inSig;
	FILE *outSig;
	FILE *outProof;
	FILE *outLog;
	FILE *partsBlk;
	FILE *partsSig;
} INTERNAL_FILE_HANDLES;

typedef struct {
	/* File names received as parameters from the user. */
	USER_FILE_NAMES user;
	/* File names generated and allocated by logksi. */
	INTERNAL_FILE_NAMES internal;
	/* Files opened by logksi. */
	INTERNAL_FILE_HANDLES files;
} IO_FILES;

#define MAX_TREE_HEIGHT 31
#define NOF_EXTRACTS 10
#define SOF_FTLV_BUFFER (0xffff + 4)

typedef enum {
	LEFT_LINK = 0,
	RIGHT_LINK = 1
} LINK_DIRECTION;

typedef struct {
	LINK_DIRECTION dir;
	KSI_DataHash *sibling;
	size_t corr;
} REC_CHAIN;

typedef struct {
	size_t extractPos;
	size_t extractOffset;
	size_t extractLevel;
	char *logLine;
	KSI_TlvElement *metaRecord;
	KSI_DataHash *extractRecord;
	REC_CHAIN extractChain[MAX_TREE_HEIGHT];
} EXTRACT_INFO;

typedef struct {
	KSI_FTLV ftlv;
	unsigned char *ftlv_raw;
	size_t ftlv_len;
	size_t blockCount;
	size_t noSigCount;
	size_t blockNo;
	size_t partNo;
	size_t sigNo;
	size_t noSigNo;
	size_t recordCount;
	size_t nofRecordHashes;
	size_t nofTotalRecordHashes;
	size_t nofTreeHashes;
	KSI_HashAlgorithm hashAlgo;
	KSI_OctetString *randomSeed;
	KSI_DataHash *prevLeaf;
	KSI_DataHash *MerkleTree[MAX_TREE_HEIGHT];
	KSI_DataHash *notVerified[MAX_TREE_HEIGHT];
	KSI_DataHash *rootHash;
	KSI_DataHash *metarecordHash;
	KSI_DataHash *extractMask;
	char *logLine;
	unsigned char *metaRecord;
	size_t nofExtractPositions;
	size_t *extractPositions;
	size_t nofExtractPositionsInBlock;
	size_t nofExtractPositionsFound;
	EXTRACT_INFO *extractInfo;
	unsigned char treeHeight;
	unsigned char balanced;
	LOGSIG_VERSION version;
	char keepRecordHashes;
	char keepTreeHashes;
	char finalTreeHashesSome;
	char finalTreeHashesNone;
	char finalTreeHashesAll;
	char warningTreeHashes;
} BLOCK_INFO;

int logsignature_extend(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, EXTENDING_FUNCTION extend_signature, IO_FILES *files);
int logsignature_verify(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, VERIFYING_FUNCTION verify_signature, IO_FILES *files);
int logsignature_extract(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files);
int logsignature_integrate(ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files);
int logsignature_sign(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files);
int get_file_read_lock(FILE *in);
int concat_names(char *org, const char *extension, char **derived);
int duplicate_name(char *in, char **out);
int temp_name(char *org, char **derived);
int logksi_file_check_and_open(ERR_TRCKR *err, char *name, FILE **out);
int logksi_file_create(char *name, FILE **out);
int logksi_file_create_temporary(char *name, FILE **out, char bStdout);
int logksi_file_redirect_to_stdout(FILE *in);
void logksi_filename_free(char **ptr);
void logksi_internal_filenames_free(INTERNAL_FILE_NAMES *internal);
void logksi_file_close(FILE **ptr);
void logksi_files_close(INTERNAL_FILE_HANDLES *files);
int logksi_file_remove(char *name);
int logksi_file_rename(char *from, char *to);
