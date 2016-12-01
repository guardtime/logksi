/*
 * Copyright 2013-2016 Guardtime, Inc.
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

//#include <ksi/tlv_element.h>
#include "../../libksi/out/include/ksi/tlv_element.h"

typedef int (*EXTENDING_FUNCTION)(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_Signature **ext);

typedef struct {
	char *inName;
	char *outName;
	char *backupName;
	char *tempName;
	FILE *inFile;
	FILE *outFile;
} IO_FILES;

#define MAX_TREE_HEIGHT 10

typedef struct {
	KSI_FTLV ftlv;
	unsigned char *ftlv_raw;
	size_t ftlv_len;
	size_t blockNo;
	size_t sigNo;
	size_t nofRecordHashes;
	size_t nofIntermediateHashes;
	KSI_HashAlgorithm hashAlgo;
	KSI_OctetString *randomSeed;
	KSI_DataHash *lastRecordHash;
	KSI_DataHash *MerkleTree[MAX_TREE_HEIGHT];
	KSI_DataHash *notVerified[MAX_TREE_HEIGHT];
	unsigned char treeHeight;
	unsigned char balanced;
} BLOCK_INFO;

int logsignature_extend(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, EXTENDING_FUNCTION extend_signature, IO_FILES *files);
