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

#ifndef MERKLE_TREE_H
#define	MERKLE_TREE_H

#include <ksi/ksi.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define MAX_TREE_HEIGHT 31

typedef struct MERKLE_TREE_st MERKLE_TREE;

int MERKLE_TREE_new(MERKLE_TREE **tree);
void MERKLE_TREE_free(MERKLE_TREE *tree);
void MERKLE_TREE_clean(MERKLE_TREE *tree);
int MERKLE_TREE_reset(MERKLE_TREE *tree, KSI_HashAlgorithm algo, KSI_DataHash *prevLeaf, KSI_OctetString *randomSeed);

int MERKLE_TREE_mergeLowestSubTrees(MERKLE_TREE *tree, KSI_DataHash **hash);
int MERKLE_TREE_calculateRootHash(MERKLE_TREE *tree, KSI_DataHash **hash);
int MERKLE_TREE_calculateTreeHash(MERKLE_TREE *tree, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash);
int MERKLE_TREE_calculateLeafHash(MERKLE_TREE *tree, KSI_DataHash *recordHash, int isMetaRecordHash, KSI_DataHash **leafHash);

int MERKLE_TREE_addLeafHash(MERKLE_TREE *tree, KSI_DataHash *hash, int isMetaRecordHash);
int MERKLE_TREE_addRecordHash(MERKLE_TREE *tree, int isMetaRecordHash, KSI_DataHash *hash);

int MERKLE_TREE_setHasher(MERKLE_TREE *tree, KSI_DataHasher *hsr);
int MERKLE_TREE_setCallbacks(MERKLE_TREE *tree,
							void *ctx,
							int (*extractRecordChain)(MERKLE_TREE*, void*, unsigned char, KSI_DataHash*),
							int (*newRecordChain)(MERKLE_TREE*, void*, int, KSI_DataHash*),
							int (*newTreeNode)(MERKLE_TREE*, void*, unsigned char, KSI_DataHash*));

int MERKLE_TREE_getSubTreeRoot(MERKLE_TREE *tree, unsigned char level, KSI_DataHash **hsh);
int MERKLE_TREE_getPrevLeaf(MERKLE_TREE *tree, KSI_DataHash **hsh);
int MERKLE_TREE_getPrevMask(MERKLE_TREE *tree, KSI_DataHash **hsh);
int MERKLE_TREE_getHasher(MERKLE_TREE *tree, KSI_DataHasher **hsr);
int MERKLE_TREE_isClosing(MERKLE_TREE *tree);
unsigned char MERKLE_TREE_getHeight(MERKLE_TREE *tree);
int MERKLE_TREE_isBalenced(MERKLE_TREE *tree);


size_t MERKLE_TREE_nofUnverifiedHashes(MERKLE_TREE *tree);
int MERKLE_TREE_setFinalHashesForVerification(MERKLE_TREE *tree);

/**
 * Pop hash value from the list of unverified tree nodes. Value returned must be freed
 * by the user.
 * \param tree	- Tree object.
 * \param pos	- Output for position (from level 1 to height of the tree). Can be \c NULL.
 * \param hsh	- Output for hash value.
 * \return
 */
int MERKLE_TREE_popUnverifed(MERKLE_TREE *tree, unsigned char *pos, KSI_DataHash **hsh);
int MERKLE_TREE_insertUnverified(MERKLE_TREE *tree, unsigned char pos, KSI_DataHash *hsh);

size_t MERKLE_TREE_calcMaxTreeHashes(size_t nof_records);

#ifdef	__cplusplus
}
#endif

#endif	/* MERKLE_TREE_H */