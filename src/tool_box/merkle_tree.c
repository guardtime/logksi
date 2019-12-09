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

#include <string.h>
#include <stdlib.h>
#include <ksi/ksi.h>
#include "merkle_tree.h"
#include "logksi_err.h"
#include "extract_info.h"
#include "logksi_impl.h"


struct MERKLE_TREE_st {
	KSI_OctetString *randomSeed;
	KSI_DataHash *prevLeaf;
	KSI_DataHash *prevMask;
	KSI_DataHash *MerkleTree[MAX_TREE_HEIGHT];
	KSI_DataHash *notVerified[MAX_TREE_HEIGHT];
	unsigned char treeHeight;
	unsigned char balanced;
	KSI_DataHasher *hasher;
	KSI_HashAlgorithm hasher_algo;

	int isClosing;

	/* Abstract functionality for extracting hash chains from the tree while the tree
	   is being built. */
	void *ctx;

	/* Is called within #MERKLE_TREE_calculate_root_hash and #MERKLE_TREE_add_leaf_hash_to_merkle_tree.*/
	int (*extractRecordChain)(MERKLE_TREE *tree, void *ctx, unsigned char lvl, KSI_DataHash *hash);

	/* Is called within #MERKLE_TREE_add_record_hash_to_merkle_tree. */
	int (*newRecordChain)(MERKLE_TREE *tree, void *ctx, int isMetaRecordHash, KSI_DataHash *hash);
};


int MERKLE_TREE_new(MERKLE_TREE **tree) {
	int i = 0;
	MERKLE_TREE *tmp = NULL;
	int res = KT_UNKNOWN_ERROR;

	if (tree == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (MERKLE_TREE*)malloc(sizeof(MERKLE_TREE));
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->balanced = 0;
	tmp->treeHeight = 0;
	tmp->isClosing = 0;
	tmp->hasher = NULL;
	tmp->hasher_algo = KSI_HASHALG_INVALID_VALUE;

	tmp->ctx = NULL;
	tmp->extractRecordChain = NULL;
	tmp->newRecordChain = NULL;
	tmp->prevLeaf = NULL;
	tmp->prevMask = NULL;
	tmp->randomSeed= NULL;


	for (i = 0; i < MAX_TREE_HEIGHT; i++) {
		tmp->notVerified[i] = NULL;
		tmp->MerkleTree[i] = NULL;
	}

	*tree = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	free(tmp);

	return res;
}

int MERKLE_TREE_setHasher(MERKLE_TREE *tree, KSI_DataHasher *hsr) {
	if (tree == NULL || hsr == NULL) return KT_INVALID_ARGUMENT;

	if (tree->hasher != NULL) {
		KSI_DataHasher_free(tree->hasher);
	}

	tree->hasher = hsr;

	return KT_OK;
}

int MERKLE_TREE_setCallbacks(MERKLE_TREE *tree,
							void *ctx,
							int (*extractRecordChain)(MERKLE_TREE*, void*, unsigned char, KSI_DataHash*),
							int (*newRecordChain)(MERKLE_TREE*, void*, int, KSI_DataHash*)) {
	if (tree == NULL || extractRecordChain == NULL || newRecordChain == NULL) return KT_INVALID_ARGUMENT;

	tree->ctx = ctx;
	tree->extractRecordChain = extractRecordChain;
	tree->newRecordChain = newRecordChain;

	return KT_OK;
}

void MERKLE_TREE_free(MERKLE_TREE *tree) {
	int i = 0;

	if (tree == NULL) return;

	KSI_OctetString_free(tree->randomSeed);
	KSI_DataHash_free(tree->prevLeaf);
	KSI_DataHash_free(tree->prevMask);

	while (i < tree->treeHeight) {
		KSI_DataHash_free(tree->MerkleTree[i]);
		KSI_DataHash_free(tree->notVerified[i]);
		i++;
	}

	KSI_DataHasher_free(tree->hasher);

	free(tree);
}

void MERKLE_TREE_clean(MERKLE_TREE *tree) {
	int i = 0;

	if (tree == NULL) return;
	KSI_DataHash_free(tree->prevMask);
	KSI_DataHash_free(tree->prevLeaf);
	KSI_OctetString_free(tree->randomSeed);
	tree->prevMask = NULL;
	tree->prevLeaf = NULL;
	tree->randomSeed = NULL;

	while (i < tree->treeHeight) {
		KSI_DataHash_free(tree->MerkleTree[i]);
		KSI_DataHash_free(tree->notVerified[i]);
		tree->MerkleTree[i] = NULL;
		tree->notVerified[i] = NULL;
		i++;
	}

	KSI_DataHasher_reset(tree->hasher);

	tree->balanced = 0;
	tree->treeHeight = 0;
	tree->isClosing = 0;

}

int MERKLE_TREE_reset(MERKLE_TREE *tree, KSI_HashAlgorithm algo, KSI_DataHash *prevLeaf, KSI_OctetString *randomSeed) {
	int res = KT_UNKNOWN_ERROR;

	if (tree == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	MERKLE_TREE_clean(tree);
	tree->prevLeaf = prevLeaf;
	tree->randomSeed = randomSeed;

	if (tree->hasher == NULL || tree->hasher_algo != algo) {
		if (tree->hasher != NULL) {
			KSI_DataHasher_free(tree->hasher);
			tree->hasher = NULL;
		}

		res = KSI_DataHasher_open(NULL, algo, &tree->hasher);
		if (res != KSI_OK) goto cleanup;

		tree->hasher_algo = algo;
	}

	res = KT_OK;

cleanup:

	return res;
}

int MERKLE_TREE_merge_one_level(MERKLE_TREE *tree, KSI_DataHash **hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *root = NULL;
	KSI_DataHash *tmp = NULL;

	if (tree == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	while (i < tree->treeHeight) {
		if (tree->MerkleTree[i]) {
			if (root == NULL) {
				/* Initialize root hash only if there is at least one more hash afterwards. */
				if (i < tree->treeHeight - 1) {
					root = KSI_DataHash_ref(tree->MerkleTree[i]);
					KSI_DataHash_free(tree->MerkleTree[i]);
					tree->MerkleTree[i] = NULL;
				}
			} else {
				res = MERKLE_TREE_calculate_new_tree_hash(tree, tree->MerkleTree[i], root, i + 2, &tmp);
				if (res != KT_OK) goto cleanup;

				KSI_DataHash_free(root);
				root = tmp;

				KSI_DataHash_free(tree->MerkleTree[i]);
				tree->MerkleTree[i] = KSI_DataHash_ref(root);
				break;
			}
		}
		i++;
	}

	*hash = KSI_DataHash_ref(root);
	tmp = NULL;

	res = KT_OK;

cleanup:

	KSI_DataHash_free(root);
	KSI_DataHash_free(tmp);
	return res;
}

int MERKLE_TREE_calculate_root_hash(MERKLE_TREE *tree, KSI_DataHash **hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *root = NULL;
	KSI_DataHash *tmp = NULL;

	if (tree == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tree->isClosing = 1;

	if (tree->balanced) {
		root = KSI_DataHash_ref(tree->MerkleTree[tree->treeHeight - 1]);
	} else {
		while (i < tree->treeHeight) {
			if (root == NULL) {
				root = KSI_DataHash_ref(tree->MerkleTree[i]);
				i++;
				continue;
			}
			if (tree->MerkleTree[i]) {
				res = MERKLE_TREE_calculate_new_tree_hash(tree, tree->MerkleTree[i], root, i + 2, &tmp);
				if (res != KT_OK) goto cleanup;

				if (tree->extractRecordChain != NULL) {
					res = tree->extractRecordChain(tree, tree->ctx, i, root);
					if (res != KT_OK) goto cleanup;
				}


				KSI_DataHash_free(root);
				root = tmp;
			}
			i++;
		}
	}


	*hash = KSI_DataHash_ref(root);
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(root);
	KSI_DataHash_free(tmp);
	return res;
}

int MERKLE_TREE_calculate_new_tree_hash(MERKLE_TREE *tree, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash) {
	int res;
	KSI_DataHash *tmp = NULL;

	if (tree == NULL || leftHash == NULL || rightHash == NULL || nodeHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_reset(tree->hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(tree->hasher, leftHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(tree->hasher, rightHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_add(tree->hasher, &level, 1);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(tree->hasher, &tmp);
	if (res != KSI_OK) goto cleanup;

	*nodeHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

 int MERKLE_TREE_add_leaf_hash_to_merkle_tree(MERKLE_TREE *tree, KSI_DataHash *hash, int isMetaRecordHash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *right = NULL;
	KSI_DataHash *tmp = NULL;

	if (tree == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	right = KSI_DataHash_ref(hash);

	tree->balanced = 0;

	while (tree->MerkleTree[i] != NULL) {
		res = MERKLE_TREE_calculate_new_tree_hash (tree, tree->MerkleTree[i], right, i + 2, &tmp);
		if (res != KT_OK) goto cleanup;

		if (tree->extractRecordChain != NULL) {
			res = tree->extractRecordChain(tree, tree->ctx, i, right);
			if (res != KT_OK) goto cleanup;
		}

		res = MERKLE_TREE_insertUnverified(tree, i, right);
		if (res != KT_OK) goto cleanup;

		KSI_DataHash_free(right);
		right = tmp;
		KSI_DataHash_free(tree->MerkleTree[i]);
		tree->MerkleTree[i] = NULL;
		i++;
	}

	tree->MerkleTree[i] = right;

	res = MERKLE_TREE_insertUnverified(tree, i, right);
	if (res != KT_OK) goto cleanup;

	if (i == tree->treeHeight) {
		tree->treeHeight++;
		tree->balanced = 1;
	}

	KSI_DataHash_free(tree->prevLeaf);
	tree->prevLeaf = KSI_DataHash_ref(hash);
	right = NULL;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(right);
	KSI_DataHash_free(tmp);
	return res;
}

int MERKLE_TREE_calculate_new_leaf_hash(MERKLE_TREE *tree, KSI_DataHash *recordHash, int isMetaRecordHash, KSI_DataHash **leafHash) {
	int res;
	KSI_DataHash *mask = NULL;
	KSI_DataHash *tmp = NULL;

	if (tree == NULL || recordHash == NULL || leafHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_reset(tree->hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(tree->hasher, tree->prevLeaf);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addOctetString(tree->hasher, tree->randomSeed);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(tree->hasher, &mask);
	if (res != KSI_OK) goto cleanup;


	KSI_DataHash_free(tree->prevMask);
	tree->prevMask = KSI_DataHash_ref(mask);



	if (isMetaRecordHash) {
		res = MERKLE_TREE_calculate_new_tree_hash(tree, recordHash, mask, 1, &tmp);
		if (res != KT_OK) goto cleanup;
	} else {
		res = MERKLE_TREE_calculate_new_tree_hash(tree, mask, recordHash, 1, &tmp);
		if (res != KT_OK) goto cleanup;
	}

	*leafHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(mask);
	KSI_DataHash_free(tmp);
	return res;
}

int MERKLE_TREE_add_record_hash_to_merkle_tree(MERKLE_TREE *tree, int isMetaRecordHash, KSI_DataHash *hash) {
	int res;
	KSI_DataHash *lastHash = NULL;

	if (tree == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = MERKLE_TREE_calculate_new_leaf_hash(tree, hash, isMetaRecordHash, &lastHash);
	if (res != KT_OK) goto cleanup;


	if (tree->newRecordChain != NULL) {
		res = tree->newRecordChain(tree, tree->ctx, isMetaRecordHash, hash);
		if (res != KT_OK) goto cleanup;
	}

	res = MERKLE_TREE_add_leaf_hash_to_merkle_tree(tree, lastHash, isMetaRecordHash);
	if (res != KT_OK) goto cleanup;

cleanup:

	KSI_DataHash_free(lastHash);
	return res;
}

int LOGKSI_add_record_hash_to_merkle_tree(LOGKSI *logksi, int isMetaRecordHash, KSI_DataHash *hash) {
	int res = KT_UNKNOWN_ERROR;

	if (logksi == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Do not allow meta records to be extracted. */
	if (isMetaRecordHash) {
		logksi->file.nofTotalMetarecords++;
		logksi->block.nofMetaRecords++;
		logksi->file.nofTotalRecordHashes--;
	}

	res = MERKLE_TREE_add_record_hash_to_merkle_tree(logksi->tree, isMetaRecordHash, hash);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	return res;
}

unsigned char MERKLE_TREE_getHeight(MERKLE_TREE *tree) {
	if (tree == NULL) return 0;
	return tree->treeHeight;
}

int MERKLE_TREE_get(MERKLE_TREE *tree, unsigned char level, KSI_DataHash **hsh) {
	if (tree == NULL || level > MAX_TREE_HEIGHT || hsh == NULL) return KT_INVALID_ARGUMENT;
	*hsh = KSI_DataHash_ref(tree->MerkleTree[level]);
	return KT_OK;
}

int MERKLE_TREE_getPrevLeaf(MERKLE_TREE *tree, KSI_DataHash **hsh) {
	if (tree == NULL || hsh == NULL) return KT_INVALID_ARGUMENT;
	*hsh = KSI_DataHash_ref(tree->prevLeaf);
	return KT_OK;
}

int MERKLE_TREE_getPrevMask(MERKLE_TREE *tree, KSI_DataHash **hsh) {
	if (tree == NULL || hsh == NULL) return KT_INVALID_ARGUMENT;
	*hsh = KSI_DataHash_ref(tree->prevMask);
	return KT_OK;
}

int MERKLE_TREE_getHasher(MERKLE_TREE *tree, KSI_DataHasher **hsr) {
	if (tree == NULL || hsr == NULL) return KT_INVALID_ARGUMENT;
	*hsr = tree->hasher;
	return KT_OK;
}

int MERKLE_TREE_isClosing(MERKLE_TREE *tree) {
	if (tree == NULL) return 0;
	return tree->isClosing;
}

int MERKLE_TREE_isBalenced(MERKLE_TREE *tree) {
	if (tree == NULL) return 0;
	return tree->balanced;
}

size_t MERKLE_TREE_nof_unverified_hashes(MERKLE_TREE *tree) {
	size_t count = 0;
	size_t i;

	if (tree == NULL) return 0;

	for (i = 0; i < MERKLE_TREE_getHeight(tree); i++) {
		if (tree->notVerified[i]) {
			count++;
		}
	}

	return count;
}

int MERKLE_TREE_setFinalHashesForVerification(MERKLE_TREE *tree) {
	int res = KT_UNKNOWN_ERROR;
	KSI_DataHash *tmp = NULL;
	size_t i;

	if (tree == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = 0; i < MERKLE_TREE_getHeight(tree); i++) {

		res = MERKLE_TREE_get(tree, i, &tmp);
		if (res != KT_OK) goto cleanup;

		if (tree->notVerified[i] != NULL) {
			//Rise error ?????????
		}

		tree->notVerified[i] = tmp;
		tmp = NULL;
	}


	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);

	return res;
}

int MERKLE_TREE_popUnverifed(MERKLE_TREE *tree, unsigned char *pos, KSI_DataHash **hsh) {
	int res = KT_UNKNOWN_ERROR;
	unsigned char i = 0;;

	if (tree == NULL  || hsh == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Find the corresponding tree hash from the merkle tree. */
	for (i = 0; i < MERKLE_TREE_getHeight(tree); i++) {
		if (tree->notVerified[i] != NULL) break;
	}

	if (pos != NULL) {
		*pos = i;
	}

	/* Reassign the ownership. */
	*hsh = tree->notVerified[i];
	tree->notVerified[i] = NULL;

	res = KT_OK;

cleanup:


	return res;
}

int MERKLE_TREE_insertUnverified(MERKLE_TREE *tree, unsigned char pos, KSI_DataHash *hsh) {
	int res = KT_UNKNOWN_ERROR;

	if (tree == NULL || pos > MAX_TREE_HEIGHT || hsh == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_DataHash_free(tree->notVerified[pos]);
	tree->notVerified[pos] = KSI_DataHash_ref(hsh);

	res = KT_OK;

cleanup:

	return res;
}

size_t MERKLE_TREE_calcMaxTreeHashes(size_t nof_records) {
	size_t max = 0;
	while (nof_records) {
		max = max + nof_records;
		nof_records = nof_records / 2;
	}
	return max;
}