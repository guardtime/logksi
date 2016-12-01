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

#include <string.h>
#include "param_set/param_set.h"
#include "err_trckr.h"
#include <ksi/ksi.h>
#include "ksitool_err.h"
#include "api_wrapper.h"
#include "debug_print.h"
//#include <ksi/tlv_element.h>
#include "../../libksi/out/include/ksi/tlv_element.h"
#include "rsyslog.h"

static size_t buf_to_int(unsigned char *buf, size_t len) {
	size_t val = 0;

	while (len--) {
		val = val * 256  + *buf++;
	}
	return val;
}

static void adjust_tlv_length_in_buffer(unsigned char *raw, KSI_FTLV *ftlv) {
	size_t val = ftlv->dat_len;
	size_t i = ftlv->hdr_len;

	while (i-- > ftlv->hdr_len / 2) {
		raw[i] = val & 0xFF;
		val = (val >> 8);
	}
}

static int calculate_new_intermediate_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash) {
	int res;
	KSI_DataHasher *hasher = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || leftHash == NULL || rightHash == NULL || nodeHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_open(ksi, blocks->hashAlgo, &hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(hasher, leftHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(hasher, rightHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_add(hasher, &level, 1);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(hasher, &tmp);
	if (res != KSI_OK) goto cleanup;

	*nodeHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	KSI_DataHasher_free(hasher);
	return res;
}

static int calculate_new_leaf_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *recordHash, KSI_DataHash **leafHash) {
	int res;
	KSI_DataHasher *hasher = NULL;
	KSI_DataHash *mask = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || recordHash == NULL || leafHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_DataHasher_open(ksi, blocks->hashAlgo, &hasher);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addImprint(hasher, blocks->lastRecordHash);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_addOctetString(hasher, blocks->randomSeed);
	if (res != KSI_OK) goto cleanup;
	res = KSI_DataHasher_close(hasher, &mask);
	if (res != KSI_OK) goto cleanup;

	res = calculate_new_intermediate_hash(ksi, blocks, mask, recordHash, 1, &tmp);
	if (res != KT_OK) goto cleanup;

	*leafHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(mask);
	KSI_DataHash_free(tmp);
	KSI_DataHasher_free(hasher);
	return res;
}

int calculate_root_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash **hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *root = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (blocks->balanced) {
		root = KSI_DataHash_ref(blocks->MerkleTree[blocks->treeHeight - 1]);
	} else {
		while (i < blocks->treeHeight) {
			if (root == NULL) {
				root = KSI_DataHash_ref(blocks->MerkleTree[i]);
				i++;
				continue;
			}
			if (blocks->MerkleTree[i]) {
				res = calculate_new_intermediate_hash(ksi, blocks, blocks->MerkleTree[i], root, i + 2, &tmp);
				if (res != KT_OK) goto cleanup;
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

int add_hash_to_merkle_tree(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *lastHash = NULL;
	KSI_DataHash *right = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || blocks == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = calculate_new_leaf_hash(ksi, blocks, hash, &lastHash);
	if (res != KT_OK) goto cleanup;

	right = KSI_DataHash_ref(lastHash);

	blocks->balanced = 0;
	while (blocks->MerkleTree[i] != NULL) {
		res = calculate_new_intermediate_hash(ksi, blocks, blocks->MerkleTree[i], right, i + 2, &tmp);
		if (res != KT_OK) goto cleanup;
		KSI_DataHash_free(blocks->notVerified[i]);
		blocks->notVerified[i] = KSI_DataHash_ref(right);
		KSI_DataHash_free(right);
		right = tmp;
		KSI_DataHash_free(blocks->MerkleTree[i]);
		blocks->MerkleTree[i] = NULL;
		i++;
	}
	blocks->MerkleTree[i] = right;
	KSI_DataHash_free(blocks->notVerified[i]);
	blocks->notVerified[i] = KSI_DataHash_ref(blocks->MerkleTree[i]);

	if (i == blocks->treeHeight) {
		blocks->treeHeight++;
		blocks->balanced = 1;
	}

	KSI_DataHash_free(blocks->lastRecordHash);
	blocks->lastRecordHash = lastHash;
	lastHash = NULL;
	right = NULL;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(lastHash);
	KSI_DataHash_free(right);
	KSI_DataHash_free(tmp);
	return res;
}

static int process_magic_number(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;
	char buf[10];
	size_t count = 0;
	size_t magicLength = strlen("LOGSIG11");
	int d = 0;

	if (set == NULL || err == NULL || files == NULL || files->inFile == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(d, "Processing magic number... ");
	count = fread(buf, 1, magicLength, files->inFile);
	if (count != magicLength || strncmp(buf, "LOGSIG11", magicLength)) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Magic number not found at the beginning of log signature file.");
	}

	if (files->outFile) {
		count = fwrite(buf, 1, magicLength, files->outFile);
		if (count != magicLength) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Could not copy magic number to extended log signature file.");
		}
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);
	return res;
}

static int process_block_header(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_FTLV sub_ftlv[3];
	size_t nof_sub_ftlvs = 0;
	unsigned char *sub_ftlv_raw = NULL;
	KSI_OctetString *tmpSeed = NULL;
	KSI_DataHash *tmpHash = NULL;
	unsigned char i = 0;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(d, "Block no. %3d: processing block header... ", blocks->blockNo + 1);
	if (blocks->blockNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: block signature data missing.", blocks->blockNo);
	}
	blocks->blockNo++;
	blocks->nofRecordHashes = 0;
	blocks->nofIntermediateHashes = 0;

	sub_ftlv_raw = blocks->ftlv_raw + blocks->ftlv.hdr_len;
	res = KSI_FTLV_memReadN(sub_ftlv_raw, blocks->ftlv_len - blocks->ftlv.hdr_len, sub_ftlv, 3, &nof_sub_ftlvs);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block header data.", blocks->blockNo);

	if (nof_sub_ftlvs != 3) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block header data.", blocks->blockNo);
	} else if (sub_ftlv[0].tag != 0x01) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse hash algorithm.", blocks->blockNo);
	} else if (sub_ftlv[1].tag != 0x02) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse random seed.", blocks->blockNo);
	} else if (sub_ftlv[2].tag != 0x03) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse last hash of previous block.", blocks->blockNo);
	}

	res = KSI_OctetString_new(ksi, sub_ftlv_raw + sub_ftlv[1].off + sub_ftlv[1].hdr_len, sub_ftlv[1].dat_len, &tmpSeed);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to create random seed.", blocks->blockNo);

	res = KSI_DataHash_fromImprint(ksi, sub_ftlv_raw + sub_ftlv[2].off + sub_ftlv[2].hdr_len, sub_ftlv[2].dat_len, &tmpHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to create hash of previous block.", blocks->blockNo);

	if (files->outFile) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to copy block header.", blocks->blockNo);
		}
	}

	blocks->hashAlgo = buf_to_int(sub_ftlv_raw + sub_ftlv[0].off + sub_ftlv[0].hdr_len, sub_ftlv[0].dat_len);
	KSI_OctetString_free(blocks->randomSeed);
	blocks->randomSeed = tmpSeed;
	tmpSeed = NULL;
	KSI_DataHash_free(blocks->lastRecordHash);
	blocks->lastRecordHash = tmpHash;
	tmpHash = NULL;

	while (i < blocks->treeHeight) {
		KSI_DataHash_free(blocks->MerkleTree[i]);
		blocks->MerkleTree[i] = NULL;
		KSI_DataHash_free(blocks->notVerified[i]);
		blocks->notVerified[i] = NULL;
		i++;
	}
	blocks->treeHeight = 0;
	blocks->balanced = 0;

	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_OctetString_free(tmpSeed);
	KSI_DataHash_free(tmpHash);
	return res;
}

static int process_record_hash(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_DataHash *recordHash = NULL;

	if (set == NULL || err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(d, "Block no. %3d: processing record hash... ", blocks->blockNo);
	if (blocks->blockNo == blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: record hash without preceding block header found.", blocks->blockNo + 1);
	}
	blocks->nofRecordHashes++;

	res = KSI_DataHash_fromImprint(ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to create hash of record no. %3d.", blocks->blockNo, blocks->nofRecordHashes);

	res = add_hash_to_merkle_tree(ksi, blocks, recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to add hash to Merkle tree.", blocks->blockNo);

	if (files->outFile) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to copy record hash.", blocks->blockNo);
		}
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(recordHash);
	return res;
}

static int process_intermediate_hash(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_DataHash *tmpHash = NULL;
	unsigned char i;

	if (set == NULL || err == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(d, "Block no. %3d: processing intermediate hash... ", blocks->blockNo);
	if (blocks->blockNo == blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: intermediate hash without preceding block header found.", blocks->blockNo + 1);
	}
	blocks->nofIntermediateHashes++;

	res = KSI_DataHash_fromImprint(ksi, blocks->ftlv_raw + blocks->ftlv.hdr_len, blocks->ftlv.dat_len, &tmpHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to create intermediate hash.", blocks->blockNo);

	if (files->outFile) {
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to copy record hash.", blocks->blockNo);
		}
	}

	for (i = 0; i < blocks->treeHeight; i++) {
		if (blocks->notVerified[i] != NULL) break;
	}
	if (i == blocks->treeHeight) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unexpected intermediate hash.", blocks->blockNo);
	}

	if (!KSI_DataHash_equals(blocks->notVerified[i], tmpHash)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: intermediate hashes not equal.", blocks->blockNo);
	}
	KSI_DataHash_free(blocks->notVerified[i]);
	blocks->notVerified[i] = NULL;
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_DataHash_free(tmpHash);
	return res;
}

static int process_block_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, EXTENDING_FUNCTION extend_signature, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_FTLV sub_ftlv[2];
	size_t nof_sub_ftlvs = 0;
	unsigned char *sub_ftlv_raw = NULL;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_VerificationContext context;

	if (set == NULL || err == NULL || ksi == NULL || extend_signature == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_VerificationContext_init(&context, ksi);

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(d, "Block no. %3d: processing block signature data... ", blocks->blockNo);

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: block signature data without preceding block header found.", blocks->sigNo);
	}

	sub_ftlv_raw = blocks->ftlv_raw + blocks->ftlv.hdr_len;
	res = KSI_FTLV_memReadN(sub_ftlv_raw, blocks->ftlv_len - blocks->ftlv.hdr_len, sub_ftlv, 2, &nof_sub_ftlvs);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block signature data.", blocks->blockNo);
	if (nof_sub_ftlvs != 2) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block signature data.", blocks->blockNo);
	} else if (sub_ftlv[0].tag != 0x01) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse record count.", blocks->blockNo);
	} else if (sub_ftlv[1].tag != 0x0905) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unsupported block signature type %04X found.", blocks->blockNo, sub_ftlv[1].tag);
	} else {
		unsigned char *sig_raw = NULL;
		size_t sig_raw_len = 0;
		unsigned char *ext_raw = NULL;
		size_t ext_raw_len = 0;
		size_t record_count = 0;

		record_count = buf_to_int(sub_ftlv_raw + sub_ftlv[0].off + sub_ftlv[0].hdr_len, sub_ftlv[0].dat_len);
		if (record_count != blocks->nofRecordHashes) {
			res = KT_INVALID_INPUT_FORMAT;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: expected %d record hashes, but found %d.", blocks->blockNo, record_count, blocks->nofRecordHashes);
		}
		print_progressResult(res); /* Done with parsing block signature data. */

		print_progressDesc(d, "Block no. %3d: parsing and verifying KSI signature... ", blocks->blockNo);
		sig_raw = sub_ftlv_raw + sub_ftlv[1].off + sub_ftlv[1].hdr_len;
		sig_raw_len = sub_ftlv[1].dat_len;
		res = calculate_root_hash(ksi, blocks, &context.documentHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to get root hash for verification.", blocks->blockNo);
		res = KSI_Signature_parseWithPolicy(ksi, sig_raw, sig_raw_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse KSI signature.", blocks->blockNo);
		KSI_DataHash_free(context.documentHash);
		context.documentHash = NULL;
		KSI_VerificationContext_clean(&context);
		print_progressResult(res);

		res = extend_signature(set, err, ksi, sig, &ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to extend KSI signature.", blocks->blockNo);
		KSI_Signature_free(sig);
		sig = NULL;

		print_progressDesc(d, "Block no. %3d: serializing extended KSI signature... ", blocks->blockNo);
		res = KSI_Signature_serialize(ext, &ext_raw, &ext_raw_len);
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to serialize extended KSI signature.", blocks->blockNo);
		KSI_Signature_free(ext);
		ext = NULL;
		print_progressResult(res);

		print_progressDesc(d, "Block no. %3d: writing extended KSI signature to file... ", blocks->blockNo);
		/* Reuse the raw buffer and adjust FTLV headers accordingly. */
		memcpy(sig_raw, ext_raw, ext_raw_len);
		KSI_free(ext_raw);
		ext_raw = NULL;

		blocks->ftlv.dat_len = blocks->ftlv.dat_len - sig_raw_len + ext_raw_len;
		sub_ftlv[1].dat_len = ext_raw_len;
		adjust_tlv_length_in_buffer(sub_ftlv_raw + sub_ftlv[1].off, &sub_ftlv[1]);
		adjust_tlv_length_in_buffer(blocks->ftlv_raw, &blocks->ftlv);
		blocks->ftlv_len = blocks->ftlv.hdr_len + blocks->ftlv.dat_len;
		if (fwrite(blocks->ftlv_raw, 1, blocks->ftlv_len, files->outFile) != blocks->ftlv_len) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to write extended signature to extended log signature file.", blocks->blockNo);
		}
		print_progressResult(res);
	}
	res = KT_OK;

cleanup:

	print_progressResult(res);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_DataHash_free(context.documentHash);
	KSI_VerificationContext_clean(&context);
	return res;
}

static int finalize_log_signature(PARAM_SET *set, ERR_TRCKR *err, BLOCK_INFO *blocks) {
	int res;
	int d = 0;

	if (set == NULL || err == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(d, "Finalizing log signature... ");

	if (blocks->blockNo == 0) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: no blocks found.");
	} else if (blocks->blockNo > blocks->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: block signature data missing.", blocks->blockNo);
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);
	return res;
}

static void free_blocks(BLOCK_INFO *blocks) {
	unsigned char i = 0;

	if (blocks) {
		KSI_DataHash_free(blocks->lastRecordHash);
		KSI_OctetString_free(blocks->randomSeed);
		while (i < blocks->treeHeight) {
			KSI_DataHash_free(blocks->MerkleTree[i]);
			KSI_DataHash_free(blocks->notVerified[i]);
			i++;
		}
	}
}

int logsignature_extend(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, EXTENDING_FUNCTION extend_signature, IO_FILES *files) {
	int res;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[0xffff + 4];

	if (set == NULL || err == NULL || ksi == NULL || extend_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;

	res = process_magic_number(set, err, files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files->inFile)) {
		res = KSI_FTLV_fileRead(files->inFile, blocks.ftlv_raw, sizeof(ftlv_raw), &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(set, err, ksi, &blocks, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					res = process_block_signature(set, err, ksi, extend_signature, &blocks, files);
					if (res != KT_OK) goto cleanup;
				}
				break;

				default:
					/* TODO: unknown TLV found. Either
					 * 1) Warn user and skip TLV
					 * 2) Copy TLV (maybe warn user)
					 * 3) Abort extending with an error
					 */
				break;
			}
		} else {
			if (feof(files->inFile)) {
				res = KT_OK;
				break;
			} else {
				/* File reading failed. */
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to read next TLV.");
			}
		}
	}

	res = finalize_log_signature(set, err, &blocks);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	free_blocks(&blocks);

	return res;
}
