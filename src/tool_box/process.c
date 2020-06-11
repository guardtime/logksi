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

/* To make function strptime prototype available. */
#define _XOPEN_SOURCE

#include <string.h>
#include <stdlib.h>
#include <ksi/ksi.h>
#include <ksi/tlv_element.h>
#include <ksi/signature_builder.h>

#include "io_files.h"
#include "logksi_err.h"
#include "param_set/param_set.h"
#include "param_set/strn.h"
#include "api_wrapper.h"
#include "logksi.h"
#include "check.h"
#include <time.h>
#include "param_control.h"
#include "debug_print.h"
#include "printer.h"
#include "rsyslog.h"
#include "process.h"
#include <ksi/tlv_element.h>
#include "tlv_object.h"
#include "logsig_version.h"
#include <gtrfc3161/tsconvert.h>

//static int is_block_signature_expected(ERR_TRCKR *err, LOGKSI *logksi);
static int process_hash_step(ERR_TRCKR *err, KSI_CTX *ksi, KSI_TlvElement *tlv, LOGKSI *logksi, KSI_DataHash *inputHash, unsigned char *chainHeight, KSI_DataHash **outputHash);
static int block_info_calculate_hash_of_logline_and_store_logline_check_log_time(PARAM_SET* set, ERR_TRCKR *err, MULTI_PRINTER *mp, LOGKSI *logksi, IO_FILES *files, KSI_DataHash **hash);
static int process_log_signature_general_components_(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, int withBlockSignature, LOGKSI *logksi, IO_FILES *files, SIGNATURE_PROCESSORS *processors);
static int logksi_calculate_hash_of_metarecord_and_store_metarecord(LOGKSI *logksi, KSI_TlvElement *tlv, KSI_DataHash **hash);
static int logksi_add_record_hash_to_merkle_tree(LOGKSI *logksi, int isMetaRecordHash, KSI_DataHash *hash);

#define SOF_ARRAY(x) (sizeof(x) / sizeof((x)[0]))

int process_magic_number(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files) {
	int res;
	SMART_FILE *in = NULL;

	if (err == NULL || logksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	in = files->files.partsBlk ? files->files.partsBlk : files->files.inSig;
	if (in == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Processing magic number... ");

	res = KT_INVALID_INPUT_FORMAT;

	if (files->files.partsBlk) {
		LOGSIG_VERSION exp_ver_blk[] = {LOG12BLK};
		LOGSIG_VERSION exp_ver_sig[] = {LOG12SIG};

		res = check_file_header(files->files.partsBlk, err, exp_ver_blk, SOF_ARRAY(exp_ver_blk), "block", NULL);
		if (res != KT_OK) goto cleanup;

		res = check_file_header(files->files.partsSig, err, exp_ver_sig, SOF_ARRAY(exp_ver_sig), "signature", NULL);
		if (res != KT_OK) goto cleanup;

		logksi->file.version = LOGSIG12;
	} else {
		LOGSIG_VERSION exp_ver[] = {LOGSIG11, LOGSIG12, RECSIG11, RECSIG12};
		res = check_file_header(files->files.inSig, err, exp_ver, SOF_ARRAY(exp_ver), "signature", &logksi->file.version);
		if (res != KT_OK) goto cleanup;
	}

	if (files->files.outSig) {
		res = SMART_FILE_write(files->files.outSig, (unsigned char*)LOGSIG_VERSION_toString(logksi->file.version), MAGIC_SIZE, NULL);
		ERR_CATCH_MSG(err, res, "Error: Could not copy magic number to log signature file.");
	} else if (files->files.outProof) {
		res = SMART_FILE_write(files->files.outProof, (unsigned char*)LOGSIG_VERSION_toString(LOGSIG_VERSION_getIntProofVer(logksi->file.version)), MAGIC_SIZE, NULL);
		ERR_CATCH_MSG(err, res, "Error: Could not write magic number to integrity proof file.");
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	return res;
}

int process_record_chain(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi) {
	int res;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvMetaRecord = NULL;
	KSI_DataHash *tmpHash = NULL;
	KSI_DataHash *root = NULL;
	KSI_DataHash *replacement = NULL;

	if (err == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	logksi->block.nofRecordHashes++;

	res = tlv_element_parse_and_check_sub_elements(err, ksi, logksi->ftlv_raw, logksi->ftlv_len, logksi->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse record chain as TLV element.", logksi->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x911, &tlvMetaRecord);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract metarecord in record chain.", logksi->blockNo);

	KSI_DataHash_free(logksi->block.metarecordHash);
	logksi->block.metarecordHash = NULL;
	if (tlvMetaRecord != NULL) {
		res = logksi_calculate_hash_of_metarecord_and_store_metarecord(logksi, tlvMetaRecord, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate metarecord hash.", logksi->blockNo);

		logksi->block.metarecordHash = KSI_DataHash_ref(hash);
	}

	res = tlv_element_get_hash(err, tlv, ksi, 0x01, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse hash of logline no. %zu.", logksi->blockNo, LOGKSI_getNofLines(logksi));

	if (logksi->block.metarecordHash != NULL) {
		char description[1024];
		PST_snprintf(description, sizeof(description), "Metarecord hash mismatch in block %zu", logksi->blockNo);

		/* This is a metarecord hash. */
		res = logksi_datahash_compare(err, mp, logksi, 0, logksi->block.metarecordHash, recordHash, description, "Metarecord hash computed from metarecord:", "Metarecord hash stored in integrity proof file:");
		res = continue_on_hash_fail(res, set, mp, logksi, logksi->block.metarecordHash, recordHash, &replacement);
		if (!logksi->isContinuedOnFail) {
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: metarecord hashes not equal.", logksi->blockNo);
		}

		if (res != KT_OK) goto cleanup;
	} else {
		/* This is a logline record hash. */

		if (files->files.inLog) {
			res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, logksi, files, &hash);
			if (res == KT_IO_ERROR) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash no. %zu does not have a matching logline, end of logfile reached.", logksi->blockNo, LOGKSI_getNofLines(logksi));
			} else if (res != KT_OK) goto cleanup;

			res = logksi_datahash_compare(err, mp, logksi, 1, hash, recordHash, NULL, "Record hash computed from logline:", "Record hash stored in integrity proof file:");
			res = continue_on_hash_fail(res, set, mp, logksi, hash, recordHash, &replacement);
			if (!logksi->isContinuedOnFail) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hashes not equal.", logksi->blockNo);
			}

			if (res != KT_OK) goto cleanup;
		} else {
			replacement = KSI_DataHash_ref(recordHash);
		}
	}

	if (tlv->subList) {
		size_t i = 0;
		char description[1024];
		unsigned char chainHeight = 0;

		root = KSI_DataHash_ref(replacement);

		for (i = 0; i < KSI_TlvElementList_length(tlv->subList); i++) {
			KSI_TlvElement *tmpTlv = NULL;

			res = KSI_TlvElementList_elementAt(tlv->subList, i, &tmpTlv);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get element %lu from TLV.", logksi->blockNo, i);
			if (tmpTlv && (tmpTlv->ftlv.tag == 0x02 || tmpTlv->ftlv.tag == 0x03)) {
				res = process_hash_step(err, ksi, tmpTlv, logksi, root, &chainHeight, &tmpHash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to process hash step.", logksi->blockNo);

				KSI_DataHash_free(root);
				root = tmpHash;
				tmpHash = NULL;
			}
		}

		PST_snprintf(description, sizeof(description), "Root hash mismatch in block %zu", logksi->blockNo);

		res = logksi_datahash_compare(err, mp, logksi, 0, root, logksi->block.rootHash, description, "Root hash computed from hash chain:", "Root hash stored in KSI signature:");
		KSI_DataHash_free(replacement);
		replacement = NULL;
		res = continue_on_hash_fail(res, set, mp, logksi, root, logksi->block.rootHash, &replacement);
		if (!logksi->isContinuedOnFail) {
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", logksi->blockNo);
		}

		if (res != KT_OK) goto cleanup;
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get sub TLVs from record chain.", logksi->blockNo);
	}
	res = KT_OK;

cleanup:

	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(hash);
	KSI_DataHash_free(root);
	KSI_DataHash_free(tmpHash);
	KSI_DataHash_free(replacement);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(tlvMetaRecord);
	return res;
}

int process_partial_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, int progress) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_DataHash *missing = NULL;
	KSI_DataHash *replacement = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_TlvElement *tlvNoSig = NULL;
	KSI_TlvElement *tlvRfc3161 = NULL;
	int insertHashes = 0;
	char description[1024];
	int sign_err = 0;

	if (err == NULL || ksi == NULL || processors == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
		print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "}\n");
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
	}

	PST_snprintf(description, sizeof(description), "Root hash mismatch in block %zu", logksi->blockNo);
	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing partial signature data... ", logksi->blockNo);

	logksi->sigNo++;
	if (logksi->sigNo > logksi->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature data without preceding block header found.", logksi->sigNo);
	}

	logksi->block.signatureTLVReached = 1;

	res = tlv_element_parse_and_check_sub_elements(err, ksi, logksi->ftlv_raw, logksi->ftlv_len, logksi->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", logksi->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &logksi->block.recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in signatures file.", logksi->blockNo);

	res = is_block_signature_expected(logksi, err);
	if (res != KT_OK) goto cleanup;


	if (logksi->block.nofRecordHashes && logksi->block.nofRecordHashes != logksi->block.recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: expected %zu records in signatures file, but found %zu records in blocks file.", logksi->blockNo, logksi->block.recordCount, logksi->block.nofRecordHashes);
	}

	insertHashes = PARAM_SET_isSetByName(set, "insert-missing-hashes");
	if (logksi->block.finalTreeHashesNone && insertHashes) {
		if (logksi->block.keepRecordHashes || (!logksi->block.keepRecordHashes && logksi->block.finalTreeHashesSome)) {
			do {
				missing = NULL;

				res = MERKLE_TREE_mergeLowestSubTrees(logksi->tree, &missing);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash could not be computed.", logksi->blockNo);

				if (missing) {
					res = tlv_element_write_hash(missing, 0x903, files->files.outSig);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash could not be written.", logksi->blockNo);
					KSI_DataHash_free(missing);
					logksi->task.sign.outSigModified = 1;
				}
			} while (missing);
			logksi->block.finalTreeHashesNone = 0;
			logksi->block.finalTreeHashesAll = 1;
		}
	}

	res = KSI_TlvElement_getElement(tlv, 0x906, &tlvRfc3161);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract RFC3161 element in block signature.", logksi->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract KSI signature element in signatures file.", logksi->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract 'no-sig' element in signatures file.", logksi->blockNo);

	if (tlvSig != NULL || tlvRfc3161 != NULL) {
		KSI_DataHash *docHash = NULL;

		if (tlvSig != NULL) {
			res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature in signatures file.", logksi->blockNo);
		} else {
			/* Convert the RFC3161 timestamp into KSI signature. */
			res = convert_signature(ksi, tlvRfc3161->ptr + tlvRfc3161->ftlv.hdr_len, tlvRfc3161->ftlv.dat_len, &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to convert RFC3161 element in block signature.", logksi->blockNo);
			logksi->file.warningLegacy = 1;
		}

		res = KSI_Signature_getDocumentHash(sig, &docHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get root hash from KSI signature.", logksi->blockNo);

		/* Compare signed root hash with unsigned root hash. */
		if (logksi->block.rootHash) {
			res = logksi_datahash_compare(err, mp, logksi, 0, logksi->block.rootHash, docHash, description, "Unsigned root hash stored in block data file:", "Signed root hash stored in KSI signature:");
			res = continue_on_hash_fail(res, set, mp, logksi, logksi->block.rootHash, docHash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", logksi->blockNo);
		} else if (logksi->block.nofRecordHashes) {
			/* Compute the root hash and compare with signed root hash. */
			res = MERKLE_TREE_calculateRootHash(logksi->tree, &rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate root hash.", logksi->blockNo);

			res = logksi_datahash_compare(err, mp, logksi, 0, rootHash, docHash, description, "Root hash computed from record hashes:", "Signed root hash stored in KSI signature:");
			res = continue_on_hash_fail(res, set, mp, logksi, rootHash, docHash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", logksi->blockNo);
		}
	} else if (tlvNoSig != NULL) {
		logksi->task.sign.noSigNo++;
		res = tlv_element_get_hash(err, tlvNoSig, ksi, 0x01, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse root hash.", logksi->blockNo);

		/* Compare unsigned root hashes. */
		if (logksi->block.rootHash) {
			res = logksi_datahash_compare(err, mp, logksi, 0, logksi->block.rootHash, hash, description, "Unsigned root hash stored in block data file:", "Unsigned root hash stored in block signature file:");
			res = continue_on_hash_fail(res, set, mp, logksi, logksi->block.rootHash, hash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", logksi->blockNo);
		} else if (logksi->block.nofRecordHashes) {
			/* Compute the root hash and compare with unsigned root hash. */
			res = MERKLE_TREE_calculateRootHash(logksi->tree, &rootHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate root hash.", logksi->blockNo);

			res = logksi_datahash_compare(err, mp, logksi, 0, rootHash, hash, description, "Root hash computed from record hashes:", "Unsigned root hash stored in block signature file:");
			res = continue_on_hash_fail(res, set, mp, logksi, rootHash, hash, &replacement);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", logksi->blockNo);
		}

		if (processors->create_signature) {
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

			if (progress) {
				print_debug("Progress: signing block %3zu of %3zu unsigned blocks. Estimated time remaining: %3zu seconds.\n",
					logksi->task.sign.noSigNo,
					logksi->task.sign.noSigCount,
					logksi->task.sign.noSigCount - logksi->task.sign.noSigNo + 1);
			}
			print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: creating missing KSI signature... ", logksi->blockNo);

			res = processors->create_signature(set, mp, err, ksi, logksi, files, hash, LOGKSI_get_aggregation_level(logksi), &sig);
			if (res != KT_OK && logksi->isContinuedOnFail) {
				sign_err = KT_SIGNING_FAILURE;
				print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Failed to sign unsigned block %zu:\n"
																					  "   + %s (0x%02x)\n"
																					  "   + Signing is continued and unsigned block will be kept.\n", logksi->blockNo, LOGKSI_errToString(res), res);
				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_2, "\n");

				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Signing is continued and unsigned block will be kept.\n", logksi->blockNo);

				res = KSI_TlvElement_serialize(tlv, logksi->ftlv_raw, SOF_FTLV_BUFFER, &logksi->ftlv_len, 0);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize unsigned block.", logksi->blockNo);
			} else {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to sign root hash.", logksi->blockNo);

				logksi->task.sign.curBlockJustReSigned = 1;
				logksi->task.sign.outSigModified = 1;
				logksi->task.sign.noSigCreated++;

				res = KSI_TlvElement_new(&tlvSig);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", logksi->blockNo);
				tlvSig->ftlv.tag = 0x904;

				res = tlv_element_set_uint(tlvSig, ksi, 0x01, logksi->block.recordCount);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", logksi->blockNo);

				res = tlv_element_set_signature(tlvSig, ksi, 0x905, sig);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", logksi->blockNo);

				res = KSI_TlvElement_serialize(tlvSig, logksi->ftlv_raw, SOF_FTLV_BUFFER, &logksi->ftlv_len, 0);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize KSI signature.", logksi->blockNo);
			}
		} else {
			/* Missing signatures found during integration. */
			logksi->task.integrate.warningSignatures = 1;
			logksi->task.integrate.unsignedRootHash = 1;
		}
	} else {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature missing in signatures file.", logksi->blockNo);
	}

	if (sig != NULL){
		KSI_Integer *t1 = NULL;
		char sigTimeStr[256];

		res = KSI_Signature_getSigningTime(sig, &t1);
		ERR_CATCH_MSG(err, res, NULL);

		logksi->block.sigTime_1 = KSI_Integer_getUInt64(t1);
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, res);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: signing time: (%llu) %s\n", logksi->blockNo, logksi->block.sigTime_1, LOGKSI_signature_sigTimeToString(sig, sigTimeStr, sizeof(sigTimeStr)));
	} else {
		logksi->block.curBlockNotSigned = 1;
	}

	if (files->files.outSig) {
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: writing block signature to file... ", logksi->blockNo);

		res = SMART_FILE_write(files->files.outSig, logksi->ftlv_raw, logksi->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to write signature data log signature file.", logksi->blockNo);

		/* Move signature file offset value at the end of the files as complete signature is written to the file. */
		res = SMART_FILE_markConsistent(files->files.outSig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to mark output log signature file consistent.", logksi->blockNo);
	}
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	logksi->file.nofTotalRecordHashes += logksi->block.nofRecordHashes;

	if (logksi->block.firstLineNo < logksi->file.nofTotalRecordHashes) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: lines processed %zu - %zu (%zu)\n", logksi->blockNo, logksi->block.firstLineNo, logksi->file.nofTotalRecordHashes, logksi->block.recordCount - logksi->block.nofMetaRecords);
	} else if (logksi->block.recordCount == 1 && logksi->block.nofMetaRecords == 1) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed n/a\n", logksi->blockNo);
	} else if (logksi->block.firstLineNo == logksi->file.nofTotalRecordHashes) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed %zu\n", logksi->blockNo,  logksi->block.firstLineNo);
	} else {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed <unknown>\n", logksi->blockNo);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	KSI_Signature_free(sig);
	KSI_DataHash_free(hash);
	KSI_DataHash_free(rootHash);
	KSI_DataHash_free(missing);
	KSI_DataHash_free(replacement);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlvNoSig);
	KSI_TlvElement_free(tlvRfc3161);
	KSI_TlvElement_free(tlv);

	return (sign_err == 0) ? res : sign_err;
}

int process_partial_block(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_DataHash *replacement = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvNoSig = NULL;

	if (err == NULL || ksi == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing partial block data... ", logksi->blockNo);

	logksi->task.integrate.partNo++;
	if (logksi->task.integrate.partNo > logksi->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: partial block data without preceding block header found.", logksi->sigNo);
	}

	res = tlv_element_parse_and_check_sub_elements(err, ksi, logksi->ftlv_raw, logksi->ftlv_len, logksi->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", logksi->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &logksi->block.recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in blocks file.", logksi->blockNo);

	res = is_block_signature_expected(logksi, err);
	if (res != KT_OK) goto cleanup;

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract 'no-sig' element in blocks file.", logksi->blockNo);

	res = tlv_element_get_hash(err, tlvNoSig, ksi, 0x01, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse root hash.", logksi->blockNo);

	if (logksi->block.nofRecordHashes && logksi->block.nofRecordHashes != logksi->block.recordCount) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: expected %zu records in blocks file, but found %zu records.", logksi->blockNo, logksi->block.recordCount, logksi->block.nofRecordHashes);
	}

	/* If the blocks file contains hashes, re-compute and compare the root hash against the provided root hash. */
	if (logksi->block.nofRecordHashes) {
		char description[1024];
		PST_snprintf(description, sizeof(description), "Root hash mismatch in block %zu", logksi->blockNo);

		res = MERKLE_TREE_calculateRootHash(logksi->tree, &rootHash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate root hash.", logksi->blockNo);

		res = logksi_datahash_compare(err, mp, logksi, 0, rootHash, hash, description, "Root hash computed from record hashes:", "Unsigned root hash stored in block data file:");
		res = continue_on_hash_fail(res, set, mp, logksi, rootHash, hash, &replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: root hashes not equal.", logksi->blockNo);
	} else {
		replacement = KSI_DataHash_ref(hash);
	}

	logksi->block.rootHash = replacement;

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(rootHash);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	KSI_TlvElement_free(tlvNoSig);
	return res;
}

int process_ksi_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_HashAlgorithm algo;

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	logksi->blockNo++;
	logksi->sigNo++;
	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing KSI signature ... ", logksi->blockNo);

	logksi->block.signatureTLVReached = 1;

	res = tlv_element_parse_and_check_sub_elements(err, ksi, logksi->ftlv_raw, logksi->ftlv_len, logksi->ftlv.hdr_len, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature as TLV element.", logksi->blockNo);

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: verifying KSI signature... ", logksi->blockNo);

	if (processors->verify_signature) {
		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", logksi->blockNo);

		res = processors->verify_signature(set, mp, err, ksi, logksi, files, sig, NULL, 0, &verificationResult);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: KSI signature verification failed.", logksi->blockNo);
		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

		res = KSI_Signature_getDocumentHash(sig, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get root hash from KSI signature.", logksi->blockNo);

		res = KSI_DataHash_getHashAlg(hash, &algo);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get algorithm ID from root hash.", logksi->blockNo);

		/* Configure merkle tree internal hash algorithm, that is used
		   to hash the record chain.  */
		res = MERKLE_TREE_reset(logksi->tree, algo,
								NULL,
								NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to reset MERKLE_TREE.", logksi->blockNo);

		KSI_DataHash_free(logksi->block.rootHash);
		logksi->block.rootHash = KSI_DataHash_ref(hash);
	}

	logksi->task.verify.lastBlockWasSkipped = 0;
	res = KT_OK;

	{
		KSI_Integer *t1 = NULL;
		char sigTimeStr[256] = "<null>";
		res = KSI_Signature_getSigningTime(sig, &t1);
		ERR_CATCH_MSG(err, res, NULL);

		logksi->block.sigTime_1 = KSI_Integer_getUInt64(t1);

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: signing time: (%llu) %s\n", logksi->blockNo, logksi->block.sigTime_1, LOGKSI_signature_sigTimeToString(sig, sigTimeStr, sizeof(sigTimeStr)));
	}

	/* Verify KSI signatures Client ID. */
	res = check_log_signature_client_id(set, mp, err, logksi, sig);
	if (res != KT_OK) goto cleanup;

	cleanup:

	KSI_Signature_free(sig);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	return res;
}

int process_log_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi) {
	return process_log_signature_general_components_(set, mp, err, ksi, NULL, 0, logksi, files, NULL);
}

int process_log_signature_with_block_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, KSI_PublicationsFile *pubFile) {
	return process_log_signature_general_components_(set, mp, err, ksi, pubFile, 1, logksi, files, processors);
}


int finalize_block(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi) {
	int res;
	KSI_DataHash *prevLeaf = NULL;

	if (set == NULL || err == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (logksi->blockNo > logksi->sigNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature data missing.", logksi->blockNo);
	}

	res = check_record_time_check_between_files(set, mp, err, logksi, files);
	if (res != KT_OK) goto cleanup;

	if ((logksi->file.recTimeMin == 0 || logksi->file.recTimeMin > logksi->block.recTimeMin) && logksi->block.recTimeMin > 0) logksi->file.recTimeMin = logksi->block.recTimeMin;
	if (logksi->file.recTimeMax == 0 || logksi->file.recTimeMax < logksi->block.recTimeMax) logksi->file.recTimeMax = logksi->block.recTimeMax;

	res = check_block_signing_time_check(set, mp, err, logksi, files);
	if (res != KT_OK) goto cleanup;

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, 0);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, 0);

	res = MERKLE_TREE_getPrevLeaf(logksi->tree, &prevLeaf);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get previous leaf.", logksi->blockNo);

	if (logksi->blockNo > 0) {
		char strT1[256] = "<no signature data available>";
		char strExtTo[256] = "<null>";
		char inHash[256] = "<null>";
		char outHash[256] = "<null>";
		int isSignTask = 0;
		int isExtractTask = 0;
		int isExtendTask = 0;
		int shortIndentation = SIZE_OF_SHORT_INDENTENTION;
		int longIndentation = SIZE_OF_LONG_INDENTATION;

		if (logksi->block.sigTime_1 > 0) {
			LOGKSI_uint64_toDateString(logksi->block.sigTime_1, strT1, sizeof(strT1));
		}

		if (logksi->task.extend.extendedToTime > 0) {
			LOGKSI_uint64_toDateString(logksi->task.extend.extendedToTime, strExtTo, sizeof(strExtTo));
		}

		LOGKSI_DataHash_toString(logksi->block.inputHash, inHash, sizeof(inHash));
		LOGKSI_DataHash_toString(prevLeaf, outHash, sizeof(outHash));

		isSignTask = logksi->taskId == TASK_SIGN;
		isExtractTask = logksi->taskId == TASK_EXTRACT;
		isExtendTask = logksi->taskId == TASK_EXTEND;

		if (logksi->file.version != RECSIG11 && logksi->file.version != RECSIG12 &&
			((isSignTask && logksi->task.sign.curBlockJustReSigned) || (isExtractTask && EXTRACT_INFO_getPositionsInBlock(logksi->task.extract.info)) || (!isSignTask && !isExtractTask))) {
			print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\nSummary of block %zu:\n", logksi->blockNo);

			if (isSignTask || isExtractTask || isExtendTask) {
				shortIndentation = longIndentation;
			}

			if (!logksi->block.curBlockNotSigned) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Sig time:", strT1);
				if (logksi->task.extend.extendedToTime > 0) print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Extended to:", strExtTo);
			} else {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Sig time:", "<unsigned>");
			}

			if (!isSignTask && !isExtractTask && !isExtendTask) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Input hash:", inHash);
				if (logksi->block.signatureTLVReached) {
					print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Output hash:", outHash);
				} else {
					print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", shortIndentation, "Output hash:", "<not valid value>");
				}
			}

			/* Print line numbers. */
			if (logksi->block.firstLineNo < logksi->file.nofTotalRecordHashes) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu - %zu (%zu)\n", longIndentation, "Lines:", logksi->block.firstLineNo, logksi->file.nofTotalRecordHashes, logksi->block.recordCount - logksi->block.nofMetaRecords);
			} else if (logksi->block.recordCount == 1 && logksi->block.nofMetaRecords == 1) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*sn/a\n", longIndentation, "Line:");
			} else if (logksi->block.firstLineNo == logksi->file.nofTotalRecordHashes) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Line:", logksi->block.firstLineNo);
			} else {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s<unknown>\n", longIndentation, "Line:");
			}

			if (logksi->block.recTimeMin > 0) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", longIndentation, "First record time:", LOGKSI_uint64_toDateString(logksi->block.recTimeMin, strT1, sizeof(strT1)));
			}

			if (logksi->block.recTimeMax > 0) {
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", longIndentation, "Last record time:", LOGKSI_uint64_toDateString(logksi->block.recTimeMax, strT1, sizeof(strT1)));
				print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", longIndentation, "Block duration:", time_diff_to_string(logksi->block.recTimeMax - logksi->block.recTimeMin, strT1, sizeof(strT1)));

			}

			if (logksi->block.nofMetaRecords > 0) print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Count of meta-records:", logksi->block.nofMetaRecords);
			if (logksi->block.nofHashFails > 0) print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Count of hash failures:", logksi->block.nofHashFails);
			if (EXTRACT_INFO_getPositionsInBlock(logksi->task.extract.info) > 0) print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", longIndentation, "Records extracted:", EXTRACT_INFO_getPositionsInBlock(logksi->task.extract.info));

			print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\n", outHash);
		}
	}

	/* Print Output hash of previous block. */
	if (prevLeaf != NULL && logksi->taskId == TASK_VERIFY && logksi->block.signatureTLVReached) {
		char buf[256];
		LOGKSI_DataHash_toString(prevLeaf, buf, sizeof(buf));
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: output hash: %s.\n", logksi->blockNo, buf);
	}

	if (logksi->task.integrate.unsignedRootHash) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Warning: Block no. %3zu: unsigned root hash found.\n", logksi->blockNo);
	}

	if (logksi->block.finalTreeHashesNone) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: Warning: all final tree hashes are missing.\n", logksi->blockNo);
		logksi->file.warningTreeHashes = 1;
	} else if (logksi->block.finalTreeHashesAll) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: all final tree hashes are present.\n", logksi->blockNo);
	}

	res = KT_OK;

cleanup:

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_ERRORS);
	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_SUMMARY);
	KSI_DataHash_free(prevLeaf);

	return res;
}

int finalize_log_signature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, KSI_CTX *ksi, KSI_DataHash* inputHash) {
	int res;
	unsigned char buf[2];
	char inHash[256] = "<null>";
	char outHash[256] = "<null>";
	int shortIndentation = 13;
	int longIndentation = 29;
	KSI_DataHash *prevLeaf = NULL;


	if (err == NULL || logksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	if (logksi->blockNo == 0) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: No blocks found.");
	}

	/* Finalize last block. */
	res = finalize_block(set, mp, err, logksi, files, ksi);
	ERR_CATCH_MSG(err, res, "Error: Unable to finalize last block.");

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Finalizing log signature... ");

	/* Log file must not contain more records than log signature file. */
	if (files->files.inLog) {
		size_t count = 0;
		SMART_FILE_read(files->files.inLog, buf, 1, &count);
		if (count > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: end of log file contains unexpected records.", logksi->blockNo);
		}
	}

	/* Signatures file must not contain more blocks than blocks file. */
	if (files->files.partsSig) {
		size_t count = 0;
		SMART_FILE_read(files->files.partsSig, buf, 1, &count);
		if (count > 0) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: end of signatures file contains unexpected data.", logksi->blockNo);
		}
	}

	if (logksi->file.nofTotaHashFails && !PARAM_SET_isSetByName(set, "multiple_logs")) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: %zu hash comparison failures found.", logksi->file.nofTotaHashFails);
	}

	if (EXTRACT_INFO_isLastPosPending(logksi->task.extract.info)) {
		res = KT_INVALID_CMD_PARAM;
		ERR_CATCH_MSG(err, res, "Error: Extract position %zu out of range - not enough loglines.", EXTRACT_INFO_getNextPosition(logksi->task.extract.info));
	}

	/* Mark output signature file consistent. */
	if (files->files.outSig != NULL) {
		res = SMART_FILE_markConsistent(files->files.outSig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to mark output log signature file consistent.", logksi->blockNo);
	}

	res = KT_OK;

cleanup:

	if (res == KT_VERIFICATION_FAILURE) LOGKSI_setErrorLevel(logksi, LOGKSI_VER_RES_FAIL);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, "\nSummary of logfile:\n");

	print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of blocks:", logksi->blockNo);
	if (logksi->file.nofTotalFailedBlocks > 0) print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of failures:", logksi->file.nofTotalFailedBlocks);
	print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of record hashes:", logksi->file.nofTotalRecordHashes); /* Meta records not included. */

	if (logksi->task.sign.noSigNo > 0) {
		if (logksi->taskId == TASK_SIGN) {
			print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of resigned blocks:", logksi->task.sign.noSigCreated);
			if (logksi->task.sign.noSigCreated < logksi->task.sign.noSigNo) {
				print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of unsigned blocks:", logksi->task.sign.noSigNo - logksi->task.sign.noSigCreated);
			}
		} else {
			print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of unsigned blocks:", logksi->task.sign.noSigNo);
		}
	}

	if (logksi->file.nofTotalMetarecords > 0) print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of meta-records:", logksi->file.nofTotalMetarecords); /* Meta records not included. */
	if (logksi->file.nofTotaHashFails > 0) print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Count of hash failures:", logksi->file.nofTotaHashFails);
	if (EXTRACT_INFO_getPositionsExtracted(logksi->task.extract.info) > 0) print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%zu\n", longIndentation, "Records extracted:", EXTRACT_INFO_getPositionsExtracted(logksi->task.extract.info));

	if (logksi->file.recTimeMin > 0 && logksi->file.recTimeMax) {
		char str_rec_time_min[1024] = "<null>";
		char str_rec_time_max[1024] = "<null>";
		char time_diff[1024] = "<null>";
		const char *sign = "";
		int calc_sign = 0;

		time_diff_to_string(uint64_diff(logksi->file.recTimeMax, logksi->file.recTimeMin, &calc_sign), time_diff, sizeof(time_diff));
		if (calc_sign < 0) sign = "-";

		LOGKSI_uint64_toDateString(logksi->file.recTimeMin, str_rec_time_min, sizeof(str_rec_time_min));
		LOGKSI_uint64_toDateString(logksi->file.recTimeMax, str_rec_time_max, sizeof(str_rec_time_max));

		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", longIndentation, "First record time:", str_rec_time_min);
		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", longIndentation, "Last record time:", str_rec_time_max);
		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s%s\n", longIndentation, "Log file duration:", sign, time_diff);
	}

	MERKLE_TREE_getPrevLeaf(logksi->tree, &prevLeaf);
	LOGKSI_DataHash_toString(inputHash, inHash, sizeof(inHash));
	LOGKSI_DataHash_toString(prevLeaf, outHash, sizeof(outHash));

	if (logksi->file.version != RECSIG11 && logksi->file.version != RECSIG12 && (logksi->taskId == TASK_VERIFY || logksi->taskId == TASK_INTEGRATE)) {
		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", shortIndentation, "Input hash:", inHash);
		print_debug_mp(mp, MP_ID_LOGFILE_SUMMARY, DEBUG_SMALLER | DEBUG_LEVEL_3, " * %-*s%s\n", shortIndentation, "Output hash:", outHash);
	}


	if (LOGKSI_hasWarnings(logksi)) {
		if (logksi && logksi->task.integrate.warningSignatures) {
			print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_LEVEL_0, "Warning: Unsigned root hashes found.\n         Run 'logksi sign' to perform signing recovery.\n");
		}

		if (logksi && logksi->file.warningTreeHashes) {
			print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_LEVEL_0, "Warning: Some tree hashes are missing from the log signature file.\n         Run 'logksi sign' with '--insert-missing-hashes' to repair the log signature.\n");
		}

		if (logksi && logksi->file.warningLegacy) {
			print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_LEVEL_0, "Warning: RFC3161 timestamp(s) found in log signature.\n         Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures.\n");
		}
	}

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	MULTI_PRINTER_printByID(mp, MP_ID_LOGFILE_SUMMARY);
	KSI_DataHash_free(prevLeaf);

	return res;
}




static int process_block_header(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *replacement = NULL;
	KSI_DataHash *prevLeaf = NULL;
	KSI_TlvElement *tlv = NULL;
	size_t algo;
	KSI_OctetString *randomSeed = NULL;


	if (err == NULL || ksi == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing block header... ", logksi->blockNo);



	res = tlv_element_parse_and_check_sub_elements(err, ksi, logksi->ftlv_raw, logksi->ftlv_len, logksi->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block header as TLV element.", logksi->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &algo);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing hash algorithm in block header.", logksi->blockNo);

	res = tlv_element_get_octet_string(tlv, ksi, 0x02, &randomSeed);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing random seed in block header.", logksi->blockNo);

	res = tlv_element_get_hash(err, tlv, ksi, 0x03, &hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse last hash of previous block.", logksi->blockNo);

	KSI_DataHash_free(logksi->block.inputHash);
	logksi->block.inputHash = KSI_DataHash_ref(hash);

	res = MERKLE_TREE_getPrevLeaf(logksi->tree, &prevLeaf);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable get previous leaf.", logksi->blockNo);

	if (prevLeaf != NULL) {
		char description[1024];
		PST_snprintf(description, sizeof(description), "Output hash of block %zu differs from input hash of block %zu", logksi->blockNo - 1, logksi->blockNo);

		res = logksi_datahash_compare(err, mp, logksi, 0, prevLeaf, hash, description, "Last hash computed from previous block data:", "Input hash stored in current block header:");
		res = continue_on_hash_fail(res, set, mp, logksi, prevLeaf, hash, &replacement);
		if (res != KT_OK && logksi->isContinuedOnFail && logksi->taskId == TASK_VERIFY) {
			char debugMessage[1024] = "";

			if (logksi->task.verify.lastBlockWasSkipped) {
				PST_snprintf(debugMessage, sizeof(debugMessage), " Failure may be caused by the error in the previous block %zu. Using input hash of the current block instead.", logksi->blockNo - 1);
				KSI_DataHash_free(replacement);
				replacement = KSI_DataHash_ref(hash);
			}

			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Verification is continued.%s\n", debugMessage);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Verification is continued.%s\n", logksi->blockNo, debugMessage);
			res = KT_OK;
		} else {
			ERR_CATCH_MSG(err, res, "Error: %s.", description);
		}
	} else {
		replacement = KSI_DataHash_ref(hash);
	}

	if (files->files.outSig) {
		/* Set the offset at the beginning of new block, so it is possible to apply recovery procedures if there is a failure. */
		res = SMART_FILE_markConsistent(files->files.outSig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to mark output log signature file consistent.", logksi->blockNo);

		res = SMART_FILE_write(files->files.outSig, logksi->ftlv_raw, logksi->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy block header.", logksi->blockNo);
	}

	res = MERKLE_TREE_reset(logksi->tree, algo,
										replacement,
										randomSeed);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to reset MERKLE_TREE.", logksi->blockNo);

	replacement = NULL;
	randomSeed = NULL;

	logksi->block.hashAlgo = algo;

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(hash);
	KSI_TlvElement_free(tlv);
	KSI_DataHash_free(prevLeaf);
	KSI_DataHash_free(replacement);
	KSI_OctetString_free(randomSeed);

	return res;
}

static int process_record_hash(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files) {
	int res;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *replacement = NULL;

	if (err == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = is_record_hash_expected(logksi, err);
	if (res != KT_OK) goto cleanup;

	logksi->block.keepRecordHashes = 1;
	logksi->block.nofRecordHashes++;

	res = LOGKSI_DataHash_fromImprint(err, ksi, logksi->ftlv_raw + logksi->ftlv.hdr_len, logksi->ftlv.dat_len, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse hash of logline no. %zu.", logksi->blockNo, LOGKSI_getNofLines(logksi));

	if (logksi->block.metarecordHash != NULL) {
		char description[1024];
		PST_snprintf(description, sizeof(description), "Metarecord hash mismatch in block %zu", logksi->blockNo);

		/* This is a metarecord hash. */
		res = logksi_datahash_compare(err, mp, logksi, 0, logksi->block.metarecordHash, recordHash, description, "Metarecord hash computed from metarecord:", "Metarecord hash stored in log signature file:");
		res = continue_on_hash_fail(res, set, mp, logksi, logksi->block.metarecordHash, recordHash, &replacement);
		if (!logksi->isContinuedOnFail || logksi->taskId != TASK_VERIFY) {
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: metarecord hashes not equal.", logksi->blockNo);
		}

		if (res != KT_OK) goto cleanup;

		res = logksi_add_record_hash_to_merkle_tree(logksi, 1, replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", logksi->blockNo);

		KSI_DataHash_free(logksi->block.metarecordHash);
		logksi->block.metarecordHash = NULL;
	} else {
		/* This is a logline record hash. */
		if (files->files.inLog) {
			res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, logksi, files, &hash);
			if (res == KT_IO_ERROR) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash no. %zu does not have a matching logline, end of logfile reached.", logksi->blockNo, LOGKSI_getNofLines(logksi));
			} else if (res != KT_OK) goto cleanup;

			res = logksi_datahash_compare(err, mp, logksi, 1, hash, recordHash, NULL, "Record hash computed from logline:", "Record hash stored in log signature file:");
			res = continue_on_hash_fail(res, set, mp, logksi, hash, recordHash, &replacement);
			if (!logksi->isContinuedOnFail || logksi->taskId != TASK_VERIFY) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hashes not equal for logline no. %zu.", logksi->blockNo, LOGKSI_getNofLines(logksi));
			}

			if (res != KT_OK) goto cleanup;
		} else {
			replacement = KSI_DataHash_ref(recordHash);
		}

		res = logksi_add_record_hash_to_merkle_tree(logksi, 0, replacement);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add hash to Merkle tree.", logksi->blockNo);
	}

	if (files->files.outSig) {
		res = SMART_FILE_write(files->files.outSig, logksi->ftlv_raw, logksi->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy record hash.", logksi->blockNo);
	}
	res = KT_OK;

cleanup:

	KSI_DataHash_free(replacement);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(hash);
	return res;
}

static int process_tree_hash(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files, int *finalHash) {
	int res;
	KSI_DataHash *unverified = NULL;
	KSI_DataHash *treeHash = NULL;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *tmpRoot = NULL;
	KSI_DataHash *root = NULL;
	KSI_DataHash *replacement = NULL;
	KSI_DataHash *tmp = NULL;
	unsigned char i;

	if (err == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = is_tree_hash_expected(logksi, err);
	if (res != KT_OK) goto cleanup;

	logksi->block.keepTreeHashes = 1;
	logksi->block.nofTreeHashes++;

	res = LOGKSI_DataHash_fromImprint(err, ksi, logksi->ftlv_raw + logksi->ftlv.hdr_len, logksi->ftlv.dat_len, &treeHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse tree hash.", logksi->blockNo);

	if (files->files.outSig) {
		res = SMART_FILE_write(files->files.outSig, logksi->ftlv_raw, logksi->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy tree hash.", logksi->blockNo);
	}

	if (!logksi->block.finalTreeHashesSome) {
		/* If the block contains tree hashes, but not record hashes:
		 * Calculate missing record hashes from the records in the logfile and
		 * build the Merkle tree according to the number of tree hashes encountered. */
		if (logksi->block.keepRecordHashes == 0 && logksi->block.nofTreeHashes > MERKLE_TREE_calcMaxTreeHashes(logksi->block.nofRecordHashes)) {
			/* If the block is closed prematurely with a metarecord, process the current tree hash as a mandatory leaf hash.
			 * Subsequent tree hashes are either mandatory tree hashes corresponding to the metarecord hash or optional final tree hashes. */
			if (logksi->block.metarecordHash) {
				logksi->block.finalTreeHashesLeaf = 1;
			}
			logksi->block.nofRecordHashes++;
			if (files->files.inLog) {
				if (logksi->block.metarecordHash) {
					res = logksi_add_record_hash_to_merkle_tree(logksi, 1, logksi->block.metarecordHash);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", logksi->blockNo);

					/*
					 * TODO:
					 * TODO:
					 * TODO:
					 * TODO:
					 * TODO: Kas see siin on vajalik?
					 */
					KSI_DataHash_free(logksi->block.metarecordHash);
					logksi->block.metarecordHash = NULL;
				} else {
					res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, logksi, files, &recordHash);
					if (res == KT_IO_ERROR) {
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hash does not have a matching logline no. %zu, end of logfile reached.", logksi->blockNo, LOGKSI_getNofLines(logksi));
					} else if (res != KT_OK) goto cleanup;

					res = logksi_add_record_hash_to_merkle_tree(logksi, 0, recordHash);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add record hash to Merkle tree.", logksi->blockNo);

					KSI_DataHash_free(recordHash);
					recordHash = NULL;
				}
			} else {
				/* No log file available so build the Merkle tree from tree hashes alone. */
				res = MERKLE_TREE_addLeafHash(logksi->tree, treeHash, 0);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add leaf hash to Merkle tree.", logksi->blockNo);
			}
		}
		if (logksi->block.nofRecordHashes) {
			unsigned char position = 0;
			char description[1024];
			PST_snprintf(description, sizeof(description), "Tree hash mismatch in block %zu", logksi->blockNo);

			/* Find the corresponding tree hash from the Merkle tree. */
			res = MERKLE_TREE_popUnverifed(logksi->tree, &position, &unverified);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to pop unverified tree node from the  Merkle tree.", logksi->blockNo);

			if (position == MERKLE_TREE_getHeight(logksi->tree)) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected tree hash for logline no. %zu.", logksi->blockNo, LOGKSI_getNofLines(logksi));
			}

			res = logksi_datahash_compare(err, mp, logksi, 0, unverified, treeHash, description, "Tree hash computed from record hashes:", "Tree hash stored in log signature file:");
			res = continue_on_hash_fail(res, set, mp, logksi, unverified, treeHash, &replacement);
			if (!logksi->isContinuedOnFail || logksi->taskId != TASK_VERIFY) {
				if (logksi->block.keepRecordHashes) {
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal for logline no. %zu.", logksi->blockNo, LOGKSI_getNofLines(logksi));
				}

				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal.", logksi->blockNo);
			}

			if (res != KT_OK) goto cleanup;

			KSI_DataHash_free(unverified);
			unverified = NULL;
		}
		if (logksi->block.finalTreeHashesLeaf && !MERKLE_TREE_nofUnverifiedHashes(logksi->tree)) {
			/* This was the last mandatory tree hash. From this point forward all tree hashes must be interpreted as optional final tree hashes. */
			logksi->block.finalTreeHashesSome = 1;

			res = MERKLE_TREE_setFinalHashesForVerification(logksi->tree);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to get tree hash for verification.", logksi->blockNo);
		}
	} else {
		if (logksi->block.nofRecordHashes) {
			char description[1024];
			PST_snprintf(description, sizeof(description), "Tree hash mismatch in block %zu", logksi->blockNo);

			if (finalHash != NULL) *finalHash = 1;
			print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: interpreting tree hash no. %3zu as a final hash... ", logksi->blockNo, logksi->block.nofTreeHashes);
			/* Find the corresponding tree hash from the Merkle tree. */
			i = 0;


			res = MERKLE_TREE_popUnverifed(logksi->tree, NULL, &root);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to pop unverified root tree node.", logksi->blockNo);

			res = MERKLE_TREE_popUnverifed(logksi->tree, &i, &tmp);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to pop unverified root tree node.", logksi->blockNo);

			res = MERKLE_TREE_calculateTreeHash(logksi->tree, tmp, root, i + 2, &tmpRoot);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable pop unverified root tree node.", logksi->blockNo);

			res = MERKLE_TREE_insertUnverified(logksi->tree, i, tmpRoot);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to insert unverified root tree node.", logksi->blockNo);

			if (i == MERKLE_TREE_getHeight(logksi->tree)) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected tree hash for logline no. %zu.", logksi->blockNo, LOGKSI_getNofLines(logksi));
			}

			res = logksi_datahash_compare(err, mp, logksi, 0, tmpRoot, treeHash, description, "Tree hash computed from record hashes:", "Tree hash stored in log signature file:");
			res = continue_on_hash_fail(res, set, mp, logksi, tmpRoot, treeHash, &replacement);
			if (!logksi->isContinuedOnFail || logksi->taskId != TASK_VERIFY) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal for logline no. %zu.", logksi->blockNo, LOGKSI_getNofLines(logksi));
			}

			if (res != KT_OK) goto cleanup;
		}
	}

	res = KT_OK;

cleanup:
	if (res == KT_VERIFICATION_FAILURE) LOGKSI_setErrorLevel(logksi, LOGKSI_VER_RES_FAIL);

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(unverified);
	KSI_DataHash_free(treeHash);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(tmpRoot);
	KSI_DataHash_free(root);
	KSI_DataHash_free(replacement);
	KSI_DataHash_free(tmp);
	return res;
}

static const char *meta_data_value_to_string(PARAM_SET* set, const KSI_OctetString *oct, char *buf, size_t buf_len) {
	int res = KT_UNKNOWN_ERROR;
	size_t i = 0;
	const unsigned char *data = NULL;
	size_t data_len = 0;
	size_t count = 0;
	const char *ret = NULL;

	if (set == NULL || oct == NULL || buf == NULL || buf_len == 0) return NULL;

	if (PARAM_SET_isSetByName(set, "hex-to-str")) {
		res = KSI_OctetString_extract(oct, &data, &data_len);
		if (res != KSI_OK) return NULL;

		buf[count++] = '\'';
		for (i = 0; i < data_len && count + 2 < buf_len; i++) {
			char c = data[i];

			if (isprint(c)) {
				buf[count] = c;
				count++;
			} else {
				count += PST_snprintf(buf + count, buf_len - count, "\\%02x", c);
			}
		}
		buf[count++] = '\'';
		buf[count] = '\0';

		ret = buf;
	} else {
		ret = KSI_OctetString_toString(oct, 0, buf, buf_len);
	}

	return ret;
}

static int process_metarecord(PARAM_SET* set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files) {
	int res;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *meta_record_pair = NULL;
	KSI_Utf8String *meta_key = NULL;
	KSI_OctetString *meta_value = NULL;
	size_t metarecord_index = 0;
	char buf[0xffff + 3];

	if (err == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = tlv_element_parse_and_check_sub_elements(err, ksi, logksi->ftlv_raw, logksi->ftlv_len, logksi->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse metarecord as TLV element.", logksi->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &metarecord_index);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing metarecord index.", logksi->blockNo);


	res = KSI_TlvElement_getElement(tlv, 0x02, &meta_record_pair);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Mandatory TLV 911.02 (Meta record pair) is missing.", logksi->blockNo);

	res = KSI_TlvElement_getUtf8String(meta_record_pair, ksi, 0x01, &meta_key);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to get TLV 911.02.01 (Meta record key).", logksi->blockNo);

	res = KSI_TlvElement_getOctetString(meta_record_pair, ksi, 0x02, &meta_value);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to get TLV 911.02.02 (Meta record value).", logksi->blockNo);

	print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Meta-record key  : '%s'.\n", logksi->blockNo, KSI_Utf8String_cstr(meta_key));
	print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Meta-record value: %s.\n", logksi->blockNo, meta_data_value_to_string(set, meta_value, buf, sizeof(buf)));


	if (files->files.inLog) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree according to the record count in the signature data. */
		if (logksi->block.metarecordHash != NULL) {
			/* Add the previous metarecord to Merkle tree. */
			logksi->block.nofRecordHashes++;

			res = logksi_add_record_hash_to_merkle_tree(logksi, 1, logksi->block.metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", logksi->blockNo);
		}

		/*
		 * If there are some record hashes missing, read loglines from logfile and
		 * calculate corresponding record hash values and add them to merkle tree.
		 * After that it is possible to add metarecord itself to the Merkle tree.
		 */
		while (logksi->block.nofRecordHashes < metarecord_index) {
			logksi->block.nofRecordHashes++;
			res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, logksi, files, &hash);
			if (res == KT_IO_ERROR) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: at least %zu loglines expected up to metarecord index %zu, end of logfile reached.", logksi->blockNo, LOGKSI_getNofLines(logksi), metarecord_index);
			} else if (res != KT_OK) goto cleanup;

			res = logksi_add_record_hash_to_merkle_tree(logksi, 0, hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", logksi->blockNo);

			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	KSI_DataHash_free(logksi->block.metarecordHash);
	logksi->block.metarecordHash = NULL;
	res = logksi_calculate_hash_of_metarecord_and_store_metarecord(logksi, tlv, &logksi->block.metarecordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate metarecord hash with index %zu.", logksi->blockNo, metarecord_index);

	if (files->files.outSig) {
		res = SMART_FILE_write(files->files.outSig, logksi->ftlv_raw, logksi->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to copy metarecord hash.", logksi->blockNo);
	}

	res = KT_OK;

cleanup:

	KSI_DataHash_free(hash);
	KSI_TlvElement_free(meta_record_pair);
	KSI_Utf8String_free(meta_key);
	KSI_OctetString_free(meta_value);
	KSI_TlvElement_free(tlv);
	return res;
}

static int extract_ksi_signature(KSI_CTX *ctx, RECORD_INFO *record, const KSI_Signature *sig, KSI_Signature **out) {
	int res = KT_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	KSI_SignatureBuilder *builder = NULL;
	KSI_AggregationHashChain *aggrChain = NULL;

	if (ctx == NULL || record == NULL || sig == NULL || out == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_SignatureBuilder_openFromSignature(sig, &builder);
	if (res != KSI_OK) goto cleanup;

	res = RECORD_INFO_getAggregationHashChain(record, ctx, &aggrChain);
	if (res != KSI_OK) goto cleanup;

	res = KSI_SignatureBuilder_createSignatureWithAggregationChain(builder, aggrChain, &tmp);
	if (res != KSI_OK) goto cleanup;

	*out = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_Signature_free(tmp);
	KSI_SignatureBuilder_free(builder);
	KSI_AggregationHashChain_free(aggrChain);

	return res;
}

static int store_integrity_proof_and_log_records(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, RECORD_INFO *record, IO_FILES *files) {
	int res = KT_INVALID_ARGUMENT;
	KSI_TlvElement *recChain = NULL;
	KSI_TlvElement *hashStep = NULL;
	unsigned char buf[0xFFFF + 4];
	size_t len = 0;
	size_t lineNumber = 0;
	char *logLine;
	KSI_DataHash *recordHash = NULL;
	KSI_TlvElement *metadata = NULL;


	if (set == NULL || err == NULL || ksi == NULL || record == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = RECORD_INFO_getLine(record, &lineNumber, &logLine);
	ERR_CATCH_MSG(err, res, "Error: Unable to get record line information.");

	res = RECORD_INFO_getRecordHash(record, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Unable to get record hash.");

	res = RECORD_INFO_getMetadata(record, &metadata);
	ERR_CATCH_MSG(err, res, "Error: Unable to get metadata TLV.");

	/* Construct hash chain for one log record. */
	res = KSI_TlvElement_new(&recChain);
	ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to create record chain.", lineNumber);
	recChain->ftlv.tag = 0x0907;

	/* Store the record hash value. */
	res = tlv_element_set_hash(recChain, ksi, 0x01, recordHash);
	ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add record hash to record chain.", lineNumber);

	/* In case of log line, store it into file.
	   In case of meta record  store it into record chain TLV. */
	if (logLine) {
		res = SMART_FILE_write(files->files.outLog, (unsigned char*)logLine, strlen(logLine), NULL);
		ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to write log record to log records file.", lineNumber);
	} else if (metadata){
		res = KSI_TlvElement_setElement(recChain, metadata);
		ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to add metarecord to record chain.", lineNumber);
	}

	res = tlv_element_set_record_hash_chain(recChain, ksi, record);
	ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to construct record hash chain TLV.", lineNumber);

	/* Serialize hash chain TLV and store into integrity proof file. */
	res = KSI_TlvElement_serialize(recChain, buf, sizeof(buf), &len, 0);
	ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to serialize record chain.", lineNumber);

	res = SMART_FILE_write(files->files.outProof, buf, len, NULL);
	ERR_CATCH_MSG(err, res, "Error: Record no. %zu: unable to write record chain to integrity proof file.", lineNumber);

	KSI_TlvElement_free(recChain);
	recChain = NULL;


	res = KT_OK;

cleanup:

	KSI_TlvElement_free(recChain);
	KSI_TlvElement_free(hashStep);
	KSI_TlvElement_free(metadata);
	KSI_DataHash_free(recordHash);

	return res;
}

static int store_ksi_signature_and_log_line(PARAM_SET *set, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files, char *logLine, size_t lineNr, KSI_Signature *sig) {
	int res;
	SMART_FILE *sigFile = NULL;
	SMART_FILE *logLineFile = NULL;

	char *lineOutName = NULL;
	char *sigOutName = NULL;
	size_t bufLen = 0;
	size_t baseNameLen = 0;
	size_t bytesWritten = 0;
	size_t logLineSize = 0;
	unsigned char *raw = NULL;
	size_t rawLen = 0;
	int i = 0;

	if (set == NULL || err == NULL || logksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create file name buffers. */
	baseNameLen = strlen(files->internal.inLog);
	bufLen = baseNameLen + 64;

	lineOutName = (char*)malloc(bufLen);
	sigOutName = (char*)malloc(bufLen);
	if (lineOutName == NULL || sigOutName == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Generate file names. */
	if (strcmp(files->internal.outLineBase, "-") == 0) {
		KSI_strncpy(lineOutName, files->internal.outLineBase, bufLen);
	} else {
		KSI_snprintf(lineOutName, bufLen, "%s.line.%zu", files->internal.outLineBase, lineNr);
	}

	if (strcmp(files->internal.outKSIBase, "-") == 0) {
		KSI_strncpy(sigOutName, files->internal.outKSIBase, bufLen);
	} else {
		KSI_snprintf(sigOutName, bufLen, "%s.line.%zu.ksig", files->internal.outKSIBase, lineNr);
	}

	/* Open output files. */
	res = SMART_FILE_open(lineOutName, "wTfs", &logLineFile);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: line %zu: unable to open file '%s'.", logksi->blockNo, lineNr, lineOutName);

	res = SMART_FILE_open(sigOutName, "wTfs", &sigFile);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: line %zu: unable to open file '%s'.", logksi->blockNo, lineNr, sigOutName);

	logLineSize = strlen(logLine);

	/* Do not include newline character. */
	for (i = 0; logLineSize > 0 && i < 2; i++) {
		char c = logLine[logLineSize - 1];
		if (c != ' ' && c != '\t' && isspace(c)) logLineSize--;
	}

	/* Write logline into file. */
	res = SMART_FILE_write(logLineFile, (unsigned char*)logLine, logLineSize, &bytesWritten);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: line %zu: unable to write log line to file '%s'.", logksi->blockNo, lineNr, lineOutName);

	if (bytesWritten != logLineSize) {
		res = KT_IO_ERROR;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: line %zu: only %zu log line bytes out of %zu written to file '%s'.", logksi->blockNo, lineNr, bytesWritten, logLineSize, lineOutName);
	}

	/* Write KSI signature into file. */
	res = KSI_Signature_serialize(sig, &raw, &rawLen);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: line %zu: unable to serialize KSI signature.", logksi->blockNo, lineNr);

	res = SMART_FILE_write(sigFile, raw, rawLen, &bytesWritten);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: line %zu: unable to write KSI signature to file '%s'.", logksi->blockNo, lineNr, sigOutName);

	if (bytesWritten != rawLen) {
		res = KT_IO_ERROR;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: line %zu: only %zu KSI signature bytes out of %zu written to file '%s'.", logksi->blockNo, lineNr, bytesWritten, rawLen, lineOutName);
	}

	res = SMART_FILE_markConsistent(sigFile);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: line %zu: unable mark file '%s' consistent.", logksi->blockNo, lineNr, lineOutName);

	res = SMART_FILE_markConsistent(logLineFile);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: line %zu: unable mark file '%s' consistent.", logksi->blockNo, lineNr, sigOutName);

	res = KT_OK;

cleanup:

	SMART_FILE_close(sigFile);
	SMART_FILE_close(logLineFile);
	free(lineOutName);
	free(sigOutName);
	KSI_free(raw);

	return res;
}

static const char *error_level_to_string(LOGKSI *logksi) {
	switch (logksi->logksiVerRes) {
		case LOGKSI_VER_RES_OK: return "ok";
		case LOGKSI_VER_RES_NA: return "inconclusive";
		case LOGKSI_VER_RES_FAIL: return "failed";
		default: return "<unexpected verification result>";
	}
}

static int process_block_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, SIGNATURE_PROCESSORS *processors, LOGKSI *logksi, IO_FILES *files) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *verificationResult = NULL;
	KSI_DataHash *hash = NULL;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvSig = NULL;
	KSI_TlvElement *tlvUnsig = NULL;
	KSI_TlvElement *tlvRfc3161 = NULL;
	KSI_Integer *t0 = NULL;

	KSI_VerificationContext_init(&context, ksi);

	if (set == NULL || err == NULL || ksi == NULL || processors == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
		print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "}\n");
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
	}

	logksi->sigNo++;
	if (logksi->sigNo > logksi->blockNo) {
		res = KT_VERIFICATION_FAILURE;
		LOGKSI_setErrorLevel(logksi, LOGKSI_VER_RES_FAIL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: block signature data without preceding block header found.", logksi->sigNo);
	}

	logksi->block.signatureTLVReached = 1;

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: processing block signature data... ", logksi->blockNo);

	res = tlv_element_parse_and_check_sub_elements(err, ksi, logksi->ftlv_raw, logksi->ftlv_len, logksi->ftlv.hdr_len, &tlv);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", logksi->blockNo);

	res = tlv_element_get_uint(tlv, ksi, 0x01, &logksi->block.recordCount);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in block signature.", logksi->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x906, &tlvRfc3161);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract RFC3161 element in block signature.", logksi->blockNo);

	if (tlvRfc3161 != NULL) {
		/* Convert the RFC3161 timestamp into KSI signature and replace it in the TLV. */
		res = convert_signature(ksi, tlvRfc3161->ptr + tlvRfc3161->ftlv.hdr_len, tlvRfc3161->ftlv.dat_len, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to convert RFC3161 element in block signature.", logksi->blockNo);

		res = KSI_TlvElement_removeElement(tlv, 0x906, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to remove RFC3161 timestamp from block signature.", logksi->blockNo);
		res = tlv_element_set_signature(tlv, ksi, 0x905, sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to insert KSI signature in block signature.", logksi->blockNo);
		KSI_Signature_free(sig);
		sig = NULL;

		logksi->file.warningLegacy = 1;
	}

	/* Try to extract KSI signature or unsigned block marker. */
	res = KSI_TlvElement_getElement(tlv, 0x905, &tlvSig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract KSI signature element in block signature.", logksi->blockNo);

	res = KSI_TlvElement_getElement(tlv, 0x02, &tlvUnsig);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract unsigned block marker.", logksi->blockNo);

	/* If block is unsigned, return verification error. If signature data is missing, return format error. */
	if (tlvUnsig != NULL) {
		res = KT_VERIFICATION_NA;
		LOGKSI_setErrorLevel(logksi, LOGKSI_VER_RES_NA);
		logksi->block.curBlockNotSigned = 1;
		logksi->quietError = res;
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Block %zu is unsigned!\n", logksi->blockNo);
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Block is unsigned!\n", logksi->blockNo);
		/* Don't use ERR_CATCH_MSG when --continue-on-fail is set, as the amount of errors
		   produced will easily exceed the limits of ERR_TRCKR. */
		if (!logksi->isContinuedOnFail || logksi->taskId != TASK_VERIFY) {
			ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion: Make sure that block signature is actually the original output\n"
											 "                and KSI signature is not replaced with unsigned marker!\n"
											 "                If that's correct, use logksi sign to sign unsigned blocks.\n");
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu is unsigned and missing KSI signature in block signature.", logksi->blockNo);
		}

		goto cleanup;
	} else if (tlvSig == NULL) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing KSI signature (and unsigned block marker) in block signature.", logksi->blockNo);
	}


	res = is_block_signature_expected(logksi, err);
	if (res != KT_OK) goto cleanup;

	if (files->files.inLog) {
		/* If the block contains metarecords but not the corresponding record hashes:
		 * Calculate missing metarecord hash from the last metarecord and
		 * build the Merkle tree with the metarecord hash. */
		if (logksi->block.metarecordHash) {
			/* Add the previous metarecord to Merkle tree. */
			logksi->block.nofRecordHashes++;

			res = logksi_add_record_hash_to_merkle_tree(logksi, 1, logksi->block.metarecordHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", logksi->blockNo);
		}

		/* If the block contains neither record hashes nor tree hashes:
		 * Calculate missing record hashes from the records in the logfile and
		 * build the Merkle tree according to the record count in the signature data. */
		if (logksi->block.keepRecordHashes == 0 && logksi->block.keepTreeHashes == 0) {
			while (logksi->block.nofRecordHashes < logksi->block.recordCount) {
				logksi->block.nofRecordHashes++;
				res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, logksi, files, &hash);
				if (res == KT_IO_ERROR) {
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: at least %zu loglines expected, end of logfile reached.", logksi->blockNo, LOGKSI_getNofLines(logksi));
				} else if (res != KT_OK) goto cleanup;

				res = logksi_add_record_hash_to_merkle_tree(logksi, 0, hash);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add hash to Merkle tree.", logksi->blockNo);

				KSI_DataHash_free(hash);
				hash = NULL;
			}
		}
	}


	/* If we have any record hashes directly from log signature file or indirectly from log file,
	 * their count must match the record count in block signature. */
	if (logksi->block.nofRecordHashes && logksi->block.nofRecordHashes != logksi->block.recordCount) {
		res = KT_VERIFICATION_FAILURE;
		LOGKSI_setErrorLevel(logksi, LOGKSI_VER_RES_FAIL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: expected %zu record hashes, but found %zu.", logksi->blockNo, logksi->block.recordCount, logksi->block.nofRecordHashes);
	}
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);


	logksi->file.nofTotalRecordHashes += logksi->block.nofRecordHashes;

	if (logksi->block.firstLineNo < logksi->file.nofTotalRecordHashes) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: lines processed %zu - %zu (%zu)\n", logksi->blockNo, logksi->block.firstLineNo, logksi->file.nofTotalRecordHashes, logksi->block.recordCount - logksi->block.nofMetaRecords);
	} else if (logksi->block.recordCount == 1 && logksi->block.nofMetaRecords == 1) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed n/a\n", logksi->blockNo);
	} else if (logksi->block.firstLineNo == logksi->file.nofTotalRecordHashes) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed %zu\n", logksi->blockNo,  logksi->block.firstLineNo);
	} else {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: line processed <unknown>\n", logksi->blockNo);
	}


	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: verifying KSI signature... ", logksi->blockNo);

	res = MERKLE_TREE_calculateRootHash(logksi->tree, (KSI_DataHash**)&context.documentHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get root hash for verification.", logksi->blockNo);

	context.docAggrLevel = LOGKSI_get_aggregation_level(logksi);

	if (processors->verify_signature) {

		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_EMPTY, NULL, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", logksi->blockNo);

		/* Verify KSI signature. */
		res = processors->verify_signature(set, mp, err, ksi, logksi, files, sig, (KSI_DataHash*)context.documentHash, context.docAggrLevel, &verificationResult);
		if (res != KSI_OK) {
			logksi->file.nofTotalFailedBlocks++;
			logksi->quietError = res;

			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Verification of block %zu KSI signature %s!\n", logksi->blockNo, error_level_to_string(logksi));
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Verification of KSI signature %s!\n", logksi->blockNo), error_level_to_string(logksi);


			if (!logksi->isContinuedOnFail || logksi->taskId != TASK_VERIFY) {
				ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: KSI signature verification failed.", logksi->blockNo);
			}

			goto cleanup;
		}

		/* TODO: add dumping of verification results. */
		KSI_PolicyVerificationResult_free(verificationResult);
		verificationResult = NULL;

	} else if (processors->extend_signature) {
		time_t t = 0;

		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", logksi->blockNo);

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

		res = processors->extend_signature(set, mp, err, ksi, logksi, files, sig, pubFile, &context, &ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extend KSI signature.", logksi->blockNo);

		res = KSI_Signature_getPublicationInfo(ext, NULL, NULL, &t, NULL, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get publication time from KSI signature.", logksi->blockNo);

		logksi->task.extend.extendedToTime = t;

		res = tlv_element_set_signature(tlv, ksi, 0x905, ext);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize extended KSI signature.", logksi->blockNo);

		res = KSI_TlvElement_serialize(tlv, logksi->ftlv_raw, SOF_FTLV_BUFFER, &logksi->ftlv_len, 0);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to serialize extended block signature.", logksi->blockNo);

		if (logksi->file.warningLegacy) {
			int convertLegacy = PARAM_SET_isSetByName(set, "enable-rfc3161-conversion");

			if (files->internal.bOverwrite && !convertLegacy) {
				res = KT_RFC3161_EXT_IMPOSSIBLE;
				ERR_CATCH_MSG(err, res, "Error: Overwriting of legacy log signature file not enabled. Run 'logksi extend' with '--enable-rfc3161-conversion' to convert RFC3161 timestamps to KSI signatures.");
			}
			logksi->file.warningLegacy = 0;
		}

		res = SMART_FILE_write(files->files.outSig, logksi->ftlv_raw, logksi->ftlv_len, NULL);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to write extended signature to extended log signature file.", logksi->blockNo);

		KSI_DataHash_free((KSI_DataHash*)context.documentHash);
		context.documentHash = NULL;
		KSI_VerificationContext_clean(&context);
	} else if (processors->extract_signature) {
		size_t j = 0;

		res = LOGKSI_Signature_parseWithPolicy(err, ksi, tlvSig->ptr + tlvSig->ftlv.hdr_len, tlvSig->ftlv.dat_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature.", logksi->blockNo);

		if (!PARAM_SET_isSetByName(set, "ksig") && EXTRACT_INFO_getPositionsInBlock(logksi->task.extract.info)) {
			res = SMART_FILE_write(files->files.outProof, tlvSig->ptr, tlvSig->ftlv.dat_len + tlvSig->ftlv.hdr_len, NULL);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to write KSI signature to integrity proof file.", logksi->blockNo);
		}

		for (j = 0; j < EXTRACT_INFO_getPositionsInBlock(logksi->task.extract.info); j++) {
			RECORD_INFO *record = NULL;
			size_t lineNumber = 0;
			char *logLine = NULL;

			res = EXTRACT_INFO_getRecord(logksi->task.extract.info, j, &record);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get extract record.", logksi->blockNo);

			res = RECORD_INFO_getLine(record, &lineNumber, &logLine);
			ERR_CATCH_MSG(err, res, "Error: Unable to get record line information.");

			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, res);
			print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: extracting log records (line %3zu)... ", logksi->blockNo, lineNumber);
			print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extracting log record from block %3zu (line %3zu)... ", logksi->blockNo, lineNumber);

			if (PARAM_SET_isSetByName(set, "ksig")) {
				KSI_Signature *ksiSig = NULL;

				if (logksi->file.warningLegacy) {
					ERR_TRCKR_ADD(err, res = KT_INVALID_INPUT_FORMAT, "Error: It is not possible to extract pure KSI signature from RFC3161 timestamp.");
					goto cleanup;
				}

				res = extract_ksi_signature(ksi, record, sig, &ksiSig);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to construct KSI signature for log line %zu.", logksi->blockNo, lineNumber);

				res = store_ksi_signature_and_log_line(set, err, logksi, files, logLine, lineNumber, ksiSig);
				KSI_Signature_free(ksiSig);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to store logline %zu and corresponding KSI signature.", logksi->blockNo, lineNumber);
			} else {
				res = store_integrity_proof_and_log_records(set, err, ksi, record, files);
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to store integrity proof file and extracted log line.", logksi->blockNo);
			}
		}

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_3, res);
	}

	{
		KSI_Integer *t1 = NULL;
		char sigTimeStr[256] = "<null>";
		res = KSI_Signature_getSigningTime(sig, &t1);
		ERR_CATCH_MSG(err, res, NULL);

		logksi->block.sigTime_1 = KSI_Integer_getUInt64(t1);

		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: signing time: (%llu) %s\n", logksi->blockNo, logksi->block.sigTime_1, LOGKSI_signature_sigTimeToString(sig, sigTimeStr, sizeof(sigTimeStr)));
	}

	/* Verify KSI signatures Client ID. */
	res = check_log_signature_client_id(set, mp, err, logksi, sig);
	if (res != KT_OK) goto cleanup;

	res = check_log_record_embedded_time_against_ksi_signature_time(set, mp, err, logksi);
	if (res != KT_OK) goto cleanup;

	logksi->task.verify.lastBlockWasSkipped = 0;
	res = KT_OK;

cleanup:
	if (processors->extract_signature) print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_DataHash_free((KSI_DataHash*)context.documentHash);
	KSI_DataHash_free(hash);
	KSI_VerificationContext_clean(&context);
	KSI_PolicyVerificationResult_free(verificationResult);
	KSI_TlvElement_free(tlvSig);
	KSI_TlvElement_free(tlvUnsig);
	KSI_TlvElement_free(tlvRfc3161);
	KSI_TlvElement_free(tlv);
	KSI_Integer_free(t0);
	return res;
}

static int process_hash_step(ERR_TRCKR *err, KSI_CTX *ksi, KSI_TlvElement *tlv, LOGKSI *logksi, KSI_DataHash *inputHash, unsigned char *chainHeight, KSI_DataHash **outputHash) {
	int res;
	size_t correction = 0;
	KSI_DataHash *siblingHash = NULL;
	KSI_DataHash *tmp = NULL;

	if (tlv == NULL || logksi == NULL || inputHash == NULL || chainHeight == NULL || outputHash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = tlv_element_get_uint(tlv, ksi, 0x01, &correction);
	if (res == KT_INVALID_INPUT_FORMAT) {
		correction = 0;
		res = KT_OK;
	}
	if (res != KT_OK) goto cleanup;
	res = tlv_element_get_hash(err, tlv, ksi, 0x02, &siblingHash);
	if (res != KT_OK) goto cleanup;

	*chainHeight = *chainHeight + correction + 1;

	if (tlv->ftlv.tag == 0x02) {
		res = MERKLE_TREE_calculateTreeHash(logksi->tree, inputHash, siblingHash, *chainHeight, &tmp);
	} else if (tlv->ftlv.tag == 0x03){
		res = MERKLE_TREE_calculateTreeHash(logksi->tree, siblingHash, inputHash, *chainHeight, &tmp);
	} else {
		res = KT_INVALID_INPUT_FORMAT;
	}
	if (res != KT_OK) goto cleanup;

	*outputHash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(siblingHash);
	KSI_DataHash_free(tmp);
	return res;
}

static int process_log_signature_general_components_(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, int withBlockSignature, LOGKSI *logksi, IO_FILES *files, SIGNATURE_PROCESSORS *processors) {
	int res = KT_UNKNOWN_ERROR;
	int printHeader = 0;
	int isFinal = 0;

	if (set == NULL || err == NULL || ksi == NULL || logksi == NULL || files == NULL || (withBlockSignature && processors == NULL)) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	printHeader = MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);

	switch (logksi->ftlv.tag) {
		case 0x901:
			res = finalize_block(set, mp, err, logksi, files, ksi);
			if (res != KT_OK) goto cleanup;

			res = LOGKSI_initNextBlock(logksi);
			if (res != KT_OK) goto cleanup;

			res = process_block_header(set, mp, err, ksi, logksi, files);
			if (res != KT_OK) goto cleanup;
		break;

		case 0x902:
			if (printHeader == 0) print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "Block no. %3zu: {", logksi->blockNo);
			print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "r" );

			res = process_record_hash(set, mp,err, ksi, logksi, files);
			if (res != KT_OK) goto cleanup;
		break;

		case 0x903:
			if (printHeader == 0) print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "Block no. %3zu: {", logksi->blockNo);


			res = process_tree_hash(set, mp, err, ksi, logksi, files, &isFinal);

			if (isFinal) {
				print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, ":");
			} else {
				print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, ".");
			}

			if (res != KT_OK) goto cleanup;
		break;

		case 0x911:
			if (printHeader == 0) print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "Block no. %3zu: {", logksi->blockNo);
			print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "M");

			res = process_metarecord(set, mp, err, ksi, logksi, files);
			if (res != KT_OK) goto cleanup;
		break;

		default:
			if (withBlockSignature && logksi->ftlv.tag) {
				res = process_block_signature(set, mp, err, ksi, pubFile, processors, logksi, files);
				if (res != KT_OK) goto cleanup;
			} else {
				res = KT_INVALID_INPUT_FORMAT;
				goto cleanup;
			}
		break;
	}

	res = KT_OK;

cleanup:

	if (res != KT_OK) {
		if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
			print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, " X\n");
			MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
			MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
		}
	}

	return res;
}

static int block_info_store_logline(LOGKSI *logksi, char *buf) {
	int res;
	char *tmp = NULL;

	if (logksi == NULL || buf == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (char*)malloc(strlen(buf) + 1);
	if (tmp == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	strncpy(tmp, buf, strlen(buf) + 1);
	free(logksi->logLine);
	logksi->logLine = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:

	free(tmp);
	return res;
}

static int logksi_calculate_hash_of_logline_and_store_logline(LOGKSI *logksi, IO_FILES *files, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;
	KSI_DataHasher *pHasher = NULL;
	/* Maximum line size is 64K characters, without newline character. */
	char buf[0x10000 + 2];

	if (files == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = MERKLE_TREE_getHasher(logksi->tree, &pHasher);
	if (res != KSI_OK) goto cleanup;

	if (files->files.inLog) {
		res = SMART_FILE_gets(files->files.inLog, buf, sizeof(buf), NULL);
		if (res != SMART_FILE_OK) goto cleanup;

		res = KSI_DataHasher_reset(pHasher);
		if (res != KSI_OK) goto cleanup;

		/* Last character (newline) is not used in hash calculation. */
		res = KSI_DataHasher_add(pHasher, buf, strlen(buf) - 1);
		if (res != KSI_OK) goto cleanup;

		res = KSI_DataHasher_close(pHasher, &tmp);
		if (res != KSI_OK) goto cleanup;

		/* Store logline for extraction. */
		res = block_info_store_logline(logksi, buf);
		if (res != KT_OK) goto cleanup;
	}
	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

static int block_info_calculate_hash_of_logline_and_store_logline_check_log_time(PARAM_SET* set, ERR_TRCKR *err, MULTI_PRINTER *mp, LOGKSI *logksi, IO_FILES *files, KSI_DataHash **hash) {
	int res = KT_UNKNOWN_ERROR;

	if (set == NULL || err == NULL || mp == NULL || logksi == NULL || files == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = logksi_calculate_hash_of_logline_and_store_logline(logksi, files, hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate hash of logline no. %zu.", logksi->blockNo, LOGKSI_getNofLines(logksi));

	res = check_log_line_embedded_time(set, mp, err, logksi);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: embedded time check failed for logline no. %zu.", logksi->blockNo, LOGKSI_getNofLines(logksi));


	res = KT_OK;

cleanup:

	return res;
}

static int block_info_store_metarecord(LOGKSI *logksi, KSI_TlvElement *tlv) {
	int res;
	size_t len = 0;
	unsigned char *buf = NULL;

	if (logksi == NULL || tlv == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_serialize(tlv, NULL, 0, &len, 0);
	if (res != KSI_OK) goto cleanup;

	buf = (unsigned char*)malloc(len);
	if (buf == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = KSI_TlvElement_serialize(tlv, buf, len, &len, 0);
	if (res != KSI_OK) goto cleanup;

	free(logksi->task.extract.metaRecord);
	logksi->task.extract.metaRecord = buf;
	logksi->task.extract.metaRecord_len = len;
	buf = NULL;

	res = KT_OK;

cleanup:

	free(buf);
	return res;
}

static int logksi_calculate_hash_of_metarecord_and_store_metarecord(LOGKSI *logksi, KSI_TlvElement *tlv, KSI_DataHash **hash) {
	int res;
	KSI_DataHash *tmp = NULL;
	KSI_DataHasher *pHasher = NULL;

	if (tlv == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = MERKLE_TREE_getHasher(logksi->tree, &pHasher);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHasher_reset(pHasher);
	if (res != KSI_OK) goto cleanup;

	/* The complete metarecord TLV us used in hash calculation. */
	res = KSI_DataHasher_add(pHasher, tlv->ptr, tlv->ftlv.hdr_len + tlv->ftlv.dat_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHasher_close(pHasher, &tmp);
	if (res != KSI_OK) goto cleanup;

	/* Store metarecord for extraction. */
	res = block_info_store_metarecord(logksi, tlv);
	if (res != KT_OK) goto cleanup;

	*hash = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_DataHash_free(tmp);
	return res;
}

static int logksi_add_record_hash_to_merkle_tree(LOGKSI *logksi, int isMetaRecordHash, KSI_DataHash *hash) {
	if (logksi == NULL) {
		return KT_INVALID_ARGUMENT;
	}

	if (isMetaRecordHash) {
		logksi->file.nofTotalMetarecords++;
		logksi->block.nofMetaRecords++;
		logksi->file.nofTotalRecordHashes--;
	}

	return MERKLE_TREE_addRecordHash(logksi->tree, isMetaRecordHash, hash);
}