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
#include <ksi/tlv_element.h>
#include <gtrfc3161/tsconvert.h>
#include <ctype.h>
#include "param_set/param_set.h"
#include "param_set/strn.h"
#include "err_trckr.h"
#include "logksi_err.h"
#include "api_wrapper.h"
#include "printer.h"
#include "debug_print.h"
#include "tlv_object.h"
#include "extract_info.h"
#include "io_files.h"
#include "logksi.h"
#include "rsyslog.h"
#include "param_control.h"
#include <time.h>
#include <ksi/signature_builder.h>
#include "check.h"

const char *io_files_getCurrentLogFilePrintRepresentation(IO_FILES *files);


#define SOF_ARRAY(x) (sizeof(x) / sizeof((x)[0]))

typedef struct {
	VERIFYING_FUNCTION verify_signature;
	EXTENDING_FUNCTION extend_signature;
	SIGNING_FUNCTION create_signature;
	int extract_signature;
} SIGNATURE_PROCESSORS;


static size_t max_tree_hashes(size_t nof_records) {
	size_t max = 0;
	while (nof_records) {
		max = max + nof_records;
		nof_records = nof_records / 2;
	}
	return max;
}

static int block_info_calculate_hash_of_logline_and_store_logline_check_log_time(PARAM_SET* set, ERR_TRCKR *err, MULTI_PRINTER *mp, LOGKSI *logksi, IO_FILES *files, KSI_DataHash **hash) {
	int res = KT_UNKNOWN_ERROR;

	if (set == NULL || err == NULL || mp == NULL || logksi == NULL || files == NULL || hash == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = LOGKSI_calculate_hash_of_logline_and_store_logline(logksi, files, hash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate hash of logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));

	res = check_log_line_embedded_time(set, mp, err, logksi);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: embedded time check failed for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));


	res = KT_OK;

cleanup:

	return res;
}

static int logksi_datahash_compare(ERR_TRCKR *err, MULTI_PRINTER *mp, LOGKSI* logksi, int isLogline, KSI_DataHash *left, KSI_DataHash *right, const char * reason, const char *helpLeft_raw, const char *helpRight_raw) {
	int res;
	KSI_HashAlgorithm leftId;
	KSI_HashAlgorithm rightId;
	char buf[1024];
	const char *failureReason = NULL;
	int differentHashAlg = 0;

	if (mp == NULL || logksi == NULL || left == NULL || right == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	failureReason = (reason == NULL) ? "Hash values do not match" : reason;

	if (!KSI_DataHash_equals(left, right)) {
		const char *helpLeft = NULL;
		const char *helpRight = NULL;
		size_t minSize = 0;

		res = KT_VERIFICATION_FAILURE;
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
		differentHashAlg = KSI_DataHash_getHashAlg(left, &leftId) == KSI_OK && KSI_DataHash_getHashAlg(right, &rightId) == KSI_OK && leftId != rightId;

		helpLeft = helpLeft_raw == NULL ? "Computed hash:" : helpLeft_raw;
		helpRight = helpRight_raw == NULL ? "Stored hash:" : helpRight_raw;
		minSize = strlen(helpLeft);
		minSize = strlen(helpRight) > minSize ? strlen(helpRight) : minSize;

		if (isLogline) {
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Failed to verify logline no. %zu:\n"
																				  "   + Logline:\n"
																				  "     '%.*s'\n", logksi_get_nof_lines(logksi), (strlen(logksi->logLine) - 1), logksi->logLine);
			if (differentHashAlg) print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Hash algorithms differ!%s\n");
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + %s\n"
																				  "     %s\n", helpLeft, LOGKSI_DataHash_toString(left, buf, sizeof(buf)));
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + %s\n"
																				  "     %s\n", helpRight, LOGKSI_DataHash_toString(right, buf, sizeof(buf)));


			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: failed to verify logline no. %zu: %s", logksi->blockNo, logksi_get_nof_lines(logksi), logksi->logLine);
		} else {
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: %s:\n", failureReason);
			if (differentHashAlg) print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Hash algorithms differ!%s\n");
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + %s\n"
																				  "     %s\n", helpLeft, LOGKSI_DataHash_toString(left, buf, sizeof(buf)));
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + %s\n"
																				  "     %s\n", helpRight, LOGKSI_DataHash_toString(right, buf, sizeof(buf)));
		}

		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %s\n", logksi->blockNo, failureReason);
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Hash algorithms differ\n", logksi->blockNo);
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %-*s %s\n", logksi->blockNo, minSize, helpLeft, LOGKSI_DataHash_toString(left, buf, sizeof(buf)));
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %-*s %s\n", logksi->blockNo, minSize, helpRight, LOGKSI_DataHash_toString(right, buf, sizeof(buf)));

		goto cleanup;
	}

	res = KT_OK;

cleanup:

	return res;
}

struct magic_reference_st {
	const char* name;
	LOGSIG_VERSION ver;
};

#define _LGVR(v) {#v, v}
struct magic_reference_st magic_reference[NOF_VERS] = {_LGVR(LOGSIG11), _LGVR(LOGSIG12), _LGVR(RECSIG11), _LGVR(RECSIG12), _LGVR(LOG12BLK), _LGVR(LOG12SIG)};
#undef _LGVR

static LOGSIG_VERSION file_version_by_string(const char *str) {
	int i = 0;
	if (str == NULL) return UNKN_VER;

	for (i = 0; i < NOF_VERS; i++) {
		if (strcmp(str, magic_reference[i].name) == 0) return magic_reference[i].ver;
	}

	return UNKN_VER;
}

static const char* file_version_to_string(LOGSIG_VERSION ver) {
	int i = 0;

	for (i = 0; i < NOF_VERS; i++) {
		if (magic_reference[i].ver == ver) return magic_reference[i].name;
	}

	return "<unknown file version>";
}

/**
 * Extracts file type by reading its magic bytes.
 * \param in		#SMART_FILE object wherefrom the magic bytes are read.
 * \return File version (#LOGSIG_VERSION) if successful or #UNKN_VER otherwise.
 */
static LOGSIG_VERSION get_file_version(SMART_FILE *in) {
	int res = KT_UNKNOWN_ERROR;
	char magic_from_file[MAGIC_SIZE + 1];
	size_t count = 0xff;

	if (in == NULL)	return UNKN_VER;

	res = SMART_FILE_read(in, (unsigned char*)magic_from_file, MAGIC_SIZE, &count);
	if (res != SMART_FILE_OK || count != MAGIC_SIZE) return UNKN_VER;

	magic_from_file[MAGIC_SIZE] = '\0';
	return file_version_by_string(magic_from_file);
}

static LOGSIG_VERSION get_integrity_proof_version(LOGSIG_VERSION ver) {
	switch(ver) {
		case LOGSIG11: return RECSIG11;
		case LOGSIG12: return RECSIG12;
		default: return UNKN_VER;
	}
}

static int check_file_header(SMART_FILE *in, ERR_TRCKR *err, LOGSIG_VERSION *expected_ver, size_t expected_ver_count, const char *human_readable_file_name, LOGSIG_VERSION *ver_out) {
	int res = KT_UNKNOWN_ERROR;
	LOGSIG_VERSION ver = UNKN_VER;
	char permitted_versions[1024] = "<unexpected>";
	int i = 0;
	size_t count = 0;

	if (in == NULL || err == NULL) return KT_INVALID_ARGUMENT;

	/* Get the actual version. */
	ver = get_file_version(in);
	if (ver_out != NULL) *ver_out = ver;

	/* Check if any of the file types matches. In case of success return with OK */
	for (i = 0; i < expected_ver_count; i++) {
		if (expected_ver[i] == ver) return KT_OK;
		count += PST_snprintf(permitted_versions + count, sizeof(permitted_versions) - count, "%s%s", (i > 0 ? ", " : ""), file_version_to_string(expected_ver[i]));
	}

    /* Format error messages.*/
	res = KT_INVALID_INPUT_FORMAT;
	if (expected_ver_count > 1) ERR_TRCKR_ADD(err, res, "Error: Expected file types {%s} but got %s!", permitted_versions, file_version_to_string(ver));
	else ERR_TRCKR_ADD(err, res, "Error: Expected file type %s but got %s!", permitted_versions, file_version_to_string(ver));
	ERR_TRCKR_ADD(err, res, "Error: Log signature file identification magic number not found.");
	ERR_TRCKR_ADD(err, res, "Error: Unable to parse %s file '%s'.", human_readable_file_name, SMART_FILE_getFname(in));

	return res;
}

static int process_magic_number(PARAM_SET* set, MULTI_PRINTER* mp, ERR_TRCKR *err, LOGKSI *logksi, IO_FILES *files) {
	int res;
	SMART_FILE *in = NULL;

	if (err == NULL || files == NULL) {
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
		res = SMART_FILE_write(files->files.outSig, (unsigned char*)file_version_to_string(logksi->file.version), MAGIC_SIZE, NULL);
		ERR_CATCH_MSG(err, res, "Error: Could not copy magic number to log signature file.");
	} else if (files->files.outProof) {
		res = SMART_FILE_write(files->files.outProof, (unsigned char*)file_version_to_string(get_integrity_proof_version(logksi->file.version)), MAGIC_SIZE, NULL);
		ERR_CATCH_MSG(err, res, "Error: Could not write magic number to integrity proof file.");
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	return res;
}

static int continue_on_hash_fail(int result, PARAM_SET *set, MULTI_PRINTER* mp, LOGKSI *logksi, KSI_DataHash *computed, KSI_DataHash *stored, KSI_DataHash **replacement) {
	int res = result;

	if (set == NULL || logksi == NULL || computed == NULL || stored == NULL || replacement == NULL) {
		goto cleanup;
	}

	if (res == KT_OK) {
		*replacement = KSI_DataHash_ref(computed);
	} else {
		logksi->file.nofTotaHashFails++;
		logksi->block.nofHashFails++;
		if (PARAM_SET_isSetByName(set, "use-computed-hash-on-fail")) {
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Using computed hash to continue.\n");
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Using computed hash to continue.\n", logksi->blockNo);
			*replacement = KSI_DataHash_ref(computed);
			res = KT_OK;
		} else if (PARAM_SET_isSetByName(set, "use-stored-hash-on-fail")) {
			*replacement = KSI_DataHash_ref(stored);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "   + Using stored hash to continue.\n");
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Using stored hash to continue.\n", logksi->blockNo);
			res = KT_OK;
		} else {
			*replacement = KSI_DataHash_ref(computed);
		}
	}

cleanup:

	return res;
}


#define SIZE_OF_SHORT_INDENTENTION 13
#define SIZE_OF_LONG_INDENTATION 29

static int finalize_block(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files) {
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

	res = handle_record_time_check_between_files(set, mp, err, logksi, files);
	if (res != KT_OK) goto cleanup;

	if ((logksi->file.recTimeMin == 0 || logksi->file.recTimeMin > logksi->block.recTimeMin) && logksi->block.recTimeMin > 0) logksi->file.recTimeMin = logksi->block.recTimeMin;
	if (logksi->file.recTimeMax == 0 || logksi->file.recTimeMax < logksi->block.recTimeMax) logksi->file.recTimeMax = logksi->block.recTimeMax;

	res = handle_block_signing_time_check(set, mp, err, logksi, files);
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

/* Called right before process_block_header. */
static int init_next_block(LOGKSI *logksi) {
	if (logksi == NULL) return KT_INVALID_ARGUMENT;

	logksi->blockNo++;

	/* Previous and current (next) signature time. Note that 0 indicates not set. */
	if (logksi->block.sigTime_1 > 0 || logksi->block.curBlockNotSigned) {
		logksi->sigTime_0 = logksi->block.sigTime_1;
		logksi->block.sigTime_1 = 0;
	}

	LOGKSI_resetBlockInfo(logksi);

	logksi->block.firstLineNo = logksi->file.nofTotalRecordHashes + 1;

	return KT_OK;
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

static int is_record_hash_expected(ERR_TRCKR *err, LOGKSI *logksi) {
	int res;

	if (err == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Check if record hash is received between block header and block signature. */
	if (logksi->blockNo == logksi->sigNo) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash without preceding block header found.", logksi->blockNo + 1);
	}
	/* Check if record hashes are present for previous records. */
	if (logksi->block.keepRecordHashes == 0 && logksi->block.nofRecordHashes > 0) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));
	}
	/* Check if all tree hashes are present for previous records. */
	if (logksi->block.keepTreeHashes && logksi->block.nofTreeHashes != max_tree_hashes(logksi->block.nofRecordHashes)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash(es) for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));
	}

	res = KT_OK;

cleanup:

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


	res = is_record_hash_expected(err, logksi);
	if (res != KT_OK) goto cleanup;

	logksi->block.keepRecordHashes = 1;
	logksi->block.nofRecordHashes++;

	res = LOGKSI_DataHash_fromImprint(err, ksi, logksi->ftlv_raw + logksi->ftlv.hdr_len, logksi->ftlv.dat_len, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse hash of logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));

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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash no. %zu does not have a matching logline, end of logfile reached.", logksi->blockNo, logksi_get_nof_lines(logksi));
			} else if (res != KT_OK) goto cleanup;

			res = logksi_datahash_compare(err, mp, logksi, 1, hash, recordHash, NULL, "Record hash computed from logline:", "Record hash stored in log signature file:");
			res = continue_on_hash_fail(res, set, mp, logksi, hash, recordHash, &replacement);
			if (!logksi->isContinuedOnFail || logksi->taskId != TASK_VERIFY) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hashes not equal for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));
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

static int max_final_hashes(LOGKSI *logksi) {
	int finalHashes = 0;
	int i;
	if (logksi) {
		for (i = 0; i < MERKLE_TREE_getHeight(logksi->tree); i++) {
			KSI_DataHash *hsh = NULL;
			int res = KT_UNKNOWN_ERROR;

			res = MERKLE_TREE_get(logksi->tree, i, &hsh);
			if (res != KT_OK) return finalHashes;

			if (hsh != NULL) {
				finalHashes++;
			}

			KSI_DataHash_free(hsh);
		}
		finalHashes--;
	}
	return finalHashes;
}

static int is_tree_hash_expected(ERR_TRCKR *err, LOGKSI *logksi) {
	int res;

	if (err == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	/* Check if tree hash is received between block header and block signature. */
	if (logksi->blockNo == logksi->sigNo) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hash without preceding block header found.", logksi->blockNo + 1);
	}
	/* Check if tree hashes are present for previous records. */
	if (logksi->block.keepTreeHashes == 0 && logksi->block.nofRecordHashes > 1) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi) - 1);
	}
	/* Check if all record hashes are present for previous records. */
	if (logksi->block.keepRecordHashes && logksi->block.nofTreeHashes == max_tree_hashes(logksi->block.nofRecordHashes)) {
		/* All the tree hashes that can be computed from the received record hashes have been received.
		 * However, another tree hash was just received, so either the preceding record hash is missing or
		 * the tree hash is used in finalizing the unbalanced tree. */
		if (MERKLE_TREE_isBalenced(logksi->tree)) {
			/* The tree is balanced, so no finalizing is needed. Thus the tree hash is unexpected, probably due to a missing record hash. */
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi) + 1);
		} else if (logksi->block.metarecordHash) {
			/* A metarecord hash is missing while the tree hash for the metarecord is present. */
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for metarecord with index %zu.", logksi->blockNo, logksi->block.nofRecordHashes);
		} else {
			/* Assuming that no record hashes are missing, let's start the finalizing process. */
			logksi->block.finalTreeHashesSome = 1;
			/* Prepare tree hashes for verification of finalizing. */

			res = MERKLE_TREE_setFinalHashesForVerification(logksi->tree);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to get tree hash for verification.", logksi->blockNo);
		}
	}

	/* Check if all final tree hashes are present. */
	if (logksi->block.finalTreeHashesSome && logksi->block.nofTreeHashes == max_tree_hashes(logksi->block.nofRecordHashes) + max_final_hashes(logksi)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected final tree hash no. %zu.", logksi->blockNo, logksi->block.nofTreeHashes + 1);
	}

	res = KT_OK;

cleanup:

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
	unsigned char i;

	if (err == NULL || files == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = is_tree_hash_expected(err, logksi);
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
		if (logksi->block.keepRecordHashes == 0 && logksi->block.nofTreeHashes > max_tree_hashes(logksi->block.nofRecordHashes)) {
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

					KSI_DataHash_free(logksi->block.metarecordHash);
					logksi->block.metarecordHash = NULL;
				} else {
					res = block_info_calculate_hash_of_logline_and_store_logline_check_log_time(set, err, mp, logksi, files, &recordHash);
					if (res == KT_IO_ERROR) {
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hash does not have a matching logline no. %zu, end of logfile reached.", logksi->blockNo, logksi_get_nof_lines(logksi));
					} else if (res != KT_OK) goto cleanup;

					res = logksi_add_record_hash_to_merkle_tree(logksi, 0, recordHash);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add record hash to Merkle tree.", logksi->blockNo);

					KSI_DataHash_free(recordHash);
					recordHash = NULL;
				}
			} else {
				/* No log file available so build the Merkle tree from tree hashes alone. */
				res = MERKLE_TREE_add_leaf_hash_to_merkle_tree(logksi->tree, treeHash, 0);
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected tree hash for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));
			}

			res = logksi_datahash_compare(err, mp, logksi, 0, unverified, treeHash, description, "Tree hash computed from record hashes:", "Tree hash stored in log signature file:");
			res = continue_on_hash_fail(res, set, mp, logksi, unverified, treeHash, &replacement);
			if (!logksi->isContinuedOnFail || logksi->taskId != TASK_VERIFY) {
				if (logksi->block.keepRecordHashes) {
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));
				}

				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal.", logksi->blockNo);
			}

			if (res != KT_OK) goto cleanup;

			KSI_DataHash_free(unverified);
			unverified = NULL;
		}
		if (logksi->block.finalTreeHashesLeaf && !MERKLE_TREE_nof_unverified_hashes(logksi->tree)) {
			/* This was the last mandatory tree hash. From this point forward all tree hashes must be interpreted as optional final tree hashes. */
			logksi->block.finalTreeHashesSome = 1;

			res = MERKLE_TREE_setFinalHashesForVerification(logksi->tree);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to get tree hash for verification.", logksi->blockNo);
		}
	} else {
		if (logksi->block.nofRecordHashes) {
			KSI_DataHash *tmp = NULL;
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

			res = MERKLE_TREE_calculate_new_tree_hash(logksi->tree, tmp, root, i + 2, &tmpRoot);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable pop unverified root tree node.", logksi->blockNo);

			res = MERKLE_TREE_insertUnverified(logksi->tree, i, tmpRoot);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: Unable to insert unverified root tree node.", logksi->blockNo);

			if (i == MERKLE_TREE_getHeight(logksi->tree)) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unexpected tree hash for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));
			}

			res = logksi_datahash_compare(err, mp, logksi, 0, tmpRoot, treeHash, description, "Tree hash computed from record hashes:", "Tree hash stored in log signature file:");
			res = continue_on_hash_fail(res, set, mp, logksi, tmpRoot, treeHash, &replacement);
			if (!logksi->isContinuedOnFail || logksi->taskId != TASK_VERIFY) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: tree hashes not equal for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));
			}

			if (res != KT_OK) goto cleanup;
		}
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
	KSI_DataHash_free(unverified);
	KSI_DataHash_free(treeHash);
	KSI_DataHash_free(recordHash);
	KSI_DataHash_free(tmpRoot);
	KSI_DataHash_free(root);
	KSI_DataHash_free(replacement);
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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: at least %zu loglines expected up to metarecord index %zu, end of logfile reached.", logksi->blockNo, logksi_get_nof_lines(logksi), metarecord_index);
			} else if (res != KT_OK) goto cleanup;

			res = logksi_add_record_hash_to_merkle_tree(logksi, 0, hash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to add metarecord hash to Merkle tree.", logksi->blockNo);

			KSI_DataHash_free(hash);
			hash = NULL;
		}
	}

	KSI_DataHash_free(logksi->block.metarecordHash);
	logksi->block.metarecordHash = NULL;
	res = LOGKSI_calculate_hash_of_metarecord_and_store_metarecord(logksi, tlv, &logksi->block.metarecordHash);
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

static int is_block_signature_expected(ERR_TRCKR *err, LOGKSI *logksi) {
	int res;
	size_t maxTreeHashes;
	size_t maxFinalHashes;

	if (err == NULL || logksi == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	maxTreeHashes = max_tree_hashes(logksi->block.recordCount);
	maxFinalHashes = max_final_hashes(logksi);

	if (logksi->block.keepRecordHashes) {
		/* Check if record hash is present for the most recent metarecord (if any). */
		if (logksi->block.metarecordHash) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for metarecord with index %zu.", logksi->blockNo, logksi->block.nofRecordHashes);
		}

		/* Check if all record hashes are present in the current block. */
		if (logksi->block.nofRecordHashes < logksi->block.recordCount) {
			res = KT_VERIFICATION_FAILURE;

			ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: expected %zu record hashes, but found %zu.", logksi->blockNo, logksi->block.recordCount, logksi->block.nofRecordHashes);
			ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: there are too few record hashes for this block.", logksi->blockNo);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record hash for logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi) + 1);
		}

		if (logksi->block.nofRecordHashes > logksi->block.recordCount) {
			res = KT_VERIFICATION_FAILURE;

			ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: expected %zu record hashes, but found %zu.", logksi->blockNo, logksi->block.recordCount, logksi->block.nofRecordHashes);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: there are too many record hashes for this block.", logksi->blockNo);
		}
	}

	if (logksi->block.keepTreeHashes) {
		if (!logksi->block.keepRecordHashes && !MERKLE_TREE_isBalenced(logksi->tree) && !logksi->block.finalTreeHashesSome) {
			/* If LOGSIG12 format is used, metarecords are mandatory for closing unbalanced blocks. */
			if (logksi->file.version == LOGSIG12) {
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete block is closed without a metarecord.", logksi->blockNo);
			}
		}
		/* Check if all mandatory tree hashes are present in the current block. */
		if (logksi->block.nofTreeHashes < maxTreeHashes) {
			res = KT_VERIFICATION_FAILURE;

			if (logksi->block.nofMetaRecords > 0) {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash(es) for metarecord with index %zu.", logksi->blockNo, logksi->block.nofRecordHashes - 1);
			} else {
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing tree hash(es) for logline no. %zu.", logksi->blockNo, logksi->block.recordCount + logksi->file.nofTotalRecordHashes);
			}
		}
		/* Check if the block contains too few final tree hashes. */
		if (logksi->block.nofTreeHashes < maxTreeHashes + maxFinalHashes) {
			/* Check if none of the final tree hashes have yet been received. (Final tree hashes must all be present or all missing.) */
			if (logksi->block.nofTreeHashes == maxTreeHashes) {
				/* Check if there is reason to expect final tree hashes. */
				if (logksi->block.finalTreeHashesSome || logksi->block.keepRecordHashes) {
					/* All final tree hashes are missing, but at least they are being expected -> this is OK and can be repaired. */
					logksi->block.finalTreeHashesNone = 1;
				} else {
					/* If LOGSIG12 format is used, metarecords are mandatory for closing unbalanced blocks. */
					if (logksi->file.version == LOGSIG12) {
						/* All of the final tree hashes are missing, but they are not being expected either (e.g. missing metarecord). This should never happen. */
						res = KT_VERIFICATION_FAILURE;
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: all final tree hashes are missing and block is closed without a metarecord.", logksi->blockNo);
					}
				}
			} else {
				/* If some final tree hashes are present, they must all be present. */
				res = KT_VERIFICATION_FAILURE;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: found %zu final tree hashes instead of %zu.", logksi->blockNo, logksi->block.nofTreeHashes - maxTreeHashes, maxFinalHashes);
			}
		}
		/* Check if the block contains too many optional tree hashes. */
		if (logksi->block.nofTreeHashes > maxTreeHashes + maxFinalHashes) {
			res = KT_VERIFICATION_FAILURE;
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: found %zu final tree hashes instead of %zu.", logksi->blockNo, logksi->block.nofTreeHashes - maxTreeHashes, maxFinalHashes);
		}
		if (logksi->block.nofTreeHashes == maxTreeHashes + maxFinalHashes) {
			logksi->block.finalTreeHashesAll = 1;
		}
	}

	res = KT_OK;

cleanup:

	return res;
}

static int extract_ksi_signature(KSI_CTX *ctx, LOGKSI *logksi, RECORD_INFO *record, const KSI_Signature *sig, KSI_Signature **out) {
	int res = KT_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	KSI_SignatureBuilder *builder = NULL;
	KSI_AggregationHashChain *aggrChain = NULL;

	if (ctx == NULL || logksi == NULL || record == NULL || sig == NULL || out == NULL) {
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

	/* Construct hash chain for one log record	. */
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
		res = KT_VERIFICATION_FAILURE;
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


	res = is_block_signature_expected(err, logksi);
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
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: at least %zu loglines expected, end of logfile reached.", logksi->blockNo, logksi_get_nof_lines(logksi));
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

	res = MERKLE_TREE_calculate_root_hash(logksi->tree, (KSI_DataHash**)&context.documentHash);
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
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Verification of block %zu KSI signature failed!\n", logksi->blockNo);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Verification of KSI signature failed!\n", logksi->blockNo);

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

				res = extract_ksi_signature(ksi, logksi, record, sig, &ksiSig);
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

static int process_ksi_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, LOGKSI *logksi, IO_FILES *files) {
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
		res = MERKLE_TREE_calculate_new_tree_hash(logksi->tree, inputHash, siblingHash, *chainHeight, &tmp);
	} else if (tlv->ftlv.tag == 0x03){
		res = MERKLE_TREE_calculate_new_tree_hash(logksi->tree, siblingHash, inputHash, *chainHeight, &tmp);
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

static int process_record_chain(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files) {
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
		res = LOGKSI_calculate_hash_of_metarecord_and_store_metarecord(logksi, tlvMetaRecord, &hash);
		ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to calculate metarecord hash.", logksi->blockNo);

		logksi->block.metarecordHash = KSI_DataHash_ref(hash);
	}

	res = tlv_element_get_hash(err, tlv, ksi, 0x01, &recordHash);
	ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse hash of logline no. %zu.", logksi->blockNo, logksi_get_nof_lines(logksi));

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
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: record hash no. %zu does not have a matching logline, end of logfile reached.", logksi->blockNo, logksi_get_nof_lines(logksi));
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
		int i;
		char description[1024];
		unsigned char chainHeight = 0;

		root = KSI_DataHash_ref(replacement);

		for (i = 0; i < KSI_TlvElementList_length(tlv->subList); i++) {
			KSI_TlvElement *tmpTlv = NULL;

			res = KSI_TlvElementList_elementAt(tlv->subList, i, &tmpTlv);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to get element %d from TLV.", logksi->blockNo, i);
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

static int process_partial_block(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files, MULTI_PRINTER* mp) {
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

	res = is_block_signature_expected(err, logksi);
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

		res = MERKLE_TREE_calculate_root_hash(logksi->tree, &rootHash);
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

static int process_partial_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, SIGNATURE_PROCESSORS *processors, LOGKSI *logksi, IO_FILES *files, int progress) {
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

	res = is_block_signature_expected(err, logksi);
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

				res = MERKLE_TREE_merge_one_level(logksi->tree, &missing);
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
			res = MERKLE_TREE_calculate_root_hash(logksi->tree, &rootHash);
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
			res = MERKLE_TREE_calculate_root_hash(logksi->tree, &rootHash);
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

static int check_warnings(LOGKSI *logksi) {
	if (logksi) {
		if (logksi->task.integrate.warningSignatures || logksi->file.warningTreeHashes || logksi->file.warningLegacy) {
			return 1;
		}
	}
	return 0;
}

static int finalize_log_signature(PARAM_SET* set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_DataHash* inputHash, LOGKSI *logksi, IO_FILES *files) {
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

	/* Finlize last block. */
	res = finalize_block(set, mp, err, ksi, logksi, files);
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


	if (check_warnings(logksi)) {
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

static int count_blocks(ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, SMART_FILE *in) {
	int res;
	KSI_TlvElement *tlv = NULL;
	KSI_TlvElement *tlvNoSig = NULL;

	if (err == NULL || in == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Do not count records, if input comes from stdin. */
	if (SMART_FILE_isStream(in)) {
		res = KT_OK;
		goto cleanup;
	}

	logksi->task.sign.blockCount = 0;
	logksi->task.sign.noSigCount = 0;
	logksi->task.sign.noSigNo = 0;

	while (!SMART_FILE_isEof(in)) {
		res = LOGKSI_FTLV_smartFileRead(in, logksi->ftlv_raw, SOF_FTLV_BUFFER, &logksi->ftlv_len, &logksi->ftlv);
		if (res == KSI_OK) {
			switch (logksi->ftlv.tag) {
				case 0x901:
					logksi->task.sign.blockCount++;
				break;

				case 0x904:
					res = tlv_element_parse_and_check_sub_elements(err, ksi, logksi->ftlv_raw, logksi->ftlv_len, logksi->ftlv.hdr_len, &tlv);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", logksi->blockNo);
					res = KSI_TlvElement_getElement(tlv, 0x02, &tlvNoSig);
					ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to extract 'no-sig' element in signatures file.", logksi->blockNo);

					if (tlvNoSig) logksi->task.sign.noSigCount++;

					KSI_TlvElement_free(tlvNoSig);
					tlvNoSig = NULL;
					KSI_TlvElement_free(tlv);
					tlv = NULL;
				break;

				default:
				/* Ignore hashes and other TLVs as we are just counting blocks. */
				break;
			}
		} else {
			if (logksi->ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", logksi->blockNo);
			} else {
				break;
			}
		}
	}

	res = KT_OK;

cleanup:

	if (in != NULL) SMART_FILE_rewind(in);

	KSI_TlvElement_free(tlvNoSig);
	KSI_TlvElement_free(tlv);

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
			res = finalize_block(set, mp, err, ksi, logksi, files);
			if (res != KT_OK) goto cleanup;

			res = init_next_block(logksi);
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

static int process_log_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files) {
	return process_log_signature_general_components_(set, mp, err, ksi, NULL, 0, logksi, files, NULL);
}

static int process_log_signature_with_block_signature(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile *pubFile, LOGKSI *blocks, IO_FILES *files, SIGNATURE_PROCESSORS *processors) {
	return process_log_signature_general_components_(set, mp, err, ksi, pubFile, 1, blocks, files, processors);
}

int logsignature_extend(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, KSI_PublicationsFile* pubFile, EXTENDING_FUNCTION extend_signature, IO_FILES *files) {
	int res;
	LOGKSI logksi;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;

	if (set == NULL || err == NULL || ksi == NULL || extend_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	LOGKSI_initialize(&logksi);
	logksi.ftlv_raw = ftlv_raw;
	logksi.taskId = TASK_EXTEND;
	logksi.err = err;
	memset(&processors, 0, sizeof(processors));
	processors.extend_signature = extend_signature;

	res = MERKLE_TREE_new(&logksi.tree);
	if (res != KT_OK) goto cleanup;

	logksi.isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");

	res = process_magic_number(set, mp, err, &logksi, files);
	if (res != KT_OK) goto cleanup;

	if (logksi.file.version == RECSIG11 || logksi.file.version == RECSIG12) {
		res = KT_VERIFICATION_SKIPPED;
		ERR_TRCKR_ADD(err, res, "Extending of excerpt file not yet implemented!");
		goto cleanup;
	}

	while (!SMART_FILE_isEof(files->files.inSig)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.inSig, logksi.ftlv_raw, SOF_FTLV_BUFFER, &logksi.ftlv_len, &logksi.ftlv);
		if (res == KSI_OK) {
			switch (logksi.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(logksi.block.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
				case 0x904:
					res = process_log_signature_with_block_signature(set, mp, err, ksi, pubFile, &logksi, files, &processors);
					if (res != KT_OK) goto cleanup;
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
			if (logksi.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", logksi.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, &logksi, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	LOGKSI_freeAndClearInternals(&logksi);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

static const char *io_files_getCurrentLogFilePrintRepresentation(IO_FILES *files) {
	int logStdin = 0;

	if (files == NULL) return NULL;

	logStdin = files->internal.inLog == NULL;
	return logStdin ? "stdin" : files->internal.inLog;
}

static int skip_current_block_as_it_does_not_verify(LOGKSI *logksi, MULTI_PRINTER* mp, IO_FILES *files, ERR_TRCKR *err, KSI_CTX *ksi, int *skip) {
	int res = KT_UNKNOWN_ERROR;
	KSI_TlvElement *tlv = NULL;
	size_t i = 0;
	char buf[1024];
	size_t logLinesToSkip = 0;


	if (logksi == NULL || ksi == NULL ||  skip == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* If skipping is not enabled, just exit. */
	if ((*skip) == 0) {
		res = KT_OK;
		goto cleanup;
	}

	switch (logksi->ftlv.tag) {
		case 0x901:
			*skip = 0;

			/* Normally this is incremented in process_block_signature or process_partial_signature.
			   If this has not happened it must be incremented here. */
			if (logksi->block.firstLineNo - 1 == logksi->file.nofTotalRecordHashes) {
				logksi->file.nofTotalRecordHashes += logksi->block.recordCount;
			}

			logLinesToSkip = logksi->block.recordCount - (logksi->block.nofRecordHashes - logksi->block.nofMetaRecords);

			if (logLinesToSkip > 0) {
				print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: Skipping %zu log lines.\n", logksi->blockNo, logLinesToSkip);

				for (i = 0; i < logLinesToSkip; i++) {
					res = SMART_FILE_gets(files->files.inLog, buf, sizeof(buf), NULL);
					if (res != SMART_FILE_OK) goto cleanup;
				}
			}
		break;

		case 0x904:
			res = tlv_element_parse_and_check_sub_elements(err, ksi, logksi->ftlv_raw, logksi->ftlv_len, logksi->ftlv.hdr_len, &tlv);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse block signature as TLV element.", logksi->blockNo);

			res = tlv_element_get_uint(tlv, ksi, 0x01, &logksi->block.recordCount);
			ERR_CATCH_MSG(err, res, "Error: Block no. %zu: missing record count in block signature.", logksi->blockNo);
			logksi->sigNo++;
		break;
	}

	res = KT_OK;

cleanup:

	KSI_TlvElement_free(tlv);

	return res;
}

int logsignature_verify(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, KSI_DataHash *firstLink, VERIFYING_FUNCTION verify_signature, IO_FILES *files, KSI_DataHash **lastLeaf, uint64_t* last_rec_time) {
	int res;

	KSI_DataHash *theFirstInputHashInFile = NULL;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	int isFirst = 1;
	int skipCurrentBlock = 0;
	int printHeader = 0;
	REGEXP *tmp_regxp = NULL;
	KSI_DataHash *prevLeaf = NULL;
	static uint64_t lastSignatureTime = 0;


	if (set == NULL || err == NULL || ksi == NULL || logksi == NULL || verify_signature == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	logksi->ftlv_raw = ftlv_raw;
	logksi->taskId = TASK_VERIFY;
	logksi->err = err;
	memset(&processors, 0, sizeof(processors));
	processors.verify_signature = verify_signature;

	res = MERKLE_TREE_new(&logksi->tree);
	if (res != KT_OK) goto cleanup;

	logksi->isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");
	logksi->sigTime_0 = lastSignatureTime;

	res = process_magic_number(set, mp, err, logksi, files);
	if (res != KT_OK) goto cleanup;

	if (PARAM_SET_isSetByName(set, "client-id")) {
		char *pattern = NULL;
		PARAM_SET_getStr(set, "client-id", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &pattern);

		res = REGEXP_new(pattern, &tmp_regxp);
		ERR_CATCH_MSG(err, res, "Error: Unable to parse regular expression for matching the client ID.");

		logksi->task.verify.client_id_match = tmp_regxp;
		tmp_regxp = NULL;
	}


	while (!SMART_FILE_isEof(files->files.inSig)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.inSig, logksi->ftlv_raw, SOF_FTLV_BUFFER, &logksi->ftlv_len, &logksi->ftlv);
		if (res == KSI_OK) {
			skip_current_block_as_it_does_not_verify(logksi, mp, files, err, ksi, &skipCurrentBlock);
			if (skipCurrentBlock) continue;

			switch (logksi->file.version) {
				case LOGSIG11:
				case LOGSIG12:
					switch (logksi->ftlv.tag) {
						case 0x904:
						case 0x901:
						case 0x902:
						case 0x903:
						case 0x911:
							res = process_log_signature_with_block_signature(set, mp, err, ksi, NULL, logksi, files, &processors);
							if (res != KT_OK) {
								/* In case of verification failure and --continue-on-fail option, verification is continued. */
								if ((res == KT_VERIFICATION_FAILURE || res == KSI_VERIFICATION_FAILURE) && logksi->isContinuedOnFail) {
									print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
									print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, res);
									print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

									logksi->quietError = KT_VERIFICATION_FAILURE;

									skipCurrentBlock = 1;
									logksi->task.verify.lastBlockWasSkipped = 1;

									print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: Skipping block %zu!\n", logksi->blockNo);
									print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: Block is skipped!\n", logksi->blockNo);
									res = KT_OK;
									continue;
								}
								goto cleanup;
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

					/* Addidional post processor for block header. */
					if (logksi->ftlv.tag == 0x901) {
						char buf[256];

						res = MERKLE_TREE_getPrevLeaf(logksi->tree, &prevLeaf);
						ERR_CATCH_MSG(err, res, "Error: Unable to get previous leaf.");

						LOGKSI_DataHash_toString(prevLeaf, buf, sizeof(buf));
						print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
						if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(prevLeaf);

						print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, "Block no. %3zu: input hash: %s.\n", logksi->blockNo, buf);

						print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_2 , "Verifying block no. %3zu... ", logksi->blockNo);


						/* Check if the last leaf from the previous block matches with the current first block. */
						if (isFirst == 1 && firstLink != NULL) {
							print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: verifying inter-linking input hash... ", logksi->blockNo);
							isFirst = 0;
							if (!KSI_DataHash_equals(firstLink, prevLeaf)) {
								char buf_imp[1024];
								char buf_exp_imp[1024];
								char buf_fname[4096];
								char *prevBlockSource = "Unexpected and not initialized previous block source.";
								const char *firstBlockSource = io_files_getCurrentLogFilePrintRepresentation(files);

								res = KT_VERIFICATION_FAILURE;

								if (PARAM_SET_isSetByName(set, "input-hash") && files->previousLogFile[0] == '\0') {
									char *fname = NULL;
									PARAM_SET_getStr(set, "input-hash", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &fname);

									PST_snprintf(buf_fname, sizeof(buf_fname), "from --input-hash %s", fname);
									prevBlockSource = buf_fname;
								} else {
									prevBlockSource = files->previousLogFile;
								}

								ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: The last leaf from the previous block (%s) does not match with the current first block (%s). Expecting '%s', but got '%s'.", logksi->blockNo, prevBlockSource, firstBlockSource, LOGKSI_DataHash_toString(firstLink, buf_exp_imp, sizeof(buf_exp_imp)), LOGKSI_DataHash_toString(prevLeaf, buf_imp, sizeof(buf_imp)));

								goto cleanup;
							}

							print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);
						}

					}

				break;

				case RECSIG11:
				case RECSIG12:
					switch (logksi->ftlv.tag) {
						case 0x905:
						{
							char strT1[256];
							logksi->file.nofTotalRecordHashes += logksi->block.nofRecordHashes;
							if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
								print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "}\n");
								MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
							}

							if ((logksi->file.recTimeMin == 0 || logksi->file.recTimeMin > logksi->block.recTimeMin) && logksi->block.recTimeMin > 0) logksi->file.recTimeMin = logksi->block.recTimeMin;
							if (logksi->file.recTimeMax == 0 || logksi->file.recTimeMax < logksi->block.recTimeMax) logksi->file.recTimeMax = logksi->block.recTimeMax;

							print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, res);
							if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_SUMMARY)) {
								print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", SIZE_OF_LONG_INDENTATION, "Record count:", logksi->block.nofRecordHashes);
								if (logksi->block.recTimeMin > 0) {
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "First record time:", LOGKSI_uint64_toDateString(logksi->block.recTimeMin, strT1, sizeof(strT1)));
								}

								if (logksi->block.recTimeMax > 0) {
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "Last record time:", LOGKSI_uint64_toDateString(logksi->block.recTimeMax, strT1, sizeof(strT1)));
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "Block duration:", time_diff_to_string(logksi->block.recTimeMax - logksi->block.recTimeMin, strT1, sizeof(strT1)));
								}

								print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\n", SIZE_OF_LONG_INDENTATION, "Record count:", logksi->block.nofRecordHashes);


								MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
								MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_ERRORS);
								MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_SUMMARY);
							}
							print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_2 , "Verifying block no. %3zu... ", logksi->blockNo + 1);
							res = process_ksi_signature(set, mp, err, ksi, &processors, logksi, files);
							if (res != KT_OK) goto cleanup;

							logksi->block.nofRecordHashes = 0;
							logksi->block.recTimeMin = 0;

							LOGKSI_uint64_toDateString(logksi->block.sigTime_1, strT1, sizeof(strT1));

							print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\nSummary of block %zu:\n", logksi->blockNo);
							print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_SHORT_INDENTENTION, "Sig time:", strT1);

							printHeader = 1;
						}
						break;

						case 0x907:
						{
						if (printHeader) {
							print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "Block no. %3zu: {", logksi->blockNo);
							printHeader = 0;
						}
							print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "r" );
							res = process_record_chain(set, mp, err, ksi, logksi, files);
							if (res != KT_OK) goto cleanup;

							res = check_log_record_embedded_time_against_ksi_signature_time(set, mp, err, logksi);
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
				break;

				default:
					/* TODO: unknown file header found. */
				break;
			}
		} else {
			if (logksi->ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", logksi->blockNo);
			} else {
				break;
			}
		}
	}

	if (logksi->file.version == RECSIG11 || logksi->file.version == RECSIG12) {
		char strT1[256];

		logksi->file.nofTotalRecordHashes += logksi->block.nofRecordHashes;

		print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%zu\n", SIZE_OF_LONG_INDENTATION, "Record count:", logksi->block.nofRecordHashes);

										if (logksi->block.recTimeMin > 0) {
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "First record time:", LOGKSI_uint64_toDateString(logksi->block.recTimeMin, strT1, sizeof(strT1)));
								}

								if (logksi->block.recTimeMax > 0) {
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "Last record time:", LOGKSI_uint64_toDateString(logksi->block.recTimeMax, strT1, sizeof(strT1)));
									print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, " * %-*s%s\n", SIZE_OF_LONG_INDENTATION, "Block duration:", time_diff_to_string(logksi->block.recTimeMax - logksi->block.recTimeMin, strT1, sizeof(strT1)));
								}
										print_debug_mp(mp, MP_ID_BLOCK_SUMMARY, DEBUG_EQUAL | DEBUG_LEVEL_2, "\n", SIZE_OF_LONG_INDENTATION, "Record count:", logksi->block.nofRecordHashes);

	}

	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES)) {
		print_debug_mp(mp, MP_ID_BLOCK_PARSING_TREE_NODES, DEBUG_LEVEL_3, "}\n");
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_PARSING_TREE_NODES);
	}


	/* If requested, return last leaf of last block. */
	if (lastLeaf != NULL) {
		KSI_DataHash_free(prevLeaf);
		prevLeaf = NULL;

		res = MERKLE_TREE_getPrevLeaf(logksi->tree, &prevLeaf);
		ERR_CATCH_MSG(err, res, "Error: Unable to get previous leaf.");

		*lastLeaf = KSI_DataHash_ref(prevLeaf);
	}

	if (last_rec_time != NULL) {
		*last_rec_time = logksi->block.recTimeMax;
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, logksi, files);
	if (res != KT_OK) goto cleanup;

	if (logksi->task.verify.errSignTime) {
		res = KT_VERIFICATION_FAILURE;
		ERR_TRCKR_ADD(err, res, "Error: Log block has signing time more recent than consecutive block!");
		goto cleanup;
	}

	res = KT_OK;

cleanup:

	if (logksi->quietError != KT_OK) {
		int isContinued = logksi->isContinuedOnFail && (res != KT_INVALID_CMD_PARAM) && (res != KT_USER_INPUT_FAILURE);
		res = logksi->quietError;
		ERR_TRCKR_ADD(err, res, isContinued ? "Error: Verification FAILED but was continued for further analysis." : "Error: Verification FAILED and was stopped.");
	}

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_2, res);

	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_ERRORS)) {
		print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n");
	}

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_ERRORS);

	KSI_DataHash_free(prevLeaf);
	REGEXP_free(tmp_regxp);
	KSI_DataHash_free(theFirstInputHashInFile);
	lastSignatureTime = logksi->block.sigTime_1;
	LOGKSI_freeAndClearInternals(logksi);

	return res;
}

int logsignature_extract(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	LOGKSI logksi;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;
	char *range = NULL;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	LOGKSI_initialize(&logksi);
	logksi.ftlv_raw = ftlv_raw;
	logksi.taskId = TASK_EXTRACT;
	logksi.err = err;
	memset(&processors, 0, sizeof(processors));
	processors.extract_signature = 1;

	res = MERKLE_TREE_new(&logksi.tree);
	if (res != KT_OK) goto cleanup;

	res = MERKLE_TREE_setCallbacks(logksi.tree, &logksi, logksi_extract_record_chain, logksi_new_record_chain);
	if (res != KT_OK) goto cleanup;


	logksi.isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");

	/* Initialize the first extract position. */
	res = PARAM_SET_getStr(set, "r", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, (char**)&range);
	if (res != KT_OK) goto cleanup;

	if (range) {
		res = EXTRACT_INFO_new(range, &logksi.task.extract.info);
		if (res != KT_OK) goto cleanup;
	}

	res = process_magic_number(set, mp, err, &logksi, files);
	if (res != KT_OK) goto cleanup;

	if (logksi.file.version == RECSIG11 || logksi.file.version == RECSIG12) {
		res = KT_VERIFICATION_SKIPPED;
		ERR_TRCKR_ADD(err, res, "Extracting from excerpt file not possible! Only log signature file can be extracted to produce excerpt file.");
		goto cleanup;
	}

	while (!SMART_FILE_isEof(files->files.inSig)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.inSig, logksi.ftlv_raw, SOF_FTLV_BUFFER, &logksi.ftlv_len, &logksi.ftlv);
		if (res == KSI_OK) {
			switch (logksi.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(logksi.block.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
				case 0x904:
					res = process_log_signature_with_block_signature(set, mp, err, ksi, NULL, &logksi, files, &processors);
					if (res != KT_OK) goto cleanup;
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
			if (logksi.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", logksi.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, &logksi, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	LOGKSI_freeAndClearInternals(&logksi);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

int logsignature_integrate(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI* logksi, IO_FILES *files) {
	int res;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;


	if (err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	logksi->ftlv_raw = ftlv_raw;
	logksi->taskId = TASK_INTEGRATE;
	logksi->err = err;
	memset(&processors, 0, sizeof(processors));

	res = MERKLE_TREE_new(&logksi->tree);
	if (res != KT_OK) goto cleanup;

	logksi->isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");

	res = process_magic_number(set, mp, err, logksi, files);
	if (res != KT_OK) goto cleanup;

	while (!SMART_FILE_isEof(files->files.partsBlk)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.partsBlk, logksi->ftlv_raw, SOF_FTLV_BUFFER, &logksi->ftlv_len, &logksi->ftlv);
		if (res == KSI_OK) {
			switch (logksi->ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(logksi->block.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
					res = process_log_signature(set, mp, err, ksi, logksi, files);
					if (res != KT_OK) goto cleanup;
				break;
				case 0x904:
				{
					print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_2, "Integrating block no. %3zu: into log signature... ", logksi->blockNo);

					res = process_partial_block(set, err, ksi, logksi, files, mp);
					if (res != KT_OK) goto cleanup;

					res = LOGKSI_FTLV_smartFileRead(files->files.partsSig, logksi->ftlv_raw, SOF_FTLV_BUFFER, &logksi->ftlv_len, &logksi->ftlv);

					if (res != KT_OK) {
						if (logksi->ftlv_len > 0) {
							res = KT_INVALID_INPUT_FORMAT;
							ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: incomplete data found in signatures file.", logksi->blockNo);
							ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature in signatures file.", logksi->blockNo);
						} else {
							res = KT_INVALID_INPUT_FORMAT;
							ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: unexpected end of signatures file.", logksi->blockNo);
							ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature in signatures file.", logksi->blockNo);
						}
					}
					if (logksi->ftlv.tag != 0x904) {
						res = KT_INVALID_INPUT_FORMAT;
						ERR_TRCKR_ADD(err, res, "Error: Block no. %zu: unexpected TLV %04X read from block-signatures file.", logksi->blockNo, logksi->ftlv.tag);
						ERR_CATCH_MSG(err, res, "Error: Block no. %zu: unable to parse KSI signature in signatures file.", logksi->blockNo);
					}

					res = process_partial_signature(set, mp, err, ksi, &processors, logksi, files, 0);
					if (res != KT_OK) goto cleanup;
					print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
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
			if (logksi->ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in blocks file.", logksi->blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, logksi, files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

static int wrapper_LOGKSI_createSignature(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files, KSI_DataHash *hash, KSI_uint64_t rootLevel, KSI_Signature **sig) {
	int res = KT_UNKNOWN_ERROR;
	int noErrTrckr = 0;

	if (set == NULL || err == NULL || ksi == NULL || logksi == NULL || files == NULL || hash == NULL || sig == NULL) {
		return KT_INVALID_ARGUMENT;
	}

	/* If --continue-on-fail is set, do not add errors to ERR_TRCKR as the amount of errors
	   will easily exceed its limits. */
	noErrTrckr = logksi->isContinuedOnFail;

	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Signing Block no. %3zu... ", logksi->blockNo);
	res = LOGKSI_createSignature((noErrTrckr ? NULL : err), ksi, hash, rootLevel, sig);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);

	return res;
}

int logsignature_sign(PARAM_SET *set, MULTI_PRINTER* mp, ERR_TRCKR *err, KSI_CTX *ksi, IO_FILES *files) {
	int res;
	int progress;
	LOGKSI logksi;
	unsigned char ftlv_raw[SOF_FTLV_BUFFER];
	SIGNATURE_PROCESSORS processors;
	KSI_DataHash *theFirstInputHashInFile = NULL;
	int lastError = KT_OK;

	if (set == NULL || err == NULL || ksi == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	LOGKSI_initialize(&logksi);
	logksi.ftlv_raw = ftlv_raw;
	logksi.taskId = TASK_SIGN;
	logksi.err = err;
	memset(&processors, 0, sizeof(processors));
	processors.create_signature = wrapper_LOGKSI_createSignature;

	res = MERKLE_TREE_new(&logksi.tree);
	if (res != KT_OK) goto cleanup;

	logksi.isContinuedOnFail = PARAM_SET_isSetByName(set, "continue-on-fail");

	res = process_magic_number(set, mp, err, &logksi, files);
	if (res != KT_OK) goto cleanup;

	if (logksi.file.version == RECSIG11 || logksi.file.version == RECSIG12) {
		res = KT_VERIFICATION_SKIPPED;
		ERR_TRCKR_ADD(err, res, "Signing of excerpt file not possible! Only log signature file can be signed.");
		goto cleanup;
	}

	if (SMART_FILE_isStream(files->files.inSig)) {
		progress = (PARAM_SET_isSetByName(set, "d")&& PARAM_SET_isSetByName(set, "show-progress"));
	} else {
		/* Impossible to estimate signing progress if input is from stdin. */
		progress = 0;
	}

	if (progress) {
		res = count_blocks(err, ksi, &logksi, files->files.inSig);
		if (res != KT_OK) goto cleanup;
		print_debug("Progress: %3zu of %3zu blocks need signing. Estimated signing time: %3zu seconds.\n",
			logksi.task.sign.noSigCount,
			logksi.task.sign.blockCount,
			logksi.task.sign.noSigCount);
	}

	while (!SMART_FILE_isEof(files->files.inSig)) {
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);

		res = LOGKSI_FTLV_smartFileRead(files->files.inSig, logksi.ftlv_raw, SOF_FTLV_BUFFER, &logksi.ftlv_len, &logksi.ftlv);
		if (res == KSI_OK) {
			switch (logksi.ftlv.tag) {
				case 0x901:
					if (theFirstInputHashInFile == NULL) theFirstInputHashInFile = KSI_DataHash_ref(logksi.block.inputHash);
				case 0x902:
				case 0x903:
				case 0x911:
					res = process_log_signature(set, mp, err, ksi, &logksi, files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					res = process_partial_signature(set, mp, err, ksi, &processors, &logksi, files, progress);
					if (res == KT_SIGNING_FAILURE) {
						lastError = res;
						res = KT_OK;
					}

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
			if (logksi.ftlv_len > 0) {
				res = KT_INVALID_INPUT_FORMAT;
				ERR_CATCH_MSG(err, res, "Error: Block no. %zu: incomplete data found in log signature file.", logksi.blockNo);
			} else {
				break;
			}
		}
	}

	res = finalize_log_signature(set, mp, err, ksi, theFirstInputHashInFile, &logksi, files);
	if (res != KT_OK) goto cleanup;

	res = SMART_FILE_markConsistent(files->files.outSig);
	ERR_CATCH_MSG(err, res, "Error: Could not close output log signature file %s.", files->internal.outSig);

	res = KT_OK;

cleanup:
	/**
	 * + If there is error mark output file as inconsistent.
	 * + If there is no changes and output is not explicitly specified
	 *   and output file already exists, mark output file as inconsistent.
	 * + Inconsistent state discards temporary file created.
	 */
	if (files->files.outSig != NULL &&
										(res != KT_OK ||
										 (!logksi.task.sign.outSigModified && !PARAM_SET_isSetByName(set, "o") && SMART_FILE_doFileExist(files->internal.outSig))
										)) {
		int tmp_res;
		tmp_res = SMART_FILE_markInconsistent(files->files.outSig);
		ERR_CATCH_MSG(err, tmp_res, "Error: Unable to mark output signature file as inconsistent.");
	}

	if (lastError != KT_OK) {
		res = lastError;
		ERR_TRCKR_ADD(err, res, "Error: Signing FAILED but was continued. All failed blocks are left unsigned!");
	}

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_2, res);
	LOGKSI_freeAndClearInternals(&logksi);
	KSI_DataHash_free(theFirstInputHashInFile);

	return res;
}

