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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include <ksi/policy.h>
#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "tool_box/ksi_init.h"
#include "tool_box/param_control.h"
#include "tool_box/task_initializer.h"
#include "tool_box.h"
#include "smart_file.h"
#include "err_trckr.h"
#include "api_wrapper.h"
#include "printer.h"
#include "obj_printer.h"
#include "debug_print.h"
#include "conf_file.h"
#include "tool.h"
//#include <ksi/tlv_element.h>
#include "../../libksi/out/include/ksi/tlv_element.h"

#define MAX_TREE_HEIGHT 10

typedef struct {
	char *inName;
	char *outName;
	char *backupName;
	char *tempName;
	FILE *inFile;
	FILE *inFile2;
	FILE *outFile;
} IO_FILES;

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

typedef int (*EXTENDING_FUNCTION)(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_Signature **ext);


static int extend_to_nearest_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_Signature **ext);
static int extend_to_specified_time(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_Signature **ext);
static int extend_to_specified_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_Signature **ext);
static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int get_backup_name(char *org, char **backup);
static int get_temp_name(char **name);
static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(int result, IO_FILES *files);
static void free_blocks(BLOCK_INFO *blocks);
static int process_magic_number(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static int process_block_header(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files);
static int calculate_new_leaf_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *recordHash, KSI_DataHash **leafHash);
static int calculate_new_intermediate_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *leftHash, KSI_DataHash *rightHash, unsigned char level, KSI_DataHash **nodeHash);
static int add_hash_to_merkle_tree(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *hash);
static int process_record_hash(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files);
static int process_intermediate_hash(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files);
static int process_block_signature(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, EXTENDING_FUNCTION extend_signature, BLOCK_INFO *blocks, IO_FILES *files);
static int finalize_log_signature(PARAM_SET *set, ERR_TRCKR *err, BLOCK_INFO *blocks);
static size_t buf_to_int(unsigned char *buf, size_t len);
static void adjust_tlv_length_in_buffer(unsigned char *raw, KSI_FTLV *ftlv);

int extend_run(int argc, char** argv, char **envp) {
	int res;
	TASK *task = NULL;
	TASK_SET *task_set = NULL;
	PARAM_SET *set = NULL;
	KSI_CTX *ksi = NULL;
	SMART_FILE *logfile = NULL;
	ERR_TRCKR *err = NULL;
	char buf[2048];
	int d = 0;
	IO_FILES files;
	BLOCK_INFO blocks;
	unsigned char ftlv_raw[0xffff + 4];
	EXTENDING_FUNCTION extend_signature = NULL;

	memset(&files, 0, sizeof(files));
	memset(&blocks, 0, sizeof(blocks));
	blocks.ftlv_raw = ftlv_raw;

	/**
	 * Extract command line parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{i}{o}{d}{x}{T}{pub-str}{dump}{conf}{log}{h|help}", "XP", buf, sizeof(buf)),
			&set);
	if (res != KT_OK) goto cleanup;

	res = TASK_SET_new(&task_set);
	if (res != PST_OK) goto cleanup;

	res = generate_tasks_set(set, task_set);
	if (res != PST_OK) goto cleanup;

	res = TASK_INITIALIZER_getServiceInfo(set, argc, argv, envp);
	if (res != PST_OK) goto cleanup;

	res = TASK_INITIALIZER_check_analyze_report(set, task_set, 0.5, 0.1, &task);
	if (res != KT_OK) goto cleanup;

	res = TOOL_init_ksi(set, &ksi, &err, &logfile);
	if (res != KT_OK) goto cleanup;

	d = PARAM_SET_isSetByName(set, "d");

	res = check_pipe_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = PARAM_SET_getStr(set, "i", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.inName);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.outName);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	switch(TASK_getID(task)) {
		case 0:
			extend_signature = extend_to_nearest_publication;
		break;

		case 1:
			extend_signature = extend_to_specified_time;
		break;

		case 2:
			extend_signature = extend_to_specified_publication;
		break;

		default:
			res = KT_UNKNOWN_ERROR;
			goto cleanup;
		break;
	}

	res = open_input_and_output_files(err, &files);
	if (res != KT_OK) goto cleanup;

	res = process_magic_number(set, err, &files);
	if (res != KT_OK) goto cleanup;

	while (!feof(files.inFile)) {
		res = KSI_FTLV_fileRead(files.inFile, blocks.ftlv_raw, sizeof(ftlv_raw), &blocks.ftlv_len, &blocks.ftlv);
		if (res == KSI_OK) {
			switch (blocks.ftlv.tag) {
				case 0x901:
					res = process_block_header(set, err, ksi, &blocks, &files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x902:
					res = process_record_hash(set, err, ksi, &blocks, &files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x903:
					res = process_intermediate_hash(set, err, ksi, &blocks, &files);
					if (res != KT_OK) goto cleanup;
				break;

				case 0x904:
				{
					if (files.inFile2) {
						res = KSI_FTLV_fileRead(files.inFile2, blocks.ftlv_raw, sizeof(ftlv_raw), &blocks.ftlv_len, &blocks.ftlv);
						if (res != KT_OK) goto cleanup;
					}
					res = process_block_signature(set, err, ksi, extend_signature, &blocks, &files);
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
			if (feof(files.inFile)) {
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

	close_input_and_output_files(res, &files);
	free_blocks(&blocks);

	print_progressResult(res);
	KSITOOL_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		KSITOOL_KSI_ERRTrace_LOG(ksi);

		print_errors("\n");
		if (d) ERR_TRCKR_printExtendedErrors(err);
		else  ERR_TRCKR_printErrors(err);
	}

	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);

	return KSITOOL_errToExitCode(res);
}
char *extend_help_toString(char*buf, size_t len) {
	size_t count = 0;

	count += KSI_snprintf(buf + count, len - count,
		"Usage:\n"
		" %s extend -i <in.ls11> [-o <out.ls11>] -X <URL>\n"
		"    [--ext-user <user> --ext-key <key>] -P <URL> [--cnstr <oid=value>]... [more_options]\n"
		" %s extend -i <in.ls11> [-o <out.ls11>] -X <URL>\n"
		"    [--ext-user <user> --ext-key <key>] -P <URL> [--cnstr <oid=value>]... [--pub-str <str>] [more_options]\n"
		" %s extend -i <in.ls11> [-o <out.ls11>] -X <URL>\n"
		"    [--ext-user <user> --ext-key <key>] -T time [more_options]\n"
		"\n"
		" -i <in.ls11>\n"
		"           - File path to the log signature file to be extended. If not specified or '-',\n"
		"             the log signature is read from stdin.\n"
		" -o <out.ls11>\n"
		"           - Output file path for the extended log signature file. Use '-' to redirect the extended\n"
		"             log signature binary stream to stdout. If not specified, the log signature is saved\n"
		"             to <in.ls11> while a backup of <in.ls11> is saved in <in.ls11>.bak.\n"
		"             If specified, existing file is always overwritten.\n"
		"             If both input and outpur or not specified, stdin and stdout are used resepectively.\n"
		" -X <URL>  - Extending service (KSI Extender) URL.\n"
		" --ext-user <user>\n"
		"           - Username for extending service.\n"
		" --ext-key <key>\n"
		"           - HMAC key for extending service.\n"
		" -P <URL>  - Publications file URL (or file with URI scheme 'file://').\n"
		" --cnstr <oid=value>\n"
		"           - OID of the PKI certificate field (e.g. e-mail address) and the expected\n"
		"             value to qualify the certificate for verification of publications file\n"
		"             PKI signature. At least one constraint must be defined.\n"
		" --pub-str <str>\n"
		"           - Publication record as publication string to extend the signature to.\n"
		" -T <time> - Publication time to extend to as the number of seconds since\n"
		"             1970-01-01 00:00:00 UTC or time string formatted as \"YYYY-MM-DD hh:mm:ss\".\n"
		"\n"
		"\n"
		" -V        - Certificate file in PEM format for publications file verification.\n"
		"             All values from lower priority source are ignored.\n"
		" -d        - Print detailed information about processes and errors.\n"
		" --dump    - Dump extended signature and verification info in human-readable format to stdout.\n"
		" --conf <file>\n"
		"             Read configuration options from given file. It must be noted\n"
		"             that configuration options given explicitly on command line will\n"
		"             override the ones in the configuration file.\n"
		" --log <file>\n"
		"           - Write libksi log to given file. Use '-' as file name to redirect\n"
		"             log to stdout.\n",
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName()
	);

	return buf;
}
const char *extend_get_desc(void) {
	return "Extends existing KSI signature to the given publication.";
}

static int extend_to_nearest_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_Signature **ext) {
	int res;
	int d = 0;
	KSI_Signature *tmp = NULL;
	KSI_PublicationsFile *pubFile = NULL;

	if (set == NULL || ksi == NULL || err == NULL || sig == NULL || ext == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(d, "%s", getPublicationsFileRetrieveDescriptionString(set));
	res = KSITOOL_receivePublicationsFile(err, ksi, &pubFile);
	ERR_CATCH_MSG(err, res, "Error: Unable receive publications file.");
	print_progressResult(res);

	if (!PARAM_SET_isSetByName(set, "publications-file-no-verify")) {
		print_progressDesc(d, "Verifying publications file... ");
		res = KSITOOL_verifyPublicationsFile(err, ksi, pubFile);
		ERR_CATCH_MSG(err, res, "Error: Unable to verify publications file.");
		print_progressResult(res);
	}

	print_progressDesc(d, "Extend the signature to the earliest available publication... ");
	res = KSITOOL_extendSignature(err, ksi, sig, &tmp);
	ERR_CATCH_MSG(err, res, "Error: Unable to extend signature.");
	print_progressResult(res);

	*ext = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:
	print_progressResult(res);

	KSI_PublicationsFile_free(pubFile);
	KSI_Signature_free(tmp);

	return res;
}

static int extend_to_specified_time(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_Signature **ext) {
	int res;
	int d = 0;
	KSI_Signature *tmp = NULL;
	KSI_Integer *pubTime = NULL;
	char buf[256];
	COMPOSITE extra;


	if (set == NULL || ksi == NULL || err == NULL || sig == NULL || ext == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	extra.ctx = ksi;
	extra.err = err;

	d = PARAM_SET_isSetByName(set, "d");

	res = PARAM_SET_getObjExtended(set, "T", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &extra, (void**)&pubTime);
	if (res != KT_OK) {
		ERR_TRCKR_ADD(err, res, "Error: Unable to extract the time value to extend to.");
		goto cleanup;
	}

	/* Extend the signature. */
	print_progressDesc(d, "Extending the signature to %s (%i)... ",
			KSI_Integer_toDateString(pubTime, buf, sizeof(buf)),
			KSI_Integer_getUInt64(pubTime));
	res = KSITOOL_Signature_extendTo(err, sig, ksi, pubTime, &tmp);
	ERR_CATCH_MSG(err, res, "Error: Unable to extend signature.");
	print_progressResult(res);

	*ext = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:
	print_progressResult(res);

	KSI_Integer_free(pubTime);
	KSI_Signature_free(tmp);

	return res;
}

static int extend_to_specified_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_Signature **ext) {
	int res;
	int d = 0;
	KSI_Signature *tmp = NULL;
	KSI_PublicationRecord *pub_rec = NULL;
	KSI_PublicationsFile *pubFile = NULL;
	char *pubs_str = NULL;

	if (set == NULL || ksi == NULL || err == NULL || sig == NULL || ext == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");
	res = PARAM_SET_getStr(set, "pub-str", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &pubs_str);
	ERR_CATCH_MSG(err, res, "Error: Unable get publication string.");

	print_progressDesc(d, "%s", getPublicationsFileRetrieveDescriptionString(set));
	res = KSITOOL_receivePublicationsFile(err, ksi, &pubFile);
	ERR_CATCH_MSG(err, res, "Error: Unable receive publications file.");
	print_progressResult(res);

	print_progressDesc(d, "Searching for a publication record from publications file... ");
	res = KSI_PublicationsFile_getPublicationDataByPublicationString(pubFile, pubs_str, &pub_rec);
	ERR_CATCH_MSG(err, res, "Error: Unable get publication record from publications file.");
	if (pub_rec == NULL) {
		ERR_TRCKR_ADD(err, res = KT_PUBFILE_HAS_NO_PUBREC_TO_EXTEND_TO, "Error: Unable to extend signature as publication record not found from publications file.");
		goto cleanup;
	}
	print_progressResult(res);


	if (!PARAM_SET_isSetByName(set, "publications-file-no-verify")) {
		print_progressDesc(d, "Verifying publications file... ");
		res = KSITOOL_verifyPublicationsFile(err, ksi, pubFile);
		ERR_CATCH_MSG(err, res, "Error: Unable to verify publications file.");
		print_progressResult(res);
	}

	print_progressDesc(d, "Extend the signature to the specified publication... ");
	res = KSITOOL_Signature_extend(err, sig, ksi, pub_rec, &tmp);
	ERR_CATCH_MSG(err, res, "Error: Unable to extend signature.");
	print_progressResult(res);

	*ext = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:
	print_progressResult(res);

	KSI_PublicationsFile_free(pubFile);
	KSI_Signature_free(tmp);

	return res;
}

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set) {
	int res;

	if (set == NULL || task_set == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/**
	 * Configure parameter set, control, repair and object extractor function.
	 */
	res = CONF_initialize_set_functions(set, "XP");
	if (res != KT_OK) goto cleanup;

	/**
	 * Configure parameter set, control, repair and object extractor function.
	 */
	PARAM_SET_addControl(set, "{conf}", isFormatOk_inputFile, isContentOk_inputFileRestrictPipe, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{log}{o}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{i}", isFormatOk_inputFile, isContentOk_inputFileWithPipe, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{T}", isFormatOk_utcTime, isContentOk_utcTime, NULL, extract_utcTime);
	PARAM_SET_addControl(set, "{d}{dump}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{pub-str}", isFormatOk_pubString, NULL, NULL, extract_pubString);

	/**
	 * Define possible tasks.
	 */
	/*					  ID	DESC												MAN					ATL		FORBIDDEN		IGN	*/
	TASK_SET_add(task_set, 0,	"Extend to the earliest available publication.",	"X,P",			NULL,	"T,pub-str",	NULL);
	TASK_SET_add(task_set, 1,	"Extend to the specified time.",					"X,T",			NULL,	"pub-str",		NULL);
	TASK_SET_add(task_set, 2,	"Extend to time specified in publications string.",	"X,P,pub-str",	NULL,	"T",			NULL);

cleanup:

	return res;
}

static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;

	res = get_pipe_out_error(set, err, NULL, "o", "dump");
	if (res != KT_OK) goto cleanup;

	res = get_pipe_out_error(set, err, NULL, "o,log", NULL);
	if (res != KT_OK) goto cleanup;

cleanup:
	return res;
}

static int get_backup_name(char *org, char **backup) {
	int res = KT_OUT_OF_MEMORY;
	char *buf = NULL;

	buf = (char*)KSI_malloc(strlen(org) + strlen(".bak") + 1);
	if (buf == NULL) goto cleanup;
	sprintf(buf, "%s%s", org, ".bak");
	*backup = buf;
	res = KT_OK;

cleanup:

	return res;
}

static int get_temp_name(char **name) {
	int res = KT_OUT_OF_MEMORY;
	char *buf = NULL;

	buf = (char*)KSI_malloc(strlen("stdout.tmp") + 1);
	if (buf == NULL) goto cleanup;
	strcpy(buf, "stdout.tmp");
	*name = buf;
	res = KT_OK;

cleanup:

	return res;
}

static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files) {
	int res = KT_IO_ERROR;
	IO_FILES tmp;
	char *buf = NULL;

	memset(&tmp, 0, sizeof(tmp));

	/* Default input file is stdin. */
	if (files->inName == NULL || !strcmp(files->inName, "-")) {
		/* Default output file is a temporary file that is copied to stdout on success. */
		if (files->outName == NULL || !strcmp(files->outName, "-")) {
			res = get_temp_name(&tmp.tempName);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			tmp.outName = tmp.tempName;
		} else {
			tmp.outName = files->outName;
		}
	} else {
		/* Default output file is the same as input, but a backup of the input file is retained. */
		if (files->outName == NULL || !strcmp(files->inName, files->outName)) {
			res = get_backup_name(files->inName, &buf);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			remove(buf);
			res = (rename(files->inName, buf) == 0) ? KT_OK : KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not rename file %s to %s.", files->inName, buf);
			tmp.backupName = buf;
			buf = NULL;
			tmp.inName = tmp.backupName;
			tmp.outName = files->inName;
		} else if (!strcmp(files->outName, "-")) {
			res = get_temp_name(&tmp.tempName);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			tmp.inName = files->inName;
			tmp.outName = tmp.tempName;
		} else {
			tmp.inName = files->inName;
			tmp.outName = files->outName;
		}
	}

	if (tmp.inName) {
		tmp.inFile = fopen(tmp.inName, "rb");
		res = (tmp.inFile == NULL) ? KT_IO_ERROR : KT_OK;
		ERR_CATCH_MSG(err, res, "Error: could not open file %s.", tmp.inName);
	} else {
		tmp.inFile = stdin;
	}

	if (tmp.outName) {
		tmp.outFile = fopen(tmp.outName, "wb");
		res = (tmp.outFile == NULL) ? KT_IO_ERROR : KT_OK;
		ERR_CATCH_MSG(err, res, "Error: could not create file %s.", tmp.outName);
	} else {
		tmp.outFile = stdout;
	}

	tmp.inFile2 = fopen("block-signatures.dat", "rb");

	tmp.inName = files->inName;
	tmp.outName = files->outName;
	*files = tmp;
	memset(&tmp, 0, sizeof(tmp));
	res = KT_OK;

cleanup:

	if (tmp.inFile == stdin) tmp.inFile = NULL;
	if (tmp.outFile == stdout) tmp.outFile = NULL;

	if (tmp.backupName) {
		if (tmp.inFile) fclose(tmp.inFile);
		tmp.inFile = NULL;
		rename(tmp.backupName, files->inName);
		KSI_free(tmp.backupName);
	}
	if (tmp.tempName) {
		if (tmp.outFile) fclose(tmp.outFile);
		tmp.outFile = NULL;
		KSI_free(tmp.tempName);
	}
	KSI_free(buf);

	if (tmp.inFile) fclose(tmp.inFile);
	if (tmp.outFile) fclose(tmp.outFile);

	return res;
}

static void close_input_and_output_files(int result, IO_FILES *files) {
	char buf[1024];
	size_t count = 0;

	if (files->inFile == stdin) files->inFile = NULL;
	if (files->outFile == stdout) files->outFile = NULL;

	if (files->tempName) {
		if (result == KT_OK) {
			freopen(NULL, "rb", files->outFile);
			while (!feof(files->outFile)) {
				count = fread(buf, 1, sizeof(buf), files->outFile);
				fwrite(buf, 1, count, stdout);
			}
		}
		fclose(files->outFile);
		files->outFile = NULL;
		remove(files->tempName);
		KSI_free(files->tempName);
	}

	if (files->backupName) {
		if (result != KT_OK) {
			fclose(files->outFile);
			files->outFile = NULL;
			remove(files->inName);
			fclose(files->inFile);
			files->inFile = NULL;
			rename(files->backupName, files->inName);
		}
		KSI_free(files->backupName);
	}

	if (files->inFile) fclose(files->inFile);
	if (files->outFile) fclose(files->outFile);
	if (files->inFile2) fclose(files->inFile2);
}

static void free_blocks(BLOCK_INFO *blocks) {
	unsigned char i = 0;

	KSI_DataHash_free(blocks->lastRecordHash);
	KSI_OctetString_free(blocks->randomSeed);
	while (i < blocks->treeHeight) {
		KSI_DataHash_free(blocks->MerkleTree[i]);
		KSI_DataHash_free(blocks->notVerified[i]);
		i++;
	}
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

static int add_hash_to_merkle_tree(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash *hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *lastHash = NULL;
	KSI_DataHash *right = NULL;
	KSI_DataHash *tmp = NULL;

	res = calculate_new_leaf_hash(ksi, blocks, hash, &lastHash);
	if (res != KT_OK) goto cleanup;

	right = KSI_DataHash_ref(lastHash);

	blocks->balanced = 0;
	while (blocks->MerkleTree[i] != NULL) {
		res = calculate_new_intermediate_hash(ksi, blocks, blocks->MerkleTree[i], right, i + 2, &tmp);
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
	res = KT_OK;

cleanup:

	return res;
}

static int calculate_root_hash(KSI_CTX *ksi, BLOCK_INFO *blocks, KSI_DataHash **hash) {
	int res;
	unsigned char i = 0;
	KSI_DataHash *root = NULL;
	KSI_DataHash *tmp = NULL;

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
	res = KT_OK;
cleanup:

	KSI_DataHash_free(root);
	return res;
}

static int process_record_hash(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files) {
	int res;
	int d = 0;
	KSI_DataHash *recordHash = NULL;
	KSI_DataHash *leafHash = NULL;
	KSI_DataHash *nodeHash = NULL;

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
	KSI_DataHash_free(leafHash);
	KSI_DataHash_free(nodeHash);
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
	if (i >= blocks->treeHeight) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unexpected intermediate record hash.", blocks->blockNo);
	}

	if (!KSI_DataHash_equals(blocks->notVerified[i], tmpHash)) {
		res = KT_VERIFICATION_FAILURE;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to verify intermediate record hash.", blocks->blockNo);
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
	KSI_FTLV sub_ftlv[4];
	size_t nof_sub_ftlvs = 0;
	unsigned char *sub_ftlv_raw = NULL;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	size_t sig_idx = 0;

	if (set == NULL || err == NULL || ksi == NULL || extend_signature == NULL || files == NULL || blocks == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(d, "Block no. %3d: processing block signature data... ", blocks->blockNo);

	blocks->sigNo++;
	if (blocks->sigNo > blocks->blockNo) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: block signature data without preceding block header found.", blocks->sigNo);
	}

	sub_ftlv_raw = blocks->ftlv_raw + blocks->ftlv.hdr_len;
	res = KSI_FTLV_memReadN(sub_ftlv_raw, blocks->ftlv_len - blocks->ftlv.hdr_len, sub_ftlv, 4, &nof_sub_ftlvs);
	ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block signature data.", blocks->blockNo);
	sig_idx = nof_sub_ftlvs - 1;
	if (nof_sub_ftlvs < 2) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse block signature data.", blocks->blockNo);
	} else if (sub_ftlv[0].tag != 0x01) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse record count.", blocks->blockNo);
	} else if (sub_ftlv[sig_idx].tag != 0x0905) {
		res = KT_INVALID_INPUT_FORMAT;
		ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unsupported block signature type %04X found.", blocks->blockNo, sub_ftlv[sig_idx].tag);
	} else {
		unsigned char *sig_raw = NULL;
		size_t sig_raw_len = 0;
		unsigned char *ext_raw = NULL;
		size_t ext_raw_len = 0;
		size_t record_count = 0;
		KSI_VerificationContext context;

		record_count = buf_to_int(sub_ftlv_raw + sub_ftlv[0].off + sub_ftlv[0].hdr_len, sub_ftlv[0].dat_len);
		if (record_count != blocks->nofRecordHashes) {
			res = KT_INVALID_INPUT_FORMAT;
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: expected %d record hashes, but found %d.", blocks->blockNo, record_count, blocks->nofRecordHashes);
		}
		print_progressResult(res); /* Done with parsing block signature data. */

		print_progressDesc(d, "Block no. %3d: parsing and verifying KSI signature... ", blocks->blockNo);
		sig_raw = sub_ftlv_raw + sub_ftlv[sig_idx].off + sub_ftlv[sig_idx].hdr_len;
		sig_raw_len = sub_ftlv[sig_idx].dat_len;
		if (sig_raw_len > 0) {
			KSI_VerificationContext_init(&context, ksi);
			res = calculate_root_hash(ksi, blocks, &context.documentHash);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to get root hash for verification.", blocks->blockNo);
			res = KSI_Signature_parseWithPolicy(ksi, sig_raw, sig_raw_len, KSI_VERIFICATION_POLICY_INTERNAL, &context, &sig);
			ERR_CATCH_MSG(err, res, "Error: Block no. %3d: unable to parse KSI signature.", blocks->blockNo);
			KSI_DataHash_free(context.documentHash);
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
		}
		print_progressResult(res);

		print_progressDesc(d, "Block no. %3d: writing extended KSI signature to file... ", blocks->blockNo);
		/* Reuse the raw buffer and adjust FTLV headers accordingly. */
		memcpy(sig_raw, ext_raw, ext_raw_len);
		KSI_free(ext_raw);
		ext_raw = NULL;

		blocks->ftlv.dat_len = blocks->ftlv.dat_len - sig_raw_len + ext_raw_len;
		sub_ftlv[sig_idx].dat_len = ext_raw_len;
		adjust_tlv_length_in_buffer(sub_ftlv_raw + sub_ftlv[sig_idx].off, &sub_ftlv[sig_idx]);
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
