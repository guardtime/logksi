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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include <ksi/policy.h>
#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "param_set/parameter.h"
#include "tool_box/ksi_init.h"
#include "tool_box/param_control.h"
#include "tool_box/task_initializer.h"
#include "smart_file.h"
#include "err_trckr.h"
#include "api_wrapper.h"
#include "printer.h"
#include "debug_print.h"
#include "obj_printer.h"
#include "conf_file.h"
#include "tool.h"
#include "rsyslog.h"
#include "blocks_info.h"
#include "io_files.h"

enum {
	/* Trust anchor based verification. */
	ANC_BASED_DEFAULT,
	ANC_BASED_DEFAULT_STDIN,
	ANC_BASED_PUB_FILE,
	ANC_BASED_PUB_FILE_X,
	ANC_BASED_PUB_SRT,
	ANC_BASED_PUB_SRT_X,
	/* Internal verification. */
	INT_BASED,
	/* Calendar based verification. */
	CAL_BASED,
	KEY_BASED,
	/* Publication based verification, use publications file. */
	PUB_BASED_FILE,
	PUB_BASED_FILE_X,
	/* Publication based verification, use publication string. */
	PUB_BASED_STR,
	PUB_BASED_STR_X
};

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);

static int signature_verify_general(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_internally(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_key_based(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_publication_based_with_user_pub(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_publication_based_with_pubfile(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi,  BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_calendar_based(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int generate_filenames(ERR_TRCKR *err, IO_FILES *files);
static int open_log_and_signature_files(ERR_TRCKR *err, IO_FILES *files);
static void close_log_and_signature_files(IO_FILES *files);
static int save_output_hash(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *ioFiles, KSI_DataHash *hash, char * logFileName, char * sigFileName);
static int getLogFiles(PARAM_SET *set, ERR_TRCKR *err, int i, IO_FILES *files);


int verify_run(int argc, char **argv, char **envp) {
	int res;
	char buf[2048];
	PARAM_SET *set = NULL;
	TASK_SET *task_set = NULL;
	TASK *task = NULL;
	KSI_CTX *ksi = NULL;
	ERR_TRCKR *err = NULL;
	SMART_FILE *logfile = NULL;
	KSI_DataHash *inputHash = NULL;
	KSI_DataHash *outputHash = NULL;
	KSI_DataHash *pLastOutputHash = NULL;
	int d = 0;
	int isMultipleLog = 0;
	KSI_Signature *sig = NULL;
	IO_FILES files;
	VERIFYING_FUNCTION verify_signature = NULL;
	int i = 0;
	char *logFileNameCpy = NULL;
	char *sigFileNameCpy = NULL;
	BLOCK_INFO blocks;
	MULTI_PRINTER *mp = NULL;


	BLOCK_INFO_reset(&blocks);
	IO_FILES_init(&files);
	/**
	 * Extract command line parameters and also add configuration specific parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{warn-same-block-time}{ignore-desc-block-time}{multiple_logs}{input}{input-hash}{output-hash}{log-from-stdin}{x}{d}{pub-str}{ver-int}{ver-cal}{ver-key}{ver-pub}{use-computed-hash-on-fail}{use-stored-hash-on-fail}{continue-on-fail}{conf}{log}{h|help}{mdata-as-string}", "XP", buf, sizeof(buf)),
			&set);
	if (res != KT_OK) goto cleanup;

	res = TASK_SET_new(&task_set);
	if (res != PST_OK) goto cleanup;

	res = generate_tasks_set(set, task_set);
	if (res != PST_OK) goto cleanup;

	res = TASK_INITIALIZER_getServiceInfo(set, argc, argv, envp);
	if (res != PST_OK) goto cleanup;

	res = TASK_INITIALIZER_check_analyze_report(set, task_set, 0.2, 0.1, &task);
	if (res != KT_OK) goto cleanup;

	res = TASK_INITIALIZER_getPrinter(set, &mp);
	ERR_CATCH_MSG(err, res, "Error: Unable to create Multi printer!");

	res = TOOL_init_ksi(set, &ksi, &err, &logfile);
	if (res != KT_OK) goto cleanup;

	d = PARAM_SET_isSetByName(set, "d");
	isMultipleLog = PARAM_SET_isSetByName(set, "multiple_logs");



	res = check_pipe_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = check_io_naming_and_type_errors(set, err);
	if (res != KT_OK) goto cleanup;

	switch(TASK_getID(task)) {
		case ANC_BASED_DEFAULT:
		case ANC_BASED_DEFAULT_STDIN:
		case ANC_BASED_PUB_FILE:
		case ANC_BASED_PUB_FILE_X:
		case ANC_BASED_PUB_SRT:
		case ANC_BASED_PUB_SRT_X:
			verify_signature = signature_verify_general;
		break;

		case INT_BASED:
			verify_signature = signature_verify_internally;
		break;

		case CAL_BASED:
			verify_signature = signature_verify_calendar_based;
		break;

		case KEY_BASED:
			verify_signature = signature_verify_key_based;
		break;

		case PUB_BASED_FILE:
		case PUB_BASED_FILE_X:
			verify_signature = signature_verify_publication_based_with_pubfile;
		break;

		case PUB_BASED_STR:
		case PUB_BASED_STR_X:
			verify_signature = signature_verify_publication_based_with_user_pub;
		break;

		default:
			res = KT_UNKNOWN_ERROR;
			goto cleanup;
		break;
	}



	if (PARAM_SET_isSetByName(set, "input-hash")) {
		COMPOSITE extra;
		extra.ctx = ksi;
		extra.err = err;
		res = PARAM_SET_getObjExtended(set, "input-hash", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &extra, (void**)&inputHash);
		ERR_CATCH_MSG(err, res, "Unable to extract input hash value!");
	}

	do {
		res = getLogFiles(set, err, i, &files);
		 if (res == PST_PARAMETER_VALUE_NOT_FOUND) {
			res = KT_OK;
			break;
		}
		ERR_CATCH_MSG(err, res, "Error: Unable to get file names for log and log signature file.");


		res = generate_filenames(err, &files);
		if (res != KT_OK) goto cleanup;

		res = open_log_and_signature_files(err, &files);
		if (res != KT_OK) goto cleanup;

		if (isMultipleLog) {
			print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "%sLog file '%s'.\n", (i == 0 ? "" : "\n"), files.internal.inLog);
		}


		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_1, "Verifying... ");
		res = logsignature_verify(set, mp, err, ksi, &blocks, inputHash, verify_signature, &files, &outputHash);
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
		if (res != KT_OK) goto cleanup;

		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
		if (MULTI_PRINTER_hasDataByID(mp, MP_ID_LOGFILE_WARNINGS)) {
			print_debug("\n");
			MULTI_PRINTER_printByID(mp, MP_ID_LOGFILE_WARNINGS);
		}

		KSI_DataHash_free(inputHash);
		inputHash = outputHash;
		pLastOutputHash = outputHash;
		outputHash = NULL;

		IO_FILES_StorePreviousFileNames(&files);
		close_log_and_signature_files(&files);
		i++;
	} while(1);


	res = save_output_hash(set, err, &files, pLastOutputHash, logFileNameCpy, sigFileNameCpy);
	if (res != KT_OK) goto cleanup;

cleanup:


	close_log_and_signature_files(&files);

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_LOGFILE_WARNINGS)) {
		print_debug("\n");
		MULTI_PRINTER_printByID(mp, MP_ID_LOGFILE_WARNINGS);
	}

	LOGKSI_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		LOGKSI_KSI_ERRTrace_LOG(ksi);

		print_errors("\n");
		ERR_TRCKR_print(err, d);
	}

	KSI_DataHash_free(inputHash);
	KSI_DataHash_free(outputHash);
	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	free(logFileNameCpy);
	free(sigFileNameCpy);
	KSI_Signature_free(sig);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);
	MULTI_PRINTER_free(mp);

	return LOGKSI_errToExitCode(res);
}

char *verify_help_toString(char *buf, size_t len) {
	KSI_snprintf(buf, len,
		"Usage:\n"
		" %s verify <logfile> [<logfile.logsig>] [more_options]\n"
		" %s verify --log-from-stdin <logfile.logsig> [more_options]\n"
		" %s verify <logfile>.excerpt [<logfile.excerpt.logsig>] [more_options]\n"
		" %s verify --log-from-stdin <logfile.excerpt.logsig> [more_options]\n"
		" %s verify --ver-int <logfile> [<logfile.logsig>] [more_options]\n"
		" %s verify --ver-cal <logfile> [<logfile.logsig>] -X <URL>\n"
		"     [--ext-user <user> --ext-key <key>] [more_options]\n"
		" %s verify --ver-key <logfile> [<logfile.logsig>] -P <URL>\n"
		"     [--cnstr <oid=value>]... [more_options]\n"
		" %s verify --ver-pub <logfile> [<logfile.logsig>] --pub-str <pubstr>\n"
		"     [-x -X <URL>  [--ext-user <user> --ext-key <key>]] [more_options]\n"
		" %s verify --ver-pub <logfile> [<logfile.logsig>] -P <URL> [--cnstr <oid=value>]...\n"
		"        [-x -X <URL>  [--ext-user <user> --ext-key <key>]] [more_options]\n"
		"\n"
		" --ver-int\n"
		"           - Perform internal verification.\n"
		" --ver-cal\n"
		"           - Perform calendar-based verification (use extending service).\n"
		" --ver-key\n"
		"           - Perform key-based verification.\n"
		" --ver-pub\n"
		"           - Perform publication-based verification (use with '-x' to permit extending).\n"
		" <logfile>\n"
		"           - Log file to be verified.\n"
		" <logfile.logsig>\n"
		"             Log signature file to be verified. If omitted, the log signature file name is\n"
		"             derived by adding either '.logsig' or '.gtsig' to '<logfile>'. The file is expected\n"
		"             to be found in the same folder as the '<logfile>'.\n"
		" <logfile.excerpt>\n"
		"           - Excerpt file to be verified.\n"
		" <logfile.excerpt.logsig>\n"
		"             Record integrity proof file to be verified. If omitted, the file name is\n"
		"             derived by adding '.logsig' to '<logfile>.excerpt'. It is expected to be found in the\n"
		"             same folder as the '<logfile>.excerpt'\n"
		" --log-from-stdin\n"
		"           - The log or excerpt file is read from stdin.\n"
		"             If '--log-from-stdin' is used, the log signature or integrity proof file name must\n"
		"             be specified explicitly.\n"
		" --        - If used, everything specified after the token is interpreted as\n"
		"             <logfile>. Note that log signature files can NOT be specified manually\n"
		"             and must have matching file names to log files. If multiple log files\n"
		"             are specified, both integrity and inter-linking between them is verified.\n"
		" --input-hash <hash>\n"
		"           - Specify hash imprint for inter-linking (the last leaf from the previous\n"
		"             log signature) verification. Hash can be specified on command line or\n"
		"             from a file containing its string representation. Hash format:\n"
		"             <alg>:<hash in hex>. Use '-' as file name to read the imprint from\n"
		"             stdin. Call logksi -h to get the list of supported hash algorithms.\n"
		"             See --output-hash to see how to extract the hash imprint from the previous\n"
		"             log signature. When used together with --, only the first log file is\n"
		"             verified against specified value.\n"
		" --output-hash <file>\n"
		"           - Output the last leaf from the log signature into file. Use '-' as\n"
		"             file name to redirect hash imprint to stdout. See --input-hash to\n"
		"             see how to verify that log signature is bound with this log signature\n"
		"             (where from the output hash was extracted). When used together with\n"
		"             '--', only the output hash of the last log file is returned.\n"
		"--ignore-desc-block-time\n"
		"           - Skip signing time verification where more recent log blocks must have\n"
		"             more recent (or equal) signing time than previous blocks.\n"
		"--warn-same-block-time\n"
		"           - Prints a warning when two consecutive blocks have same signing time.\n"
		"             When multiple log files are verified the last block from the previous\n"
		"             file is compared with the first block from the current file.\n"
		"--continue-on-fail\n"
		"           - This option can be used to continue verification to improve\n"
		"             debugging of verification errors. Other errors (e.g. IO error) will\n"
		"             terminated verification.\n"
		"--use-stored-hash-on-fail\n"
		"           - This options can be used to debug hash comparison failures, by\n"
		"             using stored hash values to continue verification process.\n"
		"--use-computed-hash-on-fail\n"
		"           - This options can be used to debug hash comparison failures, by\n"
		"             using computed hash values to continue verification process.\n"
		" -x\n"
		"           - Permit to use extender for publication-based verification.\n"
		" -X <URL>\n"
		"           - Extending service (KSI Extender) URL.\n"
		" --ext-user <user>\n"
		"           - Username for extending service.\n"
		" --ext-key <key>\n"
		"           - HMAC key for extending service.\n"
		" --ext-hmac-alg <alg>\n"
		"           - Hash algorithm to be used for computing HMAC on outgoing messages\n"
		"             towards KSI extender. If not set, default algorithm is used.\n"
		" -P <URL>\n"
		"           - Publications file URL (or file with URI scheme 'file://').\n"
		" --cnstr <oid=value>\n"
		"           - OID of the PKI certificate field (e.g. e-mail address) and the expected\n"
		"             value to qualify the certificate for verification of publications file\n"
		"             PKI signature. At least one constraint must be defined.\n"
		" --pub-str <str>\n"
		"           - Publication string to verify with.\n"
		" -V\n"
		"           - Certificate file in PEM format for publications file verification.\n"
		"             All values from lower priority sources are ignored.\n"
		" -d\n"
		"           - Print detailed information about processes and errors to stderr.\n"
		"             To make output more verbose use -dd or -ddd.\n"
		" --mdata-as-string\n"
		"           - Meta-data value is displayed as string. Non-printable characters\n"
		"             are displayed in hex with leading backslash.\n"
		" --conf <file>\n"
		"             Read configuration options from the given file.\n"
		"             Configuration options given explicitly on command line will\n"
		"             override the ones in the configuration file.\n"
		" --log <file>\n"
		"           - Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.\n",
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName()
	);

	return buf;
}

const char *verify_get_desc(void) {
	return "Verifies a signed log file using a log signature file.";
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

	PARAM_SET_addControl(set, "{conf}", isFormatOk_inputFile, isContentOk_inputFileRestrictPipe, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{log}{output-hash}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{input}{multiple_logs}", isFormatOk_inputFile, isContentOk_inputFileWithPipe, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{input-hash}", isFormatOk_inputHash, isContentOk_inputHash, convertRepair_path, extract_inputHashFromImprintOrImprintInFile);
	PARAM_SET_addControl(set, "{log-from-stdin}{d}{x}{ver-int}{ver-cal}{ver-key}{ver-pub}{use-computed-hash-on-fail}{use-stored-hash-on-fail}{continue-on-fail}{mdata-as-string}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{pub-str}", isFormatOk_pubString, NULL, NULL, extract_pubString);

	PARAM_SET_setParseOptions(set, "m", PST_PRSCMD_HAS_MULTIPLE_INSTANCES | PST_PRSCMD_BREAK_VALUE_WITH_EXISTING_PARAMETER_MATCH);

	/* Make input also collect same values as multiple_logs. It simplifies task handling. */
	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_COLLECT_WHEN_PARSING_IS_CLOSED |PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "multiple_logs", PST_PRSCMD_CLOSE_PARSING | PST_PRSCMD_COLLECT_WHEN_PARSING_IS_CLOSED | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "d,x", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "warn-same-block-time,ignore-desc-block-time,log-from-stdin,ver-int,ver-cal,ver-key,ver-pub,use-computed-hash-on-fail,use-stored-hash-on-fail,mdata-as-string", PST_PRSCMD_HAS_NO_VALUE);

	/*						ID						DESC								MAN							ATL		FORBIDDEN											IGN	*/
	TASK_SET_add(task_set,	ANC_BASED_DEFAULT,		"Verify, from file.",				"input",						NULL,	"log-from-stdin,ver-int,ver-cal,ver-key,ver-pub,P,cnstr,pub-str",	NULL);
	TASK_SET_add(task_set,	ANC_BASED_DEFAULT_STDIN,"Verify, from standard input",		"input,log-from-stdin",			NULL,	"ver-int,ver-cal,ver-key,ver-pub,P,cnstr,pub-str",	NULL);
	TASK_SET_add(task_set,	ANC_BASED_PUB_FILE,		"Verify, "
													"use publications file, "
													"extending is restricted.",			"input,P,cnstr",				NULL,	"ver-int,ver-cal,ver-key,ver-pub,x,T,pub-str",		NULL);
	TASK_SET_add(task_set,	ANC_BASED_PUB_FILE_X,	"Verify, "
													"use publications file, "
													"extending is permitted.",			"input,P,cnstr,x,X",			NULL,	"ver-int,ver-cal,ver-key,ver-pub,T,pub-str",		NULL);
	TASK_SET_add(task_set,	ANC_BASED_PUB_SRT,		"Verify, "
													"use publications string, "
													"extending is restricted.",			"input,pub-str",				NULL,	"ver-int,ver-cal,ver-key,ver-pub,x",				NULL);
	TASK_SET_add(task_set,	ANC_BASED_PUB_SRT_X,	"Verify, "
													"use publications string, "
													"extending is permitted.",			"input,pub-str,x,X",			NULL,	"ver-int,ver-cal,ver-key,ver-pub",					NULL);

	TASK_SET_add(task_set,	INT_BASED,				"Verify internally.",				"ver-int,input",				NULL,	"ver-cal,ver-key,ver-pub,T,x,pub-str",				NULL);

	TASK_SET_add(task_set,	CAL_BASED,				"Calendar based verification.",		"ver-cal,input,X",				NULL,	"ver-int,ver-key,ver-pub,pub-str",					NULL);

	TASK_SET_add(task_set,	KEY_BASED,				"Key based verification.",			"ver-key,input,P,cnstr",		NULL,	"ver-int,ver-cal,ver-pub,T,x,pub-str",				NULL);

	TASK_SET_add(task_set,	PUB_BASED_FILE,			"Publication based verification, "
													"use publications file, "
													"extending is restricted.",			"ver-pub,input,P,cnstr",		NULL,	"ver-int,ver-cal,ver-key,x,T,pub-str",				NULL);
	TASK_SET_add(task_set,	PUB_BASED_FILE_X,		"Publication based verification, "
													"use publications file, "
													"extending is permitted.",			"ver-pub,input,P,cnstr,x,X",	NULL,	"ver-int,ver-cal,ver-key,T,pub-str",				NULL);

	TASK_SET_add(task_set,	PUB_BASED_STR,			"Publication based verification, "
													"use publications string, "
													"extending is restricted.",			"ver-pub,input,pub-str",		NULL,	"ver-int,ver-cal,ver-key,x,T",						NULL);
	TASK_SET_add(task_set,	PUB_BASED_STR_X,		"Publication based verification, "
													"use publications string, "
													"extending is permitted.",			"ver-pub,input,pub-str,x,X",	NULL,	"ver-int,ver-cal,ver-key,T",						NULL);
cleanup:

	return res;
}

static void signature_set_suggestions_for_publication_based_verification(PARAM_SET *set, ERR_TRCKR *err, int errCode,
														   KSI_CTX *ksi, KSI_Signature *sig,
														   KSI_RuleVerificationResult *verRes, KSI_PublicationData *userPubData) {

	int res = KT_UNKNOWN_ERROR;
	KSI_PublicationRecord *rec = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_Integer *sigTime = NULL;
	KSI_Integer *userPubTime = NULL;
	KSI_Integer *latestPubTimeInPubfile = NULL;
	KSI_PublicationRecord *possibilityToExtendTo = NULL;
	int x = 0;
	int isExtendedToPublication = 0;
	int usePubfile = userPubData == NULL ? 1 : 0;

	if (verRes == NULL || verRes->errorCode != KSI_VER_ERR_GEN_2 || sig == NULL) return;


	x = PARAM_SET_isSetByName(set, "x");
	isExtendedToPublication = LOGKSI_Signature_isPublicationRecordPresent(sig);

	res = KSI_Signature_getSigningTime(sig, &sigTime);
	if (res != KSI_OK) return;

	/* Get publications file and check if it is possible to extend the signature to some available publication. */
	res = KSI_CTX_getPublicationsFile(ksi, &pubFile);
	if (res != KSI_OK) return;

	if (pubFile != NULL) {
		KSI_PublicationRecord *lastRec = NULL;
		KSI_PublicationData *lastRecData = NULL;

		res = KSI_PublicationsFile_getLatestPublication(pubFile, sigTime, &possibilityToExtendTo);
		if (res != KSI_OK) return;

		res = KSI_PublicationsFile_getLatestPublication(pubFile, NULL, &lastRec);
		if (res != KSI_OK) return;

		res = KSI_PublicationRecord_getPublishedData(lastRec, &lastRecData);
		if (res != KSI_OK) return;

		res = KSI_PublicationData_getTime(lastRecData, &latestPubTimeInPubfile);
		if (res != KSI_OK) return;
	}

	/* If there is user publication specified get its time. */
	if (!usePubfile && userPubData != NULL) {
		res = KSI_PublicationData_getTime(userPubData, &userPubTime);
	}

	if (!isExtendedToPublication && usePubfile) {
		if (possibilityToExtendTo != NULL && !x) {
			ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Use -x to permit automatic extending or use logksi extend command to extend the signature.\n");
		} else if (possibilityToExtendTo == NULL) {
			ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Check if publications file is up-to-date as there is not (yet) a publication record in the publications file specified to extend the signature to.\n");
			ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Wait until next publication and try again.\n");
			if (!x) ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  When a suitable publication is available use -x to permit automatic extending or use logksi extend command to extend the signature.\n");
		}

		/* Note that signature extended to some random time does not count as it is beyond normal usage. */
		ERR_TRCKR_ADD(err, errCode, "Error: Signature is not extended.");
	} else {


		if (usePubfile) {
			KSI_PublicationRecord *pubrecInPubfile = NULL;
			KSI_Integer *pubTime = NULL;
			int isPubfileOlderThanSig;

			/* Get the publication time. */
			res = KSI_Signature_getPublicationRecord(sig, &rec);
			if (res != KSI_OK) return;
			res = KSI_PublicationRecord_getPublishedData(rec, &pubData);
			if (res != KSI_OK) return;
			res = KSI_PublicationData_getTime(pubData, &pubTime);
			if (res != KSI_OK) return;

			isPubfileOlderThanSig = KSI_Integer_compare(latestPubTimeInPubfile, sigTime) == -1 ? 1 : 0;

			res = KSI_PublicationsFile_getPublicationDataByTime(pubFile, pubTime, &pubrecInPubfile);
			if (res != KSI_OK) return;

			if (pubrecInPubfile == NULL) {
				ERR_TRCKR_ADD(err, errCode, "Error: Signature is extended to a publication that does not exist in publications file.");

				if (possibilityToExtendTo == NULL && isPubfileOlderThanSig) {
					ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Check if publications file is up-to-date as the latest publication in the publications file is older than the signatures publication record.\n");
				} else if (possibilityToExtendTo != NULL && !x) {
					ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Try to use -x to permit automatic extending or use logksi extend command to re-extend the signature.\n");
				}
			}
		} else {
			if (KSI_Integer_compare(userPubTime, sigTime) == -1) {
				ERR_TRCKR_ADD(err, errCode, "Error: User publication string can not be older than the signatures signing time.");
				return;
			} else if (!x) {
				ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Use -x to permit automatic extending.\n");
			}
		}

	}
}

static void handle_verification_result(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ctx, KSI_Signature *sig, KSI_PublicationData *pubData, int res, const char *task_desc, KSI_PolicyVerificationResult *result) {
	KSI_RuleVerificationResult *verificationResult = NULL;

	if (KSI_RuleVerificationResultList_elementAt(
			result->ruleResults, KSI_RuleVerificationResultList_length(result->ruleResults) - 1,
			&verificationResult) == KSI_OK && verificationResult != NULL) {
			signature_set_suggestions_for_publication_based_verification(set, err, res, ctx, sig, verificationResult, pubData);

		ERR_TRCKR_ADD(err, res, "Error: [%s] %s. %s failed.",
				OBJPRINT_getVerificationErrorCode(verificationResult->errorCode),
				OBJPRINT_getVerificationErrorDescription(verificationResult->errorCode), task_desc);
	}
}

static int signature_verify_general(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files,
									KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	int x = PARAM_SET_isSetByName(set, "x");
	KSI_PublicationData *pub_data = NULL;
	static const char *task = "Signature verification according to trust anchor";
	COMPOSITE extra;

	extra.ctx = ksi;
	extra.err = err;
	extra.fname_out = NULL;

	/**
	 * Get Publication data if available.
	 */
	if (PARAM_SET_isSetByName(set, "pub-str")) {
		res = PARAM_SET_getObjExtended(set, "pub-str", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &extra, (void**)&pub_data);
		ERR_CATCH_MSG(err, res, "Error: Failed to get publication data.");
	}

	/**
	 * Verify signature.
	 */
	print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_3, "%s... ", task);
	res = LOGKSI_SignatureVerify_general(err, sig, ksi, hsh, rootLevel, pub_data, x, out);
	if (res != KSI_OK && *out != NULL) {
		handle_verification_result(set, err, ksi, sig, pub_data, res, task, *out);
		goto cleanup;
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	KSI_PublicationData_free(pub_data);

	return res;
}

static int signature_verify_internally(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files,
									   KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel,
									   KSI_PolicyVerificationResult **out) {
	int res;
	int d;
	static const char *task = "Signature internal verification";

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_3, "%s... ", task);
	res = LOGKSI_SignatureVerify_internally(err, sig, ksi, hsh, rootLevel, out);
	if (res != KSI_OK && *out != NULL) {
		handle_verification_result(set, err, ksi, sig, NULL, res, task, *out);
		goto cleanup;
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	return res;
}


static int signature_verify_key_based(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files,
									  KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel,
									  KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	static const char *task = "Signature key-based verification";

	/**
	 * Verify signature.
	 */
	print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_3, "%s... ", task);
	res = LOGKSI_SignatureVerify_keyBased(err, sig, ksi, hsh, rootLevel, out);
	if (res != KSI_OK && *out != NULL) {
		handle_verification_result(set, err, ksi, sig, NULL, res, task, *out);
		goto cleanup;
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	return res;
}

static int signature_verify_publication_based_with_user_pub(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files,
															KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	int x = PARAM_SET_isSetByName(set, "x");
	KSI_PublicationData *pub_data = NULL;
	static const char *task = "Signature publication-based verification with user publication string";
	COMPOSITE extra;

	extra.ctx = ksi;
	extra.err = err;
	extra.fname_out = NULL;

	/**
	 * Get Publication data.
	 */
	res = PARAM_SET_getObjExtended(set, "pub-str", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &extra, (void**)&pub_data);
	ERR_CATCH_MSG(err, res, "Error: Failed to get publication data.");

	/**
	 * Verify signature.
	 */
	print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_3, "%s... ", task);
	res = LOGKSI_SignatureVerify_userProvidedPublicationBased(err, sig, ksi, hsh, rootLevel, pub_data, x, out);
	if (res != KSI_OK && *out != NULL) {
		handle_verification_result(set, err, ksi, sig, pub_data, res, task, *out);
		goto cleanup;
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	KSI_PublicationData_free(pub_data);

	return res;
}

static int signature_verify_publication_based_with_pubfile(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files,
														   KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel,
														   KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	int x = PARAM_SET_isSetByName(set, "x");
	static const char *task = "Signature publication-based verification with publications file";

	/**
	 * Verify signature.
	 */
	print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_3, "%s... ", task);
	res = LOGKSI_SignatureVerify_publicationsFileBased(err, sig, ksi, hsh, rootLevel, x, out);
	if (res != KSI_OK && *out != NULL) {
		handle_verification_result(set, err, ksi, sig, NULL, res, task, *out);
		goto cleanup;
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	return res;
}

static int signature_verify_calendar_based(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files,
										   KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel,
										   KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	KSI_Integer *pubTime = NULL;
	static const char *task = "Signature calendar-based verification";

	/**
	 * Verify signature.
	 */
	print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_3, "%s... ", task);
	res = LOGKSI_SignatureVerify_calendarBased(err, sig, ksi, hsh, rootLevel, out);
	if (res != KSI_OK && *out != NULL) {
		handle_verification_result(set, err, ksi, sig, NULL, res, task, *out);
		goto cleanup;
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	KSI_Integer_free(pubTime);

	return res;
}

static int generate_filenames(ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;
	char *legacy_name = NULL;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (files->user.inLog) {
		res = duplicate_name(files->user.inLog, &tmp.internal.inLog);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate input log file name.");
	}

	/* If input log signature file name is not specified, it is generared from the input log file name. */
	if (files->user.inSig == NULL) {
		/* Generate input log signature file name. */
		res = concat_names(files->user.inLog, ".logsig", &tmp.internal.inSig);
		ERR_CATCH_MSG(err, res, "Error: Could not generate input log signature file name.");
		if (!SMART_FILE_doFileExist(tmp.internal.inSig)) {
			res = concat_names(files->user.inLog, ".gtsig", &legacy_name);
			ERR_CATCH_MSG(err, res, "Error: Could not generate input log signature file name.");
			if (SMART_FILE_doFileExist(legacy_name)) {
				KSI_free(tmp.internal.inSig);
				tmp.internal.inSig = legacy_name;
				legacy_name = NULL;
			}
		}
	} else {
		res = duplicate_name(files->user.inSig, &tmp.internal.inSig);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate input log signature file name.");
	}

	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

	KSI_free(legacy_name);
	logksi_internal_filenames_free(&tmp.internal);

	return res;
}

static int open_log_and_signature_files(ERR_TRCKR *err, IO_FILES *files) {
	int res = KT_IO_ERROR;
	IO_FILES tmp;

	memset(&tmp.files, 0, sizeof(tmp.files));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (files->internal.inLog) {
		res = SMART_FILE_open(files->internal.inLog, "rb", &tmp.files.inLog);
		ERR_CATCH_MSG(err, res, "Unable to open input log.")
	} else {
		res = SMART_FILE_open("-", "rbs", &tmp.files.inLog);
		ERR_CATCH_MSG(err, res, "Unable to open input log.")
	}

	if (files->internal.inSig) {
		res = SMART_FILE_open(files->internal.inSig, "rb", &tmp.files.inSig);
		ERR_CATCH_MSG(err, res, "Unable to open input signature.")
	} else {
		res = SMART_FILE_open("-", "rbs", &tmp.files.inSig);
		ERR_CATCH_MSG(err, res, "Unable to open input sig.")
	}

	files->files = tmp.files;
	memset(&tmp.files, 0, sizeof(tmp.files));

	res = KT_OK;

cleanup:

	logksi_files_close(&tmp.files);
	return res;
}

static void close_log_and_signature_files(IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);
		logksi_internal_filenames_free(&files->internal);
	}
}


static int save_output_hash(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *ioFiles, KSI_DataHash *hash, char * logFileName, char * sigFileName) {
	int res;
	SMART_FILE *out = NULL;

	if (set == NULL || err == NULL || ioFiles == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (PARAM_SET_isSetByName(set, "output-hash")) {
		char *fname = NULL;
		char buf[0xfff];
		char imprint[1024];
		size_t count = 0;
		size_t write_count = 0;

		if (hash == NULL) {
			res = KT_INVALID_CMD_PARAM;
			ERR_TRCKR_ADD(err, res, "Error: --output-hash does not work with excerpt signature file.");
			goto cleanup;
		}

		res = PARAM_SET_getStr(set, "output-hash", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &fname);
		ERR_CATCH_MSG(err, res, "Error: Unable to get file name for output hash.");

		LOGKSI_DataHash_toString(hash, imprint, sizeof(imprint));

		count += KSI_snprintf(buf + count, sizeof(buf) - count, "# Log file (%s).\n", ioFiles->previousLogFile);
		count += KSI_snprintf(buf + count, sizeof(buf) - count, "# Last leaf from previous log signature (%s).\n", ioFiles->previousSigFile);
		count += KSI_snprintf(buf + count, sizeof(buf) - count, "%s", imprint);


		res = SMART_FILE_open(fname, "ws", &out);
		ERR_CATCH_MSG(err, res, "Error: Unable to open file '%s'.", fname);

		res = SMART_FILE_write(out, (unsigned char*)buf, count, &write_count);
		ERR_CATCH_MSG(err, res, "Error: Unable to write to file '%s'.", fname);

		if (write_count != count) {
			res = KT_IO_ERROR;
			ERR_TRCKR_ADD(err, res, "Error: Only %zu bytes from %zu written.", write_count, count);
			goto cleanup;
		}
	}

	res = KT_OK;

cleanup:

	SMART_FILE_close(out);

	return res;
}

static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;

	res = get_pipe_out_error(set, err, NULL, "log,output-hash", "dump");
	if (res != KT_OK) goto cleanup;

	res = get_pipe_in_error(set, err, NULL, "input-hash", "log-from-stdin");
	if (res != KT_OK) goto cleanup;

cleanup:
	return res;
}

static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;
	int in_count = 0;
	int isMultipleLogFiles = 0;
	int isLogFromStdin = 0;

	if (set == NULL || err == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/**
	 * Get the count of inputs and outputs for error handling.
	 */
	res = PARAM_SET_getValueCount(set, "input", NULL, PST_PRIORITY_NONE, &in_count);
	if (res != PST_OK) goto cleanup;

	isMultipleLogFiles = PARAM_SET_isSetByName(set, "multiple_logs");
	isLogFromStdin = PARAM_SET_isSetByName(set, "log-from-stdin");

	if (isMultipleLogFiles) {
		if (isLogFromStdin) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: It is not possible to verify both log file from stdin (--log-from-stdin) and log file(s) specified after --!");
		}
	} else {
		if (isLogFromStdin && in_count > 1) ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Log file from stdin (--log-from-stdin) needs only ONE explicitly specified log signature file, but there are %i!", in_count);
		else if (in_count > 2) {
			 ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Only two inputs (log and log signature file) are required, but there are %i!", in_count);
			 ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  To verify multiple log files see parameter --.\n");
		}
	}

	if (res != KT_OK) goto cleanup;


	res = KT_OK;

cleanup:

	return res;
}

static int getLogFiles(PARAM_SET *set, ERR_TRCKR *err, int i, IO_FILES *files) {
	int res = KT_UNKNOWN_ERROR;
	int log_from_stdin = 0;


	if (set == NULL || err == NULL || i < 0) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	log_from_stdin = PARAM_SET_isSetByName(set, "log-from-stdin") ? 1 : 0;

	if (PARAM_SET_isSetByName(set, "multiple_logs")) {
		res = PARAM_SET_getStr(set, "multiple_logs", NULL, PST_PRIORITY_NONE, i, &files->user.inLog);
		if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

		files->user.inSig = NULL;
	} else if (PARAM_SET_isSetByName(set, "input")) {
		int count = 0;

		if (i > 0) {
			res = PST_PARAMETER_VALUE_NOT_FOUND;
			goto cleanup;
		}

		res = PARAM_SET_getValueCount(set, "input", NULL, PST_PRIORITY_NONE, &count);
		if (res != KT_OK) goto cleanup;

		if (!log_from_stdin) {
			res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, 0, &files->user.inLog);
			if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
		}

		if (count > (1 - log_from_stdin)) {
			res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, (1 - log_from_stdin), &files->user.inSig);
			if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
		}

	} else {
		res = PST_PARAMETER_EMPTY;
		goto cleanup;
	}



	res = KT_OK;

cleanup:

	return res;
}