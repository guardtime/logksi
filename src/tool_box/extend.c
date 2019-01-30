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
#include <unistd.h>
#include <errno.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include <ksi/policy.h>
#include "param_set/param_set.h"
#include "param_set/parameter.h"
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
#include "rsyslog.h"
#include <inttypes.h>

static int extend_to_nearest_publication(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext);
static int extend_to_specified_time(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext);
static int extend_to_specified_publication(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext);
static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err);
static int generate_filenames(ERR_TRCKR *err, IO_FILES *files);
static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files);
static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files);

enum {
	EXT_TO_EAV_PUBLICATION_FROM_FILE = 0x00,
	EXT_TO_EAV_PUBLICATION_FROM_STDIN = 0x01,
	EXT_TO_TIME_FROM_FILE = 0x02,
	EXT_TO_TIME_FROM_STDIN = 0x03,
	EXT_TO_SPEC_PUBLICATION_FROM_FILE = 0x04,
	EXT_TO_SPEC_PUBLICATION_FROM_STDIN = 0x05,
};

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
	EXTENDING_FUNCTION extend_signature = NULL;
	KSI_PublicationsFile *pubFile = NULL;
	MULTI_PRINTER *mp = NULL;

	IO_FILES_init(&files);

	/**
	 * Extract command line parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{input}{o}{sig-from-stdin}{enable-rfc3161-conversion}{d}{x}{T}{pub-str}{conf}{log}{h|help}", "XP", buf, sizeof(buf)),
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

	res = TASK_INITIALIZER_getPrinter(set, &mp);
	ERR_CATCH_MSG(err, res, "Error: Unable to create Multi printer!");

	res = TOOL_init_ksi(set, &ksi, &err, &logfile);
	if (res != KT_OK) goto cleanup;

	d = PARAM_SET_isSetByName(set, "d");

	res = check_pipe_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = check_io_naming_and_type_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.user.inLog);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.user.inSig);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	switch(TASK_getID(task)) {
		case EXT_TO_EAV_PUBLICATION_FROM_FILE:
		case EXT_TO_EAV_PUBLICATION_FROM_STDIN:
		case EXT_TO_SPEC_PUBLICATION_FROM_FILE:
		case EXT_TO_SPEC_PUBLICATION_FROM_STDIN:
				multi_print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_1, "%s", getPublicationsFileRetrieveDescriptionString(set));
				res = LOGKSI_receivePublicationsFile(err, ksi, &pubFile);
				ERR_CATCH_MSG(err, res, "Error: Unable to receive publications file.");
				multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

				if (!PARAM_SET_isSetByName(set, "publications-file-no-verify")) {
					multi_print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_1, "Verifying publications file... ");
					res = LOGKSI_verifyPublicationsFile(err, ksi, pubFile);
					ERR_CATCH_MSG(err, res, "Error: Unable to verify publications file.");
					multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
				}
		break;
	}

	switch(TASK_getID(task)) {
		case EXT_TO_EAV_PUBLICATION_FROM_FILE:
		case EXT_TO_EAV_PUBLICATION_FROM_STDIN:
			extend_signature = extend_to_nearest_publication;
		break;

		case EXT_TO_TIME_FROM_FILE:
		case EXT_TO_TIME_FROM_STDIN:
			extend_signature = extend_to_specified_time;
		break;

		case EXT_TO_SPEC_PUBLICATION_FROM_FILE:
		case EXT_TO_SPEC_PUBLICATION_FROM_STDIN:
			extend_signature = extend_to_specified_publication;
		break;

		default:
			res = KT_UNKNOWN_ERROR;
			goto cleanup;
		break;
	}

	res = generate_filenames(err, &files);
	if (res != KT_OK) goto cleanup;

	res = open_input_and_output_files(err, &files);
	if (res != KT_OK) goto cleanup;

	multi_print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_1, "Extending... ");
	res = logsignature_extend(set, mp, err, ksi, pubFile, extend_signature, &files);
	multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_1, res);
	if (res != KT_OK) goto cleanup;

	res = rename_temporary_and_backup_files(err, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	/* If there is an error while closing files, report it only if everything else was OK. */
	close_input_and_output_files(err, res, &files);

	MULTI_PRINTER_print(mp);
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

	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	ERR_TRCKR_free(err);
	KSI_PublicationsFile_free(pubFile);
	KSI_CTX_free(ksi);
	MULTI_PRINTER_free(mp);


	return LOGKSI_errToExitCode(res);
}
char *extend_help_toString(char*buf, size_t len) {
	KSI_snprintf(buf, len,
		"Usage:\n"
		" %s extend <logfile> [-o <out.logsig>] -X <URL>\n"
		"    [--ext-user <user> --ext-key <key>] -P <URL> [--cnstr <oid=value>]... [more_options]\n"
		" %s extend <logfile> [-o <out.logsig>] -X <URL>\n"
		"    [--ext-user <user> --ext-key <key>] -P <URL> [--cnstr <oid=value>]... [--pub-str <str>] [more_options]\n"
		" %s extend --sig-from-stdin [-o <out.logsig>] [more_options]\n"
		"\n"
		" <logfile>\n"
		"           - Name of the log file whose log signature file is to be extended. Log signature file name is\n"
		"             derived by adding either '.logsig' or '.gtsig' to '<logfile>'. The file is expected to be found in\n"
		"             the same folder as the '<logfile>'. If specified, the '--sig-from-stdin' switch cannot be used.\n"
		" --sig-from-stdin\n"
		"             The log signature file is read from stdin.\n"
		" -o <out.logsig>\n"
		"           - Name of the extended output log signature file. An existing log signature file is always overwritten.\n"
		"             If not specified, the log signature is saved to '<logfile>.logsig' while a backup of '<logfile>.logsig'\n"
		"             is saved in '<logfile>.logsig.bak'.\n"
		"             Use '-' to redirect the extended log signature binary stream to stdout.\n"
		"             If input is read from stdin and output is not specified, stdout is used for output.\n"
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
		"           - Publication record as publication string to extend the signature to.\n"
		" -V\n"
		"           - Certificate file in PEM format for publications file verification.\n"
		"             All values from lower priority sources are ignored.\n"
		" --enable-rfc3161-conversion\n"
		"           - Enable conversion, extending and replacing of RFC3161 timestamps with KSI signatures.\n"
		"             Note: this flag is not required if a different output log signature file name is specified\n"
		"             with '-o' to avoid overwriting of the original log signature file.\n"
		" -d\n"
		"           - Print detailed information about processes and errors to stderr.\n"
		"             To make output more verbose use -dd or -ddd.\n"
		" --conf <file>\n"
		"             Read configuration options from the given file.\n"
		"             Configuration options given explicitly on command line will\n"
		"             override the ones in the configuration file.\n"
		" --log <file>\n"
		"           - Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.\n",
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName()
	);

	return buf;
}
const char *extend_get_desc(void) {
	return "Extends KSI signatures in a log signature file to the desired publication.";
}
static int extend_to_nearest_publication(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext) {
	int res;
	KSI_Signature *tmp = NULL;
	KSI_Integer *sigTime = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	char buf[256];

	if (set == NULL || ksi == NULL || blocks == NULL || files == NULL || err == NULL || sig == NULL || ext == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_Signature_getSigningTime(sig, &sigTime);
	ERR_CATCH_MSG(err, res, "Error: Unable to get signing time.");

	res = KSI_PublicationsFile_getNearestPublication(pubFile, sigTime, &pubRec);
	ERR_CATCH_MSG(err, res, "Error: Unable to get earliest available publication from publications file.");



	if (pubRec == NULL) {
		multi_print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: extending KSI signature to the earliest available publication (na)... ", blocks->blockNo);
		multi_print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extending Block no. %3zu to the earliest available publication... ", blocks->blockNo);
		res = KSI_EXTEND_NO_SUITABLE_PUBLICATION;
		ERR_TRCKR_ADD(err, res, "No suitable publication found from publications file to extend the signature to (signing time %s (%llu)).", KSI_Integer_toDateString(sigTime, buf, sizeof(buf)), (unsigned long long)KSI_Integer_getUInt64(sigTime));
	} else {
		KSI_PublicationData *pubData = NULL;
		KSI_Integer *pubTime = NULL;

		res = KSI_PublicationRecord_getPublishedData(pubRec, &pubData);
		ERR_CATCH_MSG(err, res, "Error: Unable to get publication data.");

		res = KSI_PublicationData_getTime(pubData, &pubTime);
		ERR_CATCH_MSG(err, res, "Error: Unable to get publication time.");

		multi_print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: extending KSI signature to the earliest available publication: %s (%llu)... ", blocks->blockNo, KSI_Integer_toDateString(pubTime, buf, sizeof(buf)), (unsigned long long)KSI_Integer_getUInt64(pubTime));
		multi_print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extending Block no. %3zu to the earliest available publication... ", blocks->blockNo);
	}


	LOGKSI_Signature_extend(err, sig, ksi, pubRec, context, &tmp);

	ERR_CATCH_MSG(err, res, "Error: Unable to extend signature.");
	multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	*ext = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:
	multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	KSI_Signature_free(tmp);
	KSI_PublicationRecord_free(pubRec);

	return res;
}

static int extend_to_specified_time(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile* pubFile, KSI_VerificationContext *context, KSI_Signature **ext) {
	int res;
	KSI_Signature *tmp = NULL;
	KSI_Integer *pubTime = NULL;
	char buf[256];
	COMPOSITE extra;


	if (set == NULL || ksi == NULL || blocks == NULL || files == NULL || err == NULL || sig == NULL || ext == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	extra.ctx = ksi;
	extra.err = err;


	res = PARAM_SET_getObjExtended(set, "T", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &extra, (void**)&pubTime);
	if (res != KT_OK) {
		ERR_TRCKR_ADD(err, res, "Error: Unable to extract the time value to extend to.");
		goto cleanup;
	}

	/* Extend the signature. */

	multi_print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: extending KSI signature to time %s (%llu)... ",
		blocks->blockNo,
		KSI_Integer_toDateString(pubTime, buf, sizeof(buf)),
		(unsigned long long)KSI_Integer_getUInt64(pubTime));

	multi_print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extending Block no. %3zu to time %s (%llu)... ",
		blocks->blockNo,
		KSI_Integer_toDateString(pubTime, buf, sizeof(buf)),
		(unsigned long long)KSI_Integer_getUInt64(pubTime));
	res = LOGKSI_Signature_extendTo(err, sig, ksi, pubTime, context, &tmp);
	ERR_CATCH_MSG(err, res, "Error: Unable to extend signature.");
	multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	*ext = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:
	multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	KSI_Integer_free(pubTime);
	KSI_Signature_free(tmp);

	return res;
}

static int extend_to_specified_publication(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, BLOCK_INFO *blocks, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext) {
	int res;
	KSI_Signature *tmp = NULL;
	KSI_PublicationRecord *pub_rec = NULL;
	char *pubs_str = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *pubTime = NULL;
	char buf[256];

	if (set == NULL || ksi == NULL || blocks == NULL || files == NULL || err == NULL || sig == NULL || ext == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = PARAM_SET_getStr(set, "pub-str", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &pubs_str);
	ERR_CATCH_MSG(err, res, "Error: Unable get publication string.");

	multi_print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: Searching for a publication record from publications file... ", blocks->blockNo);
	res = KSI_PublicationsFile_getPublicationDataByPublicationString(pubFile, pubs_str, &pub_rec);
	ERR_CATCH_MSG(err, res, "Error: Unable get publication record from publications file.");
	if (pub_rec == NULL) {
		ERR_TRCKR_ADD(err, res = KT_PUBFILE_HAS_NO_PUBREC_TO_EXTEND_TO, "Error: Unable to extend signature as publication record not found from publications file.");
		goto cleanup;
	}
	multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	res = KSI_PublicationRecord_getPublishedData(pub_rec, &pubData);
	ERR_CATCH_MSG(err, res, "Error: Unable to get published data.");

	res = KSI_PublicationData_getTime(pubData, &pubTime);
	ERR_CATCH_MSG(err, res, "Error: Unable to get publication time.");

	multi_print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: extending KSI signature to the specified publication: %s (%llu)... ", blocks->blockNo, KSI_Integer_toDateString(pubTime, buf, sizeof(buf)), (unsigned long long)KSI_Integer_getUInt64(pubTime));
	multi_print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extending Block no. %3zu to the specified publication... ", blocks->blockNo);
	res = LOGKSI_Signature_extend(err, sig, ksi, pub_rec, context, &tmp);
	ERR_CATCH_MSG(err, res, "Error: Unable to extend signature.");
	multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	*ext = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:
	multi_print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

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
	PARAM_SET_addControl(set, "{input}", isFormatOk_inputFile, isContentOk_inputFileWithPipe, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{T}", isFormatOk_utcTime, isContentOk_utcTime, NULL, extract_utcTime);
	PARAM_SET_addControl(set, "{sig-from-stdin}{enable-rfc3161-conversion}{d}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{pub-str}", isFormatOk_pubString, NULL, NULL, extract_pubString);

	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "d", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "sig-from-stdin,enable-rfc3161-conversion", PST_PRSCMD_HAS_NO_VALUE);

	/**
	 * Define possible tasks.
	 */
	/*					  ID	DESC												MAN						ATL		FORBIDDEN			IGN	*/
	TASK_SET_add(task_set, EXT_TO_EAV_PUBLICATION_FROM_FILE,
								"Extend, "
								"from file, "
								"to the earliest available publication.",			"input,X,P",					NULL,	"sig-from-stdin,T,pub-str",	NULL);
	TASK_SET_add(task_set, EXT_TO_EAV_PUBLICATION_FROM_STDIN,
								"Extend, "
								"from standard input, "
								"to the earliest available publication.",			"sig-from-stdin,X,P",			NULL,	"input,T,pub-str",			NULL);
	TASK_SET_add(task_set, EXT_TO_TIME_FROM_FILE,
								"Extend, "
								"from file, "
								"to the specified time.",							"input,X,T",					NULL,	"sig-from-stdin,pub-str",	NULL);
	TASK_SET_add(task_set, EXT_TO_TIME_FROM_STDIN,
								"Extend, "
								"from standard input, "
								"to the specified time.",							"sig-from-stdin,X,T",			NULL,	"input,pub-str",			NULL);
	TASK_SET_add(task_set, EXT_TO_SPEC_PUBLICATION_FROM_FILE,
								"Extend, "
								"from file, "
								"to time specified in publications string.",		"input,X,P,pub-str",			NULL,	"sig-from-stdin,T",			NULL);
	TASK_SET_add(task_set, EXT_TO_SPEC_PUBLICATION_FROM_STDIN,
								"Extend, "
								"from standard input, "
								"to time specified in publications string.",		"sig-from-stdin,X,P,pub-str",	NULL,	"input,T",					NULL);

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

static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;
	int in_count = 0;

	if (set == NULL || err == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/**
	 * Get the count of inputs and outputs for error handling.
	 */
	res = PARAM_SET_getValueCount(set, "input", NULL, PST_PRIORITY_NONE, &in_count);
	if (res != PST_OK) goto cleanup;

	if (in_count > 1) {
		 ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Only one inputs (log file to locate its log signature file) is required, but there are %i!", in_count);
	}

	if (res != KT_OK) goto cleanup;


	res = KT_OK;

cleanup:

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

	/* If not specified, the input signature is read from stdin. */
	if (files->user.inLog == NULL) {
		if (files->user.inSig == NULL || !strcmp(files->user.inSig, "-")) {
			/* Output must go to a nameless temporary file before redirecting it to stdout. */
			tmp.internal.bStdout = 1;
		} else {
			/* Output must go to a named temporary file that is renamed appropriately on success. */
			res = temp_name(files->user.inSig, &tmp.internal.tempSig);
			ERR_CATCH_MSG(err, res, "Error: Could not generate temporary output log signature file name.");
			res = duplicate_name(files->user.inSig, &tmp.internal.outSig);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log signature file name.");
		}
	} else {
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

		/* Check if output would overwrite the input log signature file. */
		if (files->user.inSig == NULL || !strcmp(files->user.inSig, tmp.internal.inSig)) {
			/* Output must to go to a temporary file before overwriting the input log signature file. */
			res = temp_name(tmp.internal.inSig, &tmp.internal.tempSig);
			ERR_CATCH_MSG(err, res, "Error: Could not generate temporary output log signature file name.");
			/* Input must kept in a backup file when overwritten by the output log signature file. */
			res = concat_names(tmp.internal.inSig, ".bak", &tmp.internal.backupSig);
			ERR_CATCH_MSG(err, res, "Error: Could not generate backup input log signature file name.");
			tmp.internal.bOverwrite = 1;
		} else if (!strcmp(files->user.inSig, "-")) {
			/* Output must go to a nameless temporary file before redirecting it to stdout. */
			tmp.internal.bStdout = 1;
		} else {
			/* Output must go to a named temporary file that is renamed appropriately on success. */
			res = temp_name(files->user.inSig, &tmp.internal.tempSig);
			ERR_CATCH_MSG(err, res, "Error: Could not generate temporary output log signature file name.");
			res = duplicate_name(files->user.inSig, &tmp.internal.outSig);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log signature file name.");
		}
	}
	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

	KSI_free(legacy_name);
	logksi_internal_filenames_free(&tmp.internal);

	return res;
}

static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;

	memset(&tmp.files, 0, sizeof(tmp.files));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (files->internal.inSig) {
		res = logksi_file_check_and_open(err, files->internal.inSig, &tmp.files.inSig);
		if (res != KT_OK) goto cleanup;
	} else {
		/* If not specified, the input is taken from stdin. */
		tmp.files.inSig = stdin;
	}

	res = logksi_file_create_temporary(files->internal.tempSig, &tmp.files.outSig, files->internal.bStdout);
	ERR_CATCH_MSG(err, res, "Error: Could not create temporary output log signature file.");

	files->files = tmp.files;
	memset(&tmp.files, 0, sizeof(tmp.files));

	res = KT_OK;

cleanup:

	logksi_files_close(&tmp.files);
	return res;
}

static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files) {
	int res;

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Check if input log signature must be backed up. */
	if (files->internal.backupSig) {
		/* Create a backup of the input log signature file by renaming it. */
		logksi_file_close(&files->files.inSig);
		res = logksi_file_remove(files->internal.backupSig);
		ERR_CATCH_MSG(err, res, "Error: Could not remove existing backup file %s.", files->internal.backupSig);
		res = logksi_file_rename(files->internal.inSig, files->internal.backupSig);
		ERR_CATCH_MSG(err, res, "Error: Could not rename input log signature file %s to backup file %s.", files->internal.inSig, files->internal.backupSig);
		/* Output must be saved in input log signature file, so the temporary file is renamed. */
		logksi_file_close(&files->files.outSig);
		res = logksi_file_rename(files->internal.tempSig, files->internal.inSig);
		ERR_CATCH_MSG(err, res, "Error: Could not rename temporary file %s to input log signature file %s.", files->internal.tempSig, files->internal.inSig);
	} else if (files->internal.tempSig) {
		logksi_file_close(&files->files.inSig);
		res = logksi_file_remove(files->internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not remove existing output log signature file %s.", files->internal.outSig);
		/* Output must be saved in output log signature file, so the temporary file is renamed. */
		logksi_file_close(&files->files.outSig);
		res = logksi_file_rename(files->internal.tempSig, files->internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not rename temporary file %s to output log signature file %s.", files->internal.tempSig, files->internal.outSig);
	} else if (files->internal.bStdout) {
		res = logksi_file_redirect_to_stdout(files->files.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not write temporary output log signature file to stdout.");
	}

	logksi_filename_free(&files->internal.backupSig);
	res = KT_OK;

cleanup:

	/* Restore initial situation if something failed. */
	if (files && files->internal.backupSig) {
		if (!SMART_FILE_doFileExist(files->internal.inSig)) {
			res = logksi_file_rename(files->internal.backupSig, files->internal.inSig);
		}
	}
	return res;
}

static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);
		if (files->internal.tempSig && res != KT_OK) {
			if (remove(files->internal.tempSig) != 0) {
				if (err) ERR_TRCKR_ADD(err, KT_IO_ERROR, "Error: Could not remove temporary output log signature %s.", files->internal.tempSig);
			}
		}
		logksi_internal_filenames_free(&files->internal);
	}
}
