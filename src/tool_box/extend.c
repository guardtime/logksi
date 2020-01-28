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
#include <param_set/param_set.h>
#include <param_set/parameter.h>
#include <param_set/task_def.h>
#include <param_set/strn.h>
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
#include "io_files.h"

static int extend_to_nearest_publication(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext);
static int extend_to_specified_time(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext);
static int extend_to_specified_publication(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext);
static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err);
static int generate_filenames(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static int open_input_and_output_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files);

#define PARAMS "{input}{o}{sig-from-stdin}{enable-rfc3161-conversion}{d}{x}{T}{pub-str}{conf}{log}{h|help}{hex-to-str}"

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
			CONF_generate_param_set_desc(PARAMS, "XP", buf, sizeof(buf)),
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

	switch(TASK_getID(task)) {
		case EXT_TO_EAV_PUBLICATION_FROM_FILE:
		case EXT_TO_EAV_PUBLICATION_FROM_STDIN:
		case EXT_TO_SPEC_PUBLICATION_FROM_FILE:
		case EXT_TO_SPEC_PUBLICATION_FROM_STDIN:
				print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_1, "%s", getPublicationsFileRetrieveDescriptionString(set));
				res = LOGKSI_receivePublicationsFile(err, ksi, &pubFile);
				ERR_CATCH_MSG(err, res, "Error: Unable to receive publications file.");
				print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

				if (!PARAM_SET_isSetByName(set, "publications-file-no-verify")) {
					print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_1, "Verifying publications file... ");
					res = LOGKSI_verifyPublicationsFile(err, ksi, pubFile);
					ERR_CATCH_MSG(err, res, "Error: Unable to verify publications file.");
					print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);
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

	res = generate_filenames(set, err, &files);
	if (res != KT_OK) goto cleanup;

	res = open_input_and_output_files(set, err, &files);
	if (res != KT_OK) goto cleanup;

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_1, "Extending... ");
	res = logsignature_extend(set, mp, err, ksi, pubFile, extend_signature, &files);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_1, res);
	if (res != KT_OK) goto cleanup;

	res = rename_temporary_and_backup_files(err, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	/* If there is an error while closing files, report it only if everything else was OK. */
	close_input_and_output_files(err, res, &files);

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
	}
	ERR_TRCKR_print(err, d);

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
	int res;
	char *ret = NULL;
	PARAM_SET *set;
	size_t count = 0;
	char tmp[1024];

	if (buf == NULL || len == 0) return NULL;


	/* Create set with documented parameters. */
	res = PARAM_SET_new(CONF_generate_param_set_desc(PARAMS, "XP", tmp, sizeof(tmp)), &set);
	if (res != PST_OK) goto cleanup;

	res = CONF_initialize_set_functions(set, "XP");
	if (res != PST_OK) goto cleanup;

	/* Temporary name change for formatting help text. */
	PARAM_SET_setPrintName(set, "input", "<logfile>", NULL);
	PARAM_SET_setHelpText(set, "input", NULL, "Name of the log file whose log signature file is to be extended. Log signature file name is derived by adding either '.logsig' or '.gtsig' to '<logfile>'. The file is expected to be found in the same folder as the '<logfile>'. If specified, the '--sig-from-stdin' switch cannot be used.");
	PARAM_SET_setHelpText(set, "sig-from-stdin", NULL, "The log signature file is read from stdin.");
	PARAM_SET_setHelpText(set, "o", "<out.logsig>", "Name of the extended output log signature file. An existing log signature file is always overwritten. If not specified, the log signature is saved to '<logfile>.logsig' while a backup of '<logfile>.logsig' is saved in '<logfile>.logsig.bak'. Use '-' to redirect the extended log signature binary stream to stdout. If input is read from stdin and output is not specified, stdout is used for output.");
	PARAM_SET_setHelpText(set, "pub-str", "<str>", "Publication record as publication string to extend the signature to.");
	PARAM_SET_setHelpText(set, "enable-rfc3161-conversion", NULL, "Enable conversion, extending and replacing of RFC3161 timestamps with KSI signatures. Note: this flag is not required if a different output log signature file name is specified with '-o' to avoid overwriting of the original log signature file.");
	PARAM_SET_setHelpText(set, "d", NULL, "Print detailed information about processes and errors to stderr. To make output more verbose use -dd or -ddd.");
	PARAM_SET_setHelpText(set, "conf", NULL, "Read configuration options from the given file. Configuration options given explicitly on command line will override the ones in the configuration file.");
	PARAM_SET_setHelpText(set, "log", NULL, "Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.");


	/* Format synopsis and parameters. */
	count += PST_snhiprintf(buf + count, len - count, 80, 0, 0, NULL, ' ', "Usage:\\>1\n\\>8"
	"logksi extend <logfile> [-o <out.logsig>] -X <URL> [--ext-user <user>\n"
	"--ext-key <key>] -P <URL> [--cnstr <oid=value>]... [more_options]\\>1\n\\>8"
	"logksi extend <logfile> [-o <out.logsig>] -X <URL> [--ext-user <user>\n"
	"--ext-key <key>] -P <URL> [--cnstr <oid=value>]... [--pub-str <str>] [more_options]\\>1\n\\>8"
	"logksi extend --sig-from-stdin [-o <out.logsig>] [more_options]"
	"\\>\n\n\n");

	ret = PARAM_SET_helpToString(set, "input,sig-from-stdin,o,X,ext-user,ext-key,ext-hmac-alg,P,cnstr,pub-str,V,enable-rfc3161-conversion,d,conf,log", 1, 13, 80, buf + count, len - count);

cleanup:
	if (res != PST_OK || ret == NULL) {
		PST_snprintf(buf + count, len - count, "\nError: There were failures while generating help by PARAM_SET.\n");
	}
	PARAM_SET_free(set);
	return buf;
}
const char *extend_get_desc(void) {
	return "Extends KSI signatures in a log signature file to the desired publication.";
}
static int extend_to_nearest_publication(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext) {
	int res;
	KSI_Signature *tmp = NULL;
	KSI_Integer *sigTime = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	char buf[256];

	if (set == NULL || ksi == NULL || logksi == NULL || files == NULL || err == NULL || sig == NULL || ext == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_Signature_getSigningTime(sig, &sigTime);
	ERR_CATCH_MSG(err, res, "Error: Unable to get signing time.");

	res = KSI_PublicationsFile_getNearestPublication(pubFile, sigTime, &pubRec);
	ERR_CATCH_MSG(err, res, "Error: Unable to get earliest available publication from publications file.");



	if (pubRec == NULL) {
		print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: extending KSI signature to the earliest available publication (na)... ", logksi->blockNo);
		print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extending Block no. %3zu to the earliest available publication... ", logksi->blockNo);
		res = KSI_EXTEND_NO_SUITABLE_PUBLICATION;
		ERR_TRCKR_ADD(err, res, "No suitable publication found from publications file to extend the signature to (signing time %s (%llu)).", KSI_Integer_toDateString(sigTime, buf, sizeof(buf)), (unsigned long long)KSI_Integer_getUInt64(sigTime));
	} else {
		KSI_PublicationData *pubData = NULL;
		KSI_Integer *pubTime = NULL;

		res = KSI_PublicationRecord_getPublishedData(pubRec, &pubData);
		ERR_CATCH_MSG(err, res, "Error: Unable to get publication data.");

		res = KSI_PublicationData_getTime(pubData, &pubTime);
		ERR_CATCH_MSG(err, res, "Error: Unable to get publication time.");

		print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: extending KSI signature to the earliest available publication: %s (%llu)... ", logksi->blockNo, KSI_Integer_toDateString(pubTime, buf, sizeof(buf)), (unsigned long long)KSI_Integer_getUInt64(pubTime));
		print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extending Block no. %3zu to the earliest available publication... ", logksi->blockNo);
	}


	res = LOGKSI_Signature_extend(err, sig, ksi, pubRec, context, &tmp);
	ERR_CATCH_MSG(err, res, "Error: Unable to extend signature.");
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	*ext = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	KSI_Signature_free(tmp);
	KSI_PublicationRecord_free(pubRec);

	return res;
}

static int extend_to_specified_time(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile* pubFile, KSI_VerificationContext *context, KSI_Signature **ext) {
	int res;
	KSI_Signature *tmp = NULL;
	KSI_Integer *pubTime = NULL;
	char buf[256];
	COMPOSITE extra;


	if (set == NULL || ksi == NULL || logksi == NULL || files == NULL || err == NULL || sig == NULL || ext == NULL) {
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

	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: extending KSI signature to time %s (%llu)... ",
		logksi->blockNo,
		KSI_Integer_toDateString(pubTime, buf, sizeof(buf)),
		(unsigned long long)KSI_Integer_getUInt64(pubTime));

	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extending Block no. %3zu to time %s (%llu)... ",
		logksi->blockNo,
		KSI_Integer_toDateString(pubTime, buf, sizeof(buf)),
		(unsigned long long)KSI_Integer_getUInt64(pubTime));
	res = LOGKSI_Signature_extendTo(err, sig, ksi, pubTime, context, &tmp);
	ERR_CATCH_MSG(err, res, "Error: Unable to extend signature.");
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	*ext = tmp;
	tmp = NULL;

	res = KT_OK;

cleanup:
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	KSI_Integer_free(pubTime);
	KSI_Signature_free(tmp);

	return res;
}

static int extend_to_specified_publication(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files, KSI_Signature *sig, KSI_PublicationsFile *pubFile, KSI_VerificationContext *context, KSI_Signature **ext) {
	int res;
	KSI_Signature *tmp = NULL;
	KSI_PublicationRecord *pub_rec = NULL;
	char *pubs_str = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *pubTime = NULL;
	char buf[256];

	if (set == NULL || ksi == NULL || logksi == NULL || files == NULL || err == NULL || sig == NULL || ext == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = PARAM_SET_getStr(set, "pub-str", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &pubs_str);
	ERR_CATCH_MSG(err, res, "Error: Unable get publication string.");

	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_3, "Block no. %3zu: Searching for a publication record from publications file... ", logksi->blockNo);
	res = KSI_PublicationsFile_getPublicationDataByPublicationString(pubFile, pubs_str, &pub_rec);
	ERR_CATCH_MSG(err, res, "Error: Unable get publication record from publications file.");
	if (pub_rec == NULL) {
		ERR_TRCKR_ADD(err, res = KT_PUBFILE_HAS_NO_PUBREC_TO_EXTEND_TO, "Error: Unable to extend signature as publication record not found from publications file.");
		goto cleanup;
	}
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	res = KSI_PublicationRecord_getPublishedData(pub_rec, &pubData);
	ERR_CATCH_MSG(err, res, "Error: Unable to get published data.");

	res = KSI_PublicationData_getTime(pubData, &pubTime);
	ERR_CATCH_MSG(err, res, "Error: Unable to get publication time.");

	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_LEVEL_3, "Block no. %3zu: extending KSI signature to the specified publication: %s (%llu)... ", logksi->blockNo, KSI_Integer_toDateString(pubTime, buf, sizeof(buf)), (unsigned long long)KSI_Integer_getUInt64(pubTime));
	print_progressDesc(mp, MP_ID_BLOCK, 1, DEBUG_EQUAL | DEBUG_LEVEL_2, "Extending Block no. %3zu to the specified publication... ", logksi->blockNo);
	res = LOGKSI_Signature_extend(err, sig, ksi, pub_rec, context, &tmp);
	ERR_CATCH_MSG(err, res, "Error: Unable to extend signature.");
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

	*ext = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res);

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
	PARAM_SET_addControl(set, "{sig-from-stdin}{enable-rfc3161-conversion}{d}{hex-to-str}", isFormatOk_flag, NULL, NULL, NULL);
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

static int generate_filenames(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;
	char *legacy_name = NULL;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files->user.inLog);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files->user.outSig);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	/* Get input signature file name. */
	if (files->user.inLog == NULL) {
		/* If not specified, the input signature is read from stdin. */
		/* If log file is not specified and o is not specified get input signature from stdin. */
		if (PARAM_SET_isSetByName(set, "sig-from-stdin")) {
			res = duplicate_name("-", &tmp.internal.inSig);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log signature file name.");
		}
		/* If input is not '-' it must be explicitly specified file name. */
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
	}

	/* Get Output signature file name. */
	if (files->user.outSig == NULL && tmp.internal.inSig != NULL) {
		res = duplicate_name(tmp.internal.inSig, &tmp.internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log signature file name.");
		tmp.internal.bOverwrite = 1;
	} else {
		res = duplicate_name(files->user.outSig, &tmp.internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log signature file name.");
	}

	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

	KSI_free(legacy_name);
	logksi_internal_filenames_free(&tmp.internal);

	return res;
}

static int open_input_and_output_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;
	int overWrite = 0;

	memset(&tmp.files, 0, sizeof(tmp.files));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	overWrite = PARAM_SET_isSetByName(set, "o");

	if (files->internal.inSig) {
		res = SMART_FILE_open(files->internal.inSig, "rbs", &tmp.files.inSig);
		ERR_CATCH_MSG(err, res, "Error: Could not open input signature file '%s'.", files->internal.inSig);
	} else {
		res = SMART_FILE_open("-", "rbs", &tmp.files.inSig);	/* A buffered (nameless temporary file) stream. */
		ERR_CATCH_MSG(err, res, "Error: Could not open input signature stream.");
	}

	res = SMART_FILE_open(files->internal.outSig, overWrite ? "wbTs" : "wbBTs", &tmp.files.outSig);
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

	/* Close input file first, so it is possible to make a backup of it or overwrite it. */
	logksi_file_close(&files->files.inSig);

	res = SMART_FILE_markConsistent(files->files.outSig);
	ERR_CATCH_MSG(err, res, "Error: Could not close output log signature file %s.", files->internal.outSig);
	logksi_file_close(&files->files.outSig);

	res = KT_OK;

cleanup:

	return res;
}

static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);
		logksi_internal_filenames_free(&files->internal);
	}
}
