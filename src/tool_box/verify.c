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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <ksi/ksi.h>
#include <ksi/err.h>
#include <ksi/compatibility.h>
#include <ksi/policy.h>
#include <param_set/param_set.h>
#include <param_set/task_def.h>
#include <param_set/parameter.h>
#include <param_set/strn.h>
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
#include "logksi.h"
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
	/* Calendar-based verification. */
	CAL_BASED,
	KEY_BASED,
	/* Publication-based verification, use publications file. */
	PUB_BASED_FILE,
	PUB_BASED_FILE_X,
	/* Publication-based verification, use publication string. */
	PUB_BASED_STR,
	PUB_BASED_STR_X
};

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);

static int signature_verify_general(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_internally(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_key_based(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_publication_based_with_user_pub(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_publication_based_with_pubfile(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi,  LOGKSI *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int signature_verify_calendar_based(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *blocks, IO_FILES *files, KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out);
static int generate_filenames(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, IO_FILES *files);
static int open_log_and_signature_files(ERR_TRCKR *err, IO_FILES *files);
static void close_log_and_signature_files(IO_FILES *files);
static int getLogFiles(PARAM_SET *set, ERR_TRCKR *err, int i, IO_FILES *files);

#define PARAMS "{log-file-list}{log-file-list-delimiter}{sig-dir}{warn-same-block-time}{warn-client-id-change}{ignore-desc-block-time}{logfile}{multiple_logs}{input}{input-hash}{client-id}{output-hash}{log-from-stdin}{x}{d}{pub-str}{ver-int}{ver-cal}{ver-key}{ver-pub}{use-computed-hash-on-fail}{use-stored-hash-on-fail}{continue-on-fail}{conf}{time-form}{time-base}{time-diff}{time-disordered}{block-time-diff}{log}{h|help}{hex-to-str}"

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
	LOGKSI logksi;
	MULTI_PRINTER *mp = NULL;
	uint64_t las_rec_time = 0;

	LOGKSI_initialize(&logksi);
	IO_FILES_init(&files);
	/**
	 * Extract command line parameters and also add configuration specific parameters.
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

	res = extract_input_files_from_file(set, mp, err);
	if (res != PST_OK) goto cleanup;

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
		ERR_CATCH_MSG(err, res, "Error: Unable to extract input hash value!");
	}

	do {
		res = getLogFiles(set, err, i, &files);
		 if (res == PST_PARAMETER_VALUE_NOT_FOUND) {
			res = KT_OK;
			break;
		}
		ERR_CATCH_MSG(err, res, "Error: Unable to get file names for log and log signature file.");


		res = generate_filenames(set, mp, err, &files);
		if (res != KT_OK) goto cleanup;

		res = open_log_and_signature_files(err, &files);
		if (res != KT_OK) goto cleanup;

		if (isMultipleLog) {
			print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "%sLog file '%s'.\n", (i == 0 ? "" : "\n"), files.internal.inLog);
		}

		logksi.file.recTimeMax = las_rec_time;

		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_1, "Verifying... ");
		res = logsignature_verify(set, mp, err, ksi, &logksi, inputHash, verify_signature, &files, &outputHash, &las_rec_time);
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



	if (PARAM_SET_isSetByName(set, "output-hash")) {
		char *fname = NULL;

		res = PARAM_SET_getStr(set, "output-hash", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &fname);
		ERR_CATCH_MSG(err, res, "Error: Unable to get file name for output hash.");

		if (pLastOutputHash == NULL) {
			res = KT_INVALID_CMD_PARAM;
			ERR_TRCKR_ADD(err, res, "Error: --output-hash does not work with excerpt signature file.");
			goto cleanup;
		}

		res = logksi_save_output_hash(err, pLastOutputHash, fname, files.previousLogFile, files.previousSigFileIn);
		if (res != KT_OK) goto cleanup;
	}

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
	}
	ERR_TRCKR_print(err, d);

	KSI_DataHash_free(inputHash);
	KSI_DataHash_free(outputHash);
	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	KSI_Signature_free(sig);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);
	MULTI_PRINTER_free(mp);

	return LOGKSI_errToExitCode(res);
}

char *verify_help_toString(char *buf, size_t len) {
	int res;
	char *ret = NULL;
	PARAM_SET *set;
	size_t count = 0;
	char tmp[1024];

	if (buf == NULL || len == 0) return NULL;


	/* Create set with documented parameters. */
	res = PARAM_SET_new(CONF_generate_param_set_desc(PARAMS "{logsig}{exerpt-log}{exerpt-proof}", "XP", tmp, sizeof(tmp)), &set);
	if (res != PST_OK) goto cleanup;

	res = CONF_initialize_set_functions(set, "XP");
	if (res != PST_OK) goto cleanup;

	/* Temporary name change for formatting help text. */
	PARAM_SET_setPrintName(set, "multiple_logs", "--", NULL);
	PARAM_SET_setPrintName(set, "input", "<logfile>", NULL);
	PARAM_SET_setHelpText(set, "input", NULL, "Log file from where to extract log records.");

	/* Note that logsig, exerpt-log and exerpt-proof are not a real parameter, that are used to format help! */
	PARAM_SET_setPrintName(set, "logsig", "<logfile.logsig>", NULL);
	PARAM_SET_setPrintName(set, "exerpt-log", "<logfile.excerpt>", NULL);
	PARAM_SET_setPrintName(set, "exerpt-proof", "<logfile.excerpt.logsig>", NULL);

	PARAM_SET_setHelpText(set, "ver-int", NULL, "Perform internal verification.");
	PARAM_SET_setHelpText(set, "ver-cal", NULL, "Perform calendar-based verification (use extending service).");
	PARAM_SET_setHelpText(set, "ver-key", NULL, "Perform key-based verification.");
	PARAM_SET_setHelpText(set, "ver-pub", NULL, "Perform publication-based verification (use with '-x' to permit extending).");
	PARAM_SET_setHelpText(set, "input", NULL, "Log file to be verified.");
	PARAM_SET_setHelpText(set, "logsig", NULL, "Log signature file to be verified. If omitted, the log signature file name is derived by adding either '.logsig' or '.gtsig' to '<logfile>'. The file is expected to be found in the same folder as the '<logfile>'.");
	PARAM_SET_setHelpText(set, "exerpt-log", NULL, "Excerpt file to be verified.");
	PARAM_SET_setHelpText(set, "exerpt-proof", NULL, "Record integrity proof file to be verified. If omitted, the file name is derived by adding '.logsig' to '<logfile>.excerpt'. It is expected to be found in the same folder as the '<logfile>.excerpt'");
	PARAM_SET_setHelpText(set, "log-from-stdin", NULL, "The log or excerpt file is read from stdin. If '--log-from-stdin' is used, the log signature or integrity proof file name must be specified explicitly.");
	PARAM_SET_setHelpText(set, "multiple_logs", NULL, "If used, everything specified after the token is interpreted as <logfile>. Note that log signature files can NOT be specified manually and must have matching file names to log files. If multiple log files are specified, both integrity and inter-linking between them is verified.");
	PARAM_SET_setHelpText(set, "input-hash", "<hash>", "Specify hash imprint for inter-linking (the last leaf from the previous log signature) verification. Hash can be specified on command line or a file containing its string representation. Hash format: <alg>:<hash in hex>. Use '-' as file name to read the imprint from stdin. Call logksi -h to get the list of supported hash algorithms. See --output-hash to see how to extract the hash imprint from the previous log signature. When used together with --, only the first log file is verified against specified value.");
	PARAM_SET_setHelpText(set, "output-hash", "<file>", "Output the last leaf from the log signature into file. Use '-' as file name to redirect hash imprint to stdout. See --input-hash to see how to verify that log signature is bound with this log signature (where from the output hash was extracted). When used together with '--', only the output hash of the last log file is returned.");
	PARAM_SET_setHelpText(set, "ignore-desc-block-time", NULL, "Skip signing time verification where more recent log blocks must have more recent (or equal) signing time than previous blocks.");
	PARAM_SET_setHelpText(set, "client-id", "<regexp>", "Verifies if KSI signatures client ID is matching regular expression specified.");
	PARAM_SET_setHelpText(set, "time-form", "<fmt>", "Format string fmt is used to extract time stamp from the beginning of the log line to be matched with KSI signature signing time. Fmt is specified by function strptime and its documentation can be read for more details.");
	PARAM_SET_setHelpText(set, "time-base", "<year>", "Specify the year (e.g. 2019) when it can not be extracted with --time-form.");
	PARAM_SET_setHelpText(set, "time-diff", "<time>", "A specified time difference that with the signing time of the KSI signature forms a valid time window where all the log records must fit. Also the chronological order of the log records is checked. The difference can be specified as seconds (e.g 86400) or using integers followed by markers (e.g. 10d2H3M1S), where d, H, M and S stand for day, hour, minute and second accordingly.");
	PARAM_SET_setHelpText(set, "time-disordered", "<time>", "Will permit log records to be disordered within specified range (e.g. with value 1 following sequence of time values is correct: 1, 3, 2, 4).");
	PARAM_SET_setHelpText(set, "warn-client-id-change", NULL, "Will warn the user if KSI signatures client ID is not constant over all the blocks.");
	PARAM_SET_setHelpText(set, "warn-same-block-time", NULL, "Prints a warning when two consecutive blocks have same signing time. When multiple log files are verified the last block from the previous file is compared with the first block from the current file.");
	PARAM_SET_setHelpText(set, "continue-on-fail", NULL, "Can be used to continue verification to improve debugging of verification errors. Other errors (e.g. IO error) will terminated verification.");
	PARAM_SET_setHelpText(set, "use-stored-hash-on-fail", NULL, "Can be used to debug hash comparison failures, by using stored hash values to continue verification process.");
	PARAM_SET_setHelpText(set, "use-computed-hash-on-fail", NULL, "Can be used to debug hash comparison failures, by using computed hash values to continue verification process.");
	PARAM_SET_setHelpText(set, "x", NULL, "Permit to use extender for publication-based verification.");
	PARAM_SET_setHelpText(set, "pub-str", "<str>", "Publication string to verify with.");
	PARAM_SET_setHelpText(set, "d", NULL, "Print detailed information about processes and errors to stderr. To make output more verbose use -dd or -ddd.");
	PARAM_SET_setHelpText(set, "hex-to-str", NULL, "Will encode applicable hex encoded data fields to ASCII string (e.g. meta-record value). Non-printable characters are displayed in hex with leading backslash (e.g. 'Text\\00').");
	PARAM_SET_setHelpText(set, "conf", NULL, "Read configuration options from the given file. Configuration options given explicitly on command line will override the ones in the configuration file.");
	PARAM_SET_setHelpText(set, "log", NULL, "Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.");


	/* Format synopsis and parameters. */
	count += PST_snhiprintf(buf + count, len - count, 80, 0, 0, NULL, ' ', "Usage:\\>1\n\\>8"
	"logksi verify <logfile> [<logfile.logsig>] [more_options]\\>1\n\\>8"
	"logksi verify --log-from-stdin <logfile.logsig> [more_options]\\>1\n\\>8"
	"logksi verify <logfile>.excerpt [<logfile.excerpt.logsig>] [more_options]\\>1\n\\>8"
	"logksi verify --log-from-stdin <logfile.excerpt.logsig> [more_options]\\>1\n\\>8"
	"logksi verify --ver-int <logfile> [<logfile.logsig>] [more_options]\\>1\n\\>8"
	"logksi verify --ver-cal <logfile> [<logfile.logsig>] -X <URL>\n"
	"[--ext-user <user> --ext-key <key>] [more_options]\\>1\n\\>8"
	"logksi verify --ver-key <logfile> [<logfile.logsig>] -P <URL>\n"
	"[--cnstr <oid=value>]... [more_options]\\>1\n\\>8"
	"logksi verify --ver-pub <logfile> [<logfile.logsig>] --pub-str <pubstr>\n"
	"[-x -X <URL>  [--ext-user <user> --ext-key <key>]] [more_options]\\>1\n\\>8"
	"logksi verify --ver-pub <logfile> [<logfile.logsig>] -P <URL> [--cnstr <oid=value>]... [-x -X <URL>  [--ext-user <user> --ext-key <key>]] [more_options]"
	"\\>\n\n\n");

	ret = PARAM_SET_helpToString(set, "ver-int,ver-cal,ver-key,ver-pub,input,logsig,exerpt-log,exerpt-proof,log-from-stdin,multiple_logs,input-hash,output-hash,ignore-desc-block-time,client-id,time-form,time-base,time-diff,time-disordered,warn-client-id-change,warn-same-block-time,continue-on-fail,use-stored-hash-on-fail,use-computed-hash-on-fail,x,X,ext-user,ext-key,ext-hmac-alg,P,cnstr,pub-str,V,d,hex-to-str,conf,log", 1, 13, 80, buf + count, len - count);

cleanup:
	if (res != PST_OK || ret == NULL) {
		PST_snprintf(buf + count, len - count, "\nError: There were failures while generating help by PARAM_SET.\n");
	}
	PARAM_SET_free(set);
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

	PARAM_SET_setPrintName(set, "logfile", "--input", NULL);
	PARAM_SET_setPrintName(set, "multiple_logs", "--input", NULL);
	PARAM_SET_addControl(set, "{conf}", isFormatOk_inputFile, isContentOk_inputFileRestrictPipe, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{log}{output-hash}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{logfile}{multiple_logs}", isFormatOk_inputFile, isContentOk_inputFileNoDir, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{sig-dir}", isFormatOk_inputFile, isContentOk_dir, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{input-hash}", isFormatOk_inputHash, isContentOk_inputHash, convertRepair_path, extract_inputHashFromImprintOrImprintInFile);
	PARAM_SET_addControl(set, "{log-from-stdin}{d}{x}{ver-int}{ver-cal}{ver-key}{ver-pub}{use-computed-hash-on-fail}{use-stored-hash-on-fail}{continue-on-fail}{hex-to-str}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{pub-str}", isFormatOk_pubString, NULL, NULL, extract_pubString);
	PARAM_SET_addControl(set, "client-id,time-form", isFormatOk_string, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "time-base", isFormatOk_int, isContentOk_uint, NULL, extract_int);
	PARAM_SET_addControl(set, "time-diff", isFormatOk_timeDiff, NULL, NULL, extract_timeDiff);
	PARAM_SET_addControl(set, "block-time-diff", isFormatOk_timeDiffInfinity, NULL, NULL, extract_timeDiff);
	PARAM_SET_addControl(set, "time-disordered", isFormatOk_timeValue, NULL, NULL, extract_timeValue);
	PARAM_SET_addControl(set, "log-file-list-delimiter", isFormatOk_fileNameDelimiter, NULL, NULL, NULL);

	PARAM_SET_setParseOptions(set, "time-form,time-base,time-diff,time-disordered,block-time-diff", PST_PRSCMD_HAS_VALUE);

	/* Make input also collect same values as multiple_logs. It simplifies task handling. */
	PARAM_SET_setParseOptions(set, "input",
		PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS |
		PST_PRSCMD_COLLECT_LOOSE_VALUES |
		PST_PRSCMD_COLLECT_WHEN_PARSING_IS_CLOSED
		);
	PARAM_SET_setParseOptions(set, "logfile",  PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS | PST_PRSCMD_COLLECT_LOOSE_VALUES);
	PARAM_SET_setParseOptions(set, "multiple_logs",
		PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS |
		PST_PRSCMD_CLOSE_PARSING | PST_PRSCMD_COLLECT_WHEN_PARSING_IS_CLOSED
		);

	PARAM_SET_setParseOptions(set, "d,x,h", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "warn-client-id-change,warn-same-block-time,ignore-desc-block-time,"
								   "log-from-stdin,ver-int,ver-cal,ver-key,ver-pub,use-computed-hash-on-fail,"
								   "use-stored-hash-on-fail,continue-on-fail,hex-to-str", PST_PRSCMD_HAS_NO_VALUE);


	/*						ID						DESC								MAN							ATL		FORBIDDEN											IGN	*/
	TASK_SET_add(task_set, ANC_BASED_DEFAULT,		"Verify, from file list.",			"log-file-list",				NULL, 	"input,log-from-stdin,ver-int,ver-cal,ver-key,ver-pub", NULL);
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

	TASK_SET_add(task_set,	CAL_BASED,				"Calendar-based verification.",		"ver-cal,input,X",				NULL,	"ver-int,ver-key,ver-pub,pub-str",					NULL);

	TASK_SET_add(task_set,	KEY_BASED,				"Key-based verification.",			"ver-key,input,P,cnstr",		NULL,	"ver-int,ver-cal,ver-pub,T,x,pub-str",				NULL);

	TASK_SET_add(task_set,	PUB_BASED_FILE,			"Publication-based verification, "
													"use publications file, "
													"extending is restricted.",			"ver-pub,input,P,cnstr",		NULL,	"ver-int,ver-cal,ver-key,x,T,pub-str",				NULL);
	TASK_SET_add(task_set,	PUB_BASED_FILE_X,		"Publication-based verification, "
													"use publications file, "
													"extending is permitted.",			"ver-pub,input,P,cnstr,x,X",	NULL,	"ver-int,ver-cal,ver-key,T,pub-str",				NULL);

	TASK_SET_add(task_set,	PUB_BASED_STR,			"Publication-based verification, "
													"use publications string, "
													"extending is restricted.",			"ver-pub,input,pub-str",		NULL,	"ver-int,ver-cal,ver-key,x,T",						NULL);
	TASK_SET_add(task_set,	PUB_BASED_STR_X,		"Publication-based verification, "
													"use publications string, "
													"extending is permitted.",			"ver-pub,input,pub-str,x,X",	NULL,	"ver-int,ver-cal,ver-key,T",						NULL);
cleanup:

	return res;
}

enum suggestions_enum {
	/* Suggest to permit extending as signature has no publication record. */
	SUGST_PERMIT_EXT = 0x01,

	/* Suggest to re-extend the signature as its publication record is not available in publications file. */
	SUGST_PERMIT_RE_EXT = 0x02,

	/* Suggest to check if publications file is up to date. */
	SUGST_PUBFILE_HAS_NOT_YET_PUB = 0x04,

	/* Suggest to check if publications file is up to date as already extend signature contains
	 * more recent publication record than available in publications file. */
	SUGST_PUBFILE_OLDER_THAN_PUBREC = 0x08,
};

static int suggestion_map = SUGST_PERMIT_EXT | SUGST_PERMIT_RE_EXT | SUGST_PUBFILE_HAS_NOT_YET_PUB | SUGST_PUBFILE_OLDER_THAN_PUBREC;

static int do_suggest(int code) {
	if (suggestion_map & code) {
		suggestion_map &= ~code;
		return 1;
	}

	return 0;
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
		if (res != KSI_OK) return;
	}

	if (!isExtendedToPublication && usePubfile) {
		if (possibilityToExtendTo != NULL && !x && do_suggest(SUGST_PERMIT_EXT)) {
			ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Use -x to permit automatic extending or use logksi extend command to extend the signature.\n");
		} else if (possibilityToExtendTo == NULL && do_suggest(SUGST_PUBFILE_HAS_NOT_YET_PUB)) {
			ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Check if publications file is up-to-date as there is not (yet) a publication record in the publications file specified to extend the signature to.\n");
			ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Wait until next publication and try again.\n");
			if (!x && do_suggest(SUGST_PERMIT_EXT)) ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  When a suitable publication is available use -x to permit automatic extending or use logksi extend command to extend the signature.\n");
		}
	} else {
		if (usePubfile) {
			KSI_PublicationRecord *pubrecInPubfile = NULL;
			KSI_Integer *pubTime = NULL;

			/* Get the publication time. */
			res = KSI_Signature_getPublicationRecord(sig, &rec);
			if (res != KSI_OK) return;
			res = KSI_PublicationRecord_getPublishedData(rec, &pubData);
			if (res != KSI_OK) return;
			res = KSI_PublicationData_getTime(pubData, &pubTime);
			if (res != KSI_OK) return;


			res = KSI_PublicationsFile_getPublicationDataByTime(pubFile, pubTime, &pubrecInPubfile);
			if (res != KSI_OK) return;

			if (pubrecInPubfile == NULL) {
				int isPubfileOlderThanPublication = KSI_Integer_compare(latestPubTimeInPubfile, pubTime) == -1 ? 1 : 0;

				ERR_TRCKR_ADD(err, errCode, "Error: Signature is extended to a publication that does not exist in publications file.");

				if (possibilityToExtendTo == NULL && isPubfileOlderThanPublication && do_suggest(SUGST_PUBFILE_OLDER_THAN_PUBREC)) {
					ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Check if publications file is up-to-date as the latest publication in the publications file is older than the signatures publication record.\n");
				} else if (possibilityToExtendTo != NULL && !x && do_suggest(SUGST_PERMIT_RE_EXT)) {
					ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Try to use -x to permit automatic extending or use logksi extend command to re-extend the signature.\n");
				}
			}
		} else {
			if (KSI_Integer_compare(userPubTime, sigTime) == -1) {
				ERR_TRCKR_ADD(err, errCode, "Error: User publication string can not be older than the signatures signing time.");
				return;
			} else if (!x && do_suggest(SUGST_PERMIT_EXT)) {
				ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  Use -x to permit automatic extending.\n");
			}
		}
	}
}

static int isUserInputError(KSI_PolicyVerificationResult *result) {
	if (result == NULL) return 1;

	switch(result->finalResult.status) {
		case KSI_SERVICE_AUTHENTICATION_FAILURE:
		case KSI_NETWORK_ERROR:
		case KSI_IO_ERROR:
		case KSI_HMAC_MISMATCH:
			return 1;
		default:
			return 0;
	}

	return 0;
}

static int mapToLogksiVerRes(KSI_RuleVerificationResult *verificationResult) {
	if (verificationResult == NULL) return LOGKSI_VER_RES_INVALID;
	switch (verificationResult->resultCode) {
		case KSI_VER_RES_OK: return LOGKSI_VER_RES_OK;
		case KSI_VER_RES_FAIL: return LOGKSI_VER_RES_FAIL;
		case KSI_VER_RES_NA: return LOGKSI_VER_RES_NA;
		default: return LOGKSI_VER_RES_INVALID;
	}
}

static int handle_verification_result(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ctx, LOGKSI *logksi, KSI_Signature *sig, KSI_PublicationData *pubData, int res_in, const char *task_desc, KSI_PolicyVerificationResult *result, int isPubBased) {
	KSI_RuleVerificationResult *verificationResult = NULL;
	int res_out = res_in;

	if (isUserInputError(result)) {
		res_out = KT_USER_INPUT_FAILURE;
	}

	if (KSI_RuleVerificationResultList_elementAt(
			result->ruleResults, KSI_RuleVerificationResultList_length(result->ruleResults) - 1,
			&verificationResult) == KSI_OK && verificationResult != NULL) {
			int res = KT_UNKNOWN_ERROR;
			if (isPubBased) signature_set_suggestions_for_publication_based_verification(set, err, res_in, ctx, sig, verificationResult, pubData);

			res = LOGKSI_setErrorLevel(logksi, mapToLogksiVerRes(verificationResult));
			if (res != KT_OK) return res;

			if (verificationResult->status != KSI_OK && verificationResult->statusMessage != NULL) {
				size_t str_len = strlen(verificationResult->statusMessage);
				const char *period = "";

				if (str_len > 0) {
					char last_c = verificationResult->statusMessage[str_len - 1];
					period = last_c != 0 && !ispunct(last_c) ? "." : "";
				}

				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: %s%s", verificationResult->statusMessage, period);
				print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %s%s", logksi->blockNo, verificationResult->statusMessage, period);
			}

			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, res_in);
			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_SMALLER | DEBUG_LEVEL_3, "\n x Error: %s: [%s] %s.",
				task_desc,
				OBJPRINT_getVerificationErrorCode(verificationResult->errorCode),
				OBJPRINT_getVerificationErrorDescription(verificationResult->errorCode));


			print_debug_mp(mp, MP_ID_BLOCK_ERRORS, DEBUG_EQUAL | DEBUG_LEVEL_3, "Block no. %3zu: Error: %s: [%s] %s.",
				logksi->blockNo,
				task_desc,
				OBJPRINT_getVerificationErrorCode(verificationResult->errorCode),
				OBJPRINT_getVerificationErrorDescription(verificationResult->errorCode));
	}

	return res_out;
}

static int check_resources_verify_general(PARAM_SET *set, ERR_TRCKR *err, KSI_Signature *sig, KSI_PublicationData *pubdata, int extperm) {
	int res = KT_UNKNOWN_ERROR;

	if (set == NULL || err == NULL || sig == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (extperm && !PARAM_SET_isSetByName(set, "X")) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Extending is permitted (-x) but extender is not configured (-X).");
		goto cleanup;
	}

	/* First check if user has provided publications. */
	if (pubdata != NULL) {
		res = KT_OK;
	} else {
		/* Get available trust anchor from the signature. */
		if (LOGKSI_Signature_isCalendarAuthRecPresent(sig) && !PARAM_SET_isSetByName(set, "P")) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Publications file (-P) needed for verifying Calendar Authentication Record is not configured!");
		} else if (LOGKSI_Signature_isPublicationRecordPresent(sig) && !PARAM_SET_isSetByName(set, "P")) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Publications file (-P) needed for verifying signature's Publication Record is not configured!");
		} else if (!PARAM_SET_isSetByName(set, "X")) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Extender needed for verifying signature against Calendar Data Base is not configured!");
		} else {
			res = KT_OK;
		}
	}
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:
	return res;
}


static int signature_verify_general(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files,
									KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	int x = PARAM_SET_isSetByName(set, "x");
	KSI_PublicationData *pub_data = NULL;
	KSI_PublicationsFile *pubFile = NULL;
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

	/* If user insists to ignore the publications file and publications file URI is set, try to retrieve it.
	   If it fails ignore the incident and let the general verification handle the case. */
	if (PARAM_SET_isSetByName(set, "publications-file-no-verify,P")) {
		res = LOGKSI_receivePublicationsFile(err, ksi, &pubFile);
		if (res != KSI_OK) {
			KSI_ERR_clearErrors(ksi);
			res = KSI_OK;
		}
	}

	/**
	 * Verify signature.
	 */
	print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_3, "%s... ", task);

	res = check_resources_verify_general(set, err, sig, pub_data, x);
	if (res != KT_OK) {
		LOGKSI_setErrorLevel(logksi, LOGKSI_VER_RES_NA);
		goto cleanup;
	}

	res = LOGKSI_SignatureVerify_general(err, sig, ksi, hsh, rootLevel, pubFile, pub_data, x, out);
	if (res != KSI_OK && *out != NULL) {
		int is_pub_based = pub_data != NULL || LOGKSI_Signature_isPublicationRecordPresent(sig);

		res = handle_verification_result(set, mp, err, ksi, logksi, sig, pub_data, res, task, *out, is_pub_based);
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

static int signature_verify_internally(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files,
									   KSI_Signature *sig, KSI_DataHash *hsh, KSI_uint64_t rootLevel,
									   KSI_PolicyVerificationResult **out) {
	int res;
	int d;
	static const char *task = "Signature internal verification";

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(mp, MP_ID_BLOCK, d, DEBUG_LEVEL_3, "%s... ", task);
	res = LOGKSI_SignatureVerify_internally(err, sig, ksi, hsh, rootLevel, out);
	if (res != KSI_OK && *out != NULL) {
		res = handle_verification_result(set, mp, err, ksi, logksi, sig, NULL, res, task, *out, 0);
		goto cleanup;
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	return res;
}


static int signature_verify_key_based(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files,
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
		res = handle_verification_result(set, mp, err, ksi, logksi, sig, NULL, res, task, *out, 0);
		goto cleanup;
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	return res;
}

static int signature_verify_publication_based_with_user_pub(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files,
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
		res = handle_verification_result(set, mp, err, ksi, logksi, sig, pub_data, res, task, *out, 1);
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

static int signature_verify_publication_based_with_pubfile(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files,
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
		res = handle_verification_result(set, mp, err, ksi, logksi, sig, NULL, res, task, *out, 1);
		goto cleanup;
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_3, res);

	return res;
}

static int signature_verify_calendar_based(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, KSI_CTX *ksi, LOGKSI *logksi, IO_FILES *files,
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
		res = handle_verification_result(set, mp, err, ksi, logksi, sig, NULL, res, task, *out, 0);
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

static int generate_filenames(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;
	char *legacy_name = NULL;
	char *sig_dir = NULL;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	files->user.bStdinLog = PARAM_SET_isSetByName(set, "log-from-stdin");

	res = PARAM_SET_getStr(set, "sig-dir", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &sig_dir);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	if (files->user.inLog) {
		res = duplicate_name(files->user.inLog, &tmp.internal.inLog);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate input log file name.");
	}

	/* If input log signature file name is not specified, it is generared from the input log file name. */
	if (files->user.inSig == NULL) {
		const char *pathComponents[2];
		const char *fnameComponents[2] = {NULL, ".logsig"};
		int sigExists = 0;
		int legacySigExists = 0;
		pathComponents[0] = sig_dir;

		fnameComponents[0] = files->user.inLog;
		if (files->user.bStdinLog) {
			fnameComponents[0] = "stdin";
		} else if (sig_dir) {
			const char *pure_file_name = NULL;
			pure_file_name = strrchr(files->user.inLog, '/');
			if (pure_file_name == NULL) pure_file_name = files->user.inLog;
			else pure_file_name++;
			fnameComponents[0] = pure_file_name;
		}

		res = merge_path(pathComponents, 1, fnameComponents, 2, &tmp.internal.inSig);
		ERR_CATCH_MSG(err, res, "Error: Could not generate input log signature file name.");

		fnameComponents[1] = ".gtsig";
		res = merge_path(pathComponents, 1, fnameComponents, 2, &legacy_name);
		ERR_CATCH_MSG(err, res, "Error: Could not generate input log signature file name.");

		sigExists = SMART_FILE_doFileExist(tmp.internal.inSig);
		legacySigExists = SMART_FILE_doFileExist(legacy_name);

		if (sigExists && legacySigExists) {
			print_debug_mp(mp, MP_ID_LOGFILE_WARNINGS, DEBUG_LEVEL_0,
				"Warning: Both possible auto generated log signature files exist (using .logsig):\n"
				"         %s\n"
				"         %s\n", tmp.internal.inSig, legacy_name);
		}

		if (!sigExists) {
			KSI_free(tmp.internal.inSig);
			tmp.internal.inSig = legacy_name;
			legacy_name = NULL;
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
		ERR_CATCH_MSG(err, res, "Unable to open input log file '%s'.", files->internal.inLog)
	} else {
		res = SMART_FILE_open("-", "rbs", &tmp.files.inLog);
		ERR_CATCH_MSG(err, res, "Unable to open input log stream.")
	}

	if (files->internal.inSig) {
		res = SMART_FILE_open(files->internal.inSig, "rb", &tmp.files.inSig);
		ERR_CATCH_MSG(err, res, "Unable to open input signature file '%s'.", files->internal.inSig)
	} else {
		res = SMART_FILE_open("-", "rbs", &tmp.files.inSig);
		ERR_CATCH_MSG(err, res, "Unable to open input signature stream.")
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

static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;

	res = get_pipe_out_error(set, err, NULL, "log,output-hash", "dump");
	if (res != KT_OK) goto cleanup;

	res = get_pipe_in_error(set, err, NULL, "input-hash,log-file-list", "log-from-stdin");
	if (res != KT_OK) goto cleanup;

cleanup:
	return res;
}

static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;
	int in_count = 0;
	int in_count_all = 0;
	int isMultipleLogFiles = 0;
	int isLogFromStdin = 0;
	int isLogSigFromDir = 0;

	if (set == NULL || err == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/**
	 * Get the count of inputs and outputs for error handling.
	 */
	res = PARAM_SET_getValueCount(set, "logfile", NULL, PST_PRIORITY_NONE, &in_count);
	if (res != PST_OK) goto cleanup;
	res = PARAM_SET_getValueCount(set, "input", NULL, PST_PRIORITY_NONE, &in_count_all);
	if (res != PST_OK) goto cleanup;

	isMultipleLogFiles = PARAM_SET_isSetByName(set, "multiple_logs");
	isLogFromStdin = PARAM_SET_isSetByName(set, "log-from-stdin");
	isLogSigFromDir = PARAM_SET_isSetByName(set, "sig-dir");

	if (isMultipleLogFiles) {
		if (isLogFromStdin) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: It is not possible to verify both log file from stdin (--log-from-stdin) and log file(s) specified after --!");
		}
	} else {
		if (isLogFromStdin && isLogSigFromDir && in_count > 0) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Log file from stdin (--log-from-stdin) and signature from directory (--sig-dir) needs no explicitly specified log signature file, but there are %i!", in_count);
		} else  if (isLogFromStdin && in_count > 1) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Log file from stdin (--log-from-stdin) needs only ONE explicitly specified log signature file, but there are %i!", in_count);
		} else  if (isLogSigFromDir && in_count > 1) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Signature from directory (--sig-dir) needs no explicitly specified log signature file, but there are %i!", in_count - 1);
			 ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  To verify multiple log files see parameter --.\n");
		} else if (in_count > 2) {
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

	if (set == NULL || err == NULL || i < 0) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	files->user.bStdinLog = PARAM_SET_isSetByName(set, "log-from-stdin") ? 1 : 0;

	if (PARAM_SET_isSetByName(set, "logfile")) {
		int count = 0;

		if (i > 0) {
			res = PST_PARAMETER_VALUE_NOT_FOUND;
			goto cleanup;
		}

		res = PARAM_SET_getValueCount(set, "logfile", NULL, PST_PRIORITY_NONE, &count);
		if (res != KT_OK) goto cleanup;

		if (!files->user.bStdinLog) {
			res = PARAM_SET_getStr(set, "logfile", NULL, PST_PRIORITY_NONE, 0, &files->user.inLog);
			if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
		}

		if (count > (1 - files->user.bStdinLog)) {
			res = PARAM_SET_getStr(set, "logfile", NULL, PST_PRIORITY_NONE, (1 - files->user.bStdinLog), &files->user.inSig);
			if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
		}

	} else if (PARAM_SET_isSetByName(set, "input")) {
		res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, i, &files->user.inLog);
		if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

		files->user.inSig = NULL;
	} else {
		res = PST_PARAMETER_EMPTY;
		goto cleanup;
	}


	res = KT_OK;

cleanup:

	return res;
}