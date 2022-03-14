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

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include "param_set/param_set.h"
#include "param_set/task_def.h"
#include "param_set/parameter.h"
#include "api_wrapper.h"
#include "tool_box/param_control.h"
#include "tool_box/ksi_init.h"
#include "tool_box/task_initializer.h"
#include "debug_print.h"
#include "smart_file.h"
#include "err_trckr.h"
#include "printer.h"
#include "obj_printer.h"
#include "conf_file.h"
#include "tool.h"
#include "param_set/parameter.h"
#include "../tool_box.h"
#include "param_set/strn.h"
#include "rsyslog.h"
#include "logksi.h"
#include "io_files.h"

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int generate_filenames(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static int open_input_and_output_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files);
static int getLogFiles(PARAM_SET *set, ERR_TRCKR *err, int i, IO_FILES *files);
static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err);
static int check_if_output_files_will_not_be_overwritten_if_restricted(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err);

#define PARAMS "{log-file-list}{log-file-list-delimiter}{sig-dir}{logfile}{input}{multiple_logs}{o}{input-hash}{output-hash}{force-overwrite}{blk-size}{keep-record-hashes}{seed}{seed-len}{keep-tree-hashes}{d}{log}{conf}{h|help}{log-from-stdin}"

int create_run(int argc, char** argv, char **envp) {
	int res;
	char buf[2048];
	PARAM_SET *set = NULL;
	TASK_SET *task_set = NULL;
	TASK *task = NULL;
	KSI_CTX *ksi = NULL;
	ERR_TRCKR *err = NULL;
	SMART_FILE *logfile = NULL;
	int d = 0;
	IO_FILES files;
	MULTI_PRINTER *mp = NULL;
	IO_FILES_init(&files);
	LOGKSI logksi;
	COMPOSITE extra;
	KSI_HashAlgorithm aggrAlgo = KSI_HASHALG_INVALID_VALUE;
	KSI_DataHash *inputHash = NULL;
	KSI_DataHash *outputHash = NULL;
	KSI_DataHash *pLastOutputHash = NULL;
	size_t i = 0;
	/**
	 * Extract command line parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc(PARAMS, "S", buf, sizeof(buf)),
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

	res = TOOL_init_ksi(set, &ksi, &err, &logfile);
	if (res != KT_OK) goto cleanup;

	PARAM_SET_getValueCount(set, "d", NULL, PST_PRIORITY_HIGHEST, &d);

	res = TASK_INITIALIZER_getPrinter(set, &mp);
	ERR_CATCH_MSG(err, res, "Error: Unable to create Multi printer!");

	res = check_pipe_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = check_io_naming_and_type_errors(set, err);
	if (res != KT_OK) goto cleanup;

	res = extract_input_files_from_file(set, mp, err);
	if (res != PST_OK) goto cleanup;


	extra.ctx = ksi;
	extra.err = err;

	LOGKSI_initialize(&logksi);

	if (PARAM_SET_isSetByName(set, "H")) {
		res = PARAM_SET_getObjExtended(set, "H", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, NULL, (void**)&aggrAlgo);
		if (res != PST_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
	} else {
		aggrAlgo = /*(KSI_isHashAlgorithmSupported(remote_algo)) ? remote_algo :*/ KSI_getHashAlgorithmByName("default");
	}

	if (PARAM_SET_isSetByName(set, "input-hash")) {
		res = PARAM_SET_getObjExtended(set, "input-hash", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &extra, (void**)&inputHash);
		ERR_CATCH_MSG(err, res, "Error: Unable to extract input hash value!");
	} else {
		res = KSI_DataHash_createZero(ksi, aggrAlgo, &inputHash);
		ERR_CATCH_MSG(err, res, "Unable to create zero hash for input hash!");
	}

	res = check_if_output_files_will_not_be_overwritten_if_restricted(set, mp, err);
	if (res != KT_OK) goto cleanup;

	do {
		int isSigStream = 0;
		int isLogStream = 0;

		res = getLogFiles(set, err, i, &files);
		 if (res == PST_PARAMETER_VALUE_NOT_FOUND) {
			res = KT_OK;
			break;
		}
		ERR_CATCH_MSG(err, res, "Error: Unable to get file names for log and log signature file.");

		res = generate_filenames(set, err, &files);
		if (res != KT_OK) goto cleanup;

		res = open_input_and_output_files(set, err, &files);
		if (res != KT_OK) goto cleanup;

		isSigStream = SMART_FILE_isStream(files.files.outSig);
		isLogStream = SMART_FILE_isStream(files.files.inLog);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "%sLog file           %s%s%s.\n",
			(i == 0 ? "" : "\n"),
			isLogStream ? "" : "'",
			isLogStream ? "<stdin>" : files.internal.inLog,
			isLogStream ? "" : "'");
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "Log signature file %s%s%s.\n\n",
			isSigStream ? "" : "'",
			isSigStream ? "<stdout>" : files.internal.outSig,
			isSigStream ? "" : "'");

		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_1, "Creating... ");
		res = logsignature_create(set, mp, err, ksi, &logksi, &files, aggrAlgo, inputHash, &outputHash);
		print_progressResult(mp, MP_ID_BLOCK, DEBUG_EQUAL | DEBUG_LEVEL_1, res);
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
		close_input_and_output_files(err, KT_OK, &files);

		// As no input file is interpreted as input from stdin, break the loop
		if (files.user.bStdinLog) break;
		i++;
	} while(1);

	if (PARAM_SET_isSetByName(set, "output-hash")) {
		char *fname = NULL;

		res = PARAM_SET_getStr(set, "output-hash", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &fname);
		ERR_CATCH_MSG(err, res, "Error: Unable to get file name for output hash.");

		res = logksi_save_output_hash(err, pLastOutputHash, fname, files.previousLogFile, files.previousSigFileOut);
		if (res != KT_OK) goto cleanup;
	}

	res = rename_temporary_and_backup_files(err, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	/* If there is an error while closing files, report it only if everything else was OK. */
	close_input_and_output_files(err, res, &files);

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_BLOCK_ERRORS)) {
		print_debug("\n");
		MULTI_PRINTER_printByID(mp, MP_ID_BLOCK_ERRORS);
	}

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

	MULTI_PRINTER_free(mp);
	SMART_FILE_close(logfile);
	TASK_SET_free(task_set);
	PARAM_SET_free(set);
	ERR_TRCKR_free(err);
	KSI_DataHash_free(inputHash);
	KSI_DataHash_free(outputHash);
	KSI_CTX_free(ksi);

	return LOGKSI_errToExitCode(res);
}

char *create_help_toString(char*buf, size_t len) {
	int res;
	char *ret = NULL;
	PARAM_SET *set;
	size_t count = 0;
	char tmp[1024];


	if (buf == NULL || len == 0) return NULL;

	/* Create set with documented parameters. */
	res = PARAM_SET_new(CONF_generate_param_set_desc(PARAMS, "S", tmp, sizeof(tmp)), &set);
	if (res != PST_OK) goto cleanup;

	res = CONF_initialize_set_functions(set, "S");
	if (res != PST_OK) goto cleanup;


	/* Temporary name change for formatting help text. */
	PARAM_SET_setPrintName(set, "input", "<logfile>", NULL);
	PARAM_SET_setPrintName(set, "multiple_logs", "--", NULL);

	PARAM_SET_setHelpText(set, "input", NULL, "Name of the log file from what the log signature will be created. To sign a log file from stdin see option --log-from-stdin. To sign multiple log files see options --. By default the log signature is stored next to log file as <logfile>.logsig (see options -o and --sig-dir to change how the signature is stored).");
	PARAM_SET_setHelpText(set, "multiple_logs", NULL, "Is used for signing multiple log files. Everything specified after the token is interpreted as <logfile>. This option can be used together with <logfile> and can even be left empty (e.g. for optional log files). If only one log file is signed it can be combined with -o, otherwise log signature file names are generated by appending '.logsig' extension to log file (see --sig-dir to change the output directory). Each log file generates corresponding log signature file.\n\nIt must be noted that the order of the log files is important as every logfile is cryptographically linked to each other. Log files must be ordered by the caller and are processed on command line from left to right.");
	PARAM_SET_setHelpText(set, "log-file-list", "<file>", "Same as -- but log file list is read from a file or from stdin (use '-' as file name to read log file list from stdin). This option can be useful when the list of log files is too long to represent it on the command line. By default file names are separated by whitespace characters (including new line). Empty lines are ignored. Quote (') and double quote (\") can be used to include strings containing delimiters or delimiters can be escaped with backslash (\\\\). To change the delimiter see --log-file-list-delimiter. It can not be combined with other log file inputs and log file output -o.");
	PARAM_SET_setHelpText(set, "log-file-list-delimiter", "<str>", "To change how the file names are separated from each other in log file list (see --log-file-list) specify the delimiter. There are two magical strings 'new-line', where each line contains one log file name, and 'space' (default), where whitespace characters separates log file names. Otherwise the user can specify a single character from {:;,|}.");
	PARAM_SET_setHelpText(set, "log-from-stdin", NULL, "Read log file from stdin (same as input log file is omitted). This option can not be used together with file inputs (<logfile>, -- and --log-file-list). If output file name is not specified, log signature is stored as stdin.logsig.");
	PARAM_SET_setHelpText(set, "seed", "<file>", "Specify random seed for masking. Random seed is a file containing enough bytes to provide a sequence of bytes, in the size of the output of hash algorithm used to build Merkle tree, for every block (see -H). Use '-' as file name to read the random from stdin.");
	PARAM_SET_setHelpText(set, "seed-len", "<int>", "Size of the random seed. If not set size of the seed is the size of the output of hash algorithm used to build Merkle tree (see -H).");
	PARAM_SET_setHelpText(set, "blk-size", "<int>", "The maximum size of the block (how many log records are aggregated into single Merkle tree).");
	PARAM_SET_setHelpText(set, "keep-record-hashes", NULL, "Include record hashes (hash value directly calculated from log line without any masking) into log signature file. Log signature without record hashes can still be verified but the diagnostics in case of failure is more difficult.");
	PARAM_SET_setHelpText(set, "keep-tree-hashes", NULL, "Include intermediate Merkle tree (every tree node) hash values into log signature file. Log signature without tree hashes can still be verified but the diagnostics in case of failure is more difficult.");
	PARAM_SET_setHelpText(set, "input-hash", "<hash>", "Specify hash imprint for inter-linking (the last leaf from the previous log signature). Hash can be specified on command line or from a file containing its string representation. Hash format: <alg>:<hash in hex>. Use '-' as file name to read the imprint from stdin. Call logksi -h to get the list of supported hash algorithms. See --output-hash to see how to extract the hash imprint from the previous log file. When used together with -- or --log-file-list, only the first block uses the value as input hash.");
	PARAM_SET_setHelpText(set, "output-hash", "<file>", "Output the last leaf from the log signature into file. Use '-' as file name to redirect hash imprint to stdout. See --input-hash to use the output hash as input hash to next log signature. When used together with -- or --log-file-list, only the output hash of the last block is returned. Will always overwrite existing file.");
	PARAM_SET_setHelpText(set, "o", "<out.logsig>", "Specify the name of the created log signature file; recommended file extension is '.logsig'. If not specified, the log signature file is saved as '<logfile>.logsig' in the same folder where the <logfile> is located. An attempt to overwrite an existing log signature file will result in an error (see --force-overwrite). Use '-' as file name to redirect the output as a binary stream to stdout. This option can only be used when a single log file is used as input (exept with --log-file-list).");
	PARAM_SET_setHelpText(set, "force-overwrite", NULL, "Force overwriting of existing log signature file.");
	PARAM_SET_setHelpText(set, "d", NULL, "Print detailed information about processes and errors to stderr. To make output more verbose use -dd or -ddd.");
	PARAM_SET_setHelpText(set, "conf", "<file>", "Read configuration options from the given file. It must be noted that configuration options given explicitly on command line will override the ones in the configuration file.");
	PARAM_SET_setHelpText(set, "log", "<file>", "Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.");


	/* Format synopsis and parameters. */
	count += PST_snhiprintf(buf + count, len - count, 80, 0, 0, NULL, ' ', "Usage:\\>1\n\\>8"
		"logksi create <logfile> [-o <out.logsig>] -S <URL> [--aggr-user <user>\n"
		"--aggr-key <key>] [more_options]\\>1\n\\>8"
		"\\>\n\n\n");

	ret = PARAM_SET_helpToString(set, "input,multiple_logs,log-file-list,log-file-list-delimiter,log-from-stdin,seed,seed-len,max-lvl,blk-size,keep-record-hashes,keep-tree-hashes,input-hash,output-hash,H,o,force-overwrite,S,aggr-user,aggr-key,aggr-hmac-alg,d,conf,log", 1, 13, 80, buf + count, len - count);

cleanup:
	if (res != PST_OK || ret == NULL) {
		PST_snprintf(buf + count, len - count, "\nError: There were failures while generating help by PARAM_SET.\n");
	}
	PARAM_SET_free(set);
	return buf;
}

const char *create_get_desc(void) {
	return "Creates log signatures from log files.";
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
	res = CONF_initialize_set_functions(set, "S");
	if (res != KT_OK) goto cleanup;

	res |= PARAM_SET_setPrintName(set, "logfile", "<logfile>", NULL);
	res |= PARAM_SET_setPrintName(set, "multiple_logs", "--", NULL);

	res |= PARAM_SET_addControl(set, "{conf}", isFormatOk_inputFile, isContentOk_inputFileRestrictPipe, convertRepair_path, NULL);
	res |= PARAM_SET_addControl(set, "{o}{log}{output-hash}", isFormatOk_path, NULL, convertRepair_path, NULL);
	res |= PARAM_SET_addControl(set, "{d}{keep-record-hashes}{keep-tree-hashes}{log-from-stdin}{force-overwrite}", isFormatOk_flag, NULL, NULL, NULL);
	res |= PARAM_SET_addControl(set, "{logfile}{multiple_logs}", isFormatOk_inputFile, isContentOk_inputFileNoDir, convertRepair_path, NULL);
	res |= PARAM_SET_addControl(set, "{sig-dir}", isFormatOk_inputFile, isContentOk_dir, convertRepair_path, NULL);
	res |= PARAM_SET_addControl(set, "{input-hash}", isFormatOk_inputHash, isContentOk_inputHash, convertRepair_path, extract_inputHashFromImprintOrImprintInFile);
	res |= PARAM_SET_addControl(set, "{seed}{log-file-list}", isFormatOk_inputFile, isContentOk_inputFileWithPipe, convertRepair_path, NULL);
	res |= PARAM_SET_addControl(set, "{seed-len}{blk-size}", isFormatOk_int, isContentOk_uint_not_zero, NULL, extract_uint);
	res |= PARAM_SET_addControl(set, "{log-file-list-delimiter}", isFormatOk_fileNameDelimiter, NULL, NULL, NULL);

	res |= PARAM_SET_setParseOptions(set, "seed-len,blk-size,max-lvl,log-file-list-delimiter",
		PST_PRSCMD_HAS_VALUE | PST_PRSCMD_BREAK_WITH_EXISTING_PARAMETER_MATCH);

	res |= PARAM_SET_setParseOptions(set, "seed", PST_PRSCMD_HAS_VALUE);
	/* Input takes only 1 value - to make user interface similar to verify
	   multiple log files ar given after -- ("multiple_logs").
	   No input nor multiple_logs has a flag as they are collectors. */
	res |= PARAM_SET_setParseOptions(set, "input",
		PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS |
		PST_PRSCMD_COLLECT_LOOSE_VALUES |
		PST_PRSCMD_COLLECT_WHEN_PARSING_IS_CLOSED
		);
	res |= PARAM_SET_setParseOptions(set, "logfile",  PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS | PST_PRSCMD_COLLECT_LOOSE_VALUES);
	res |= PARAM_SET_setParseOptions(set, "multiple_logs",
		PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS |
		PST_PRSCMD_CLOSE_PARSING | PST_PRSCMD_COLLECT_WHEN_PARSING_IS_CLOSED
		);
	res |= PARAM_SET_setParseOptions(set, "d,h", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);
	res |= PARAM_SET_setParseOptions(set, "log-from-stdin,keep-record-hashes,keep-tree-hashes,force-overwrite", PST_PRSCMD_HAS_NO_VALUE);

	res |= TASK_SET_add(task_set,
	/* ID:           */ 0,
	/* Desc:         */ "Create from files.",
	/* Man:          */ "input,seed,S",
	/* At least one: */ "max-lvl,blk-size",
	/* Forbidden:    */ "log-from-stdin,log-file-list",
	/* Ignore:       */ NULL);

	res |= TASK_SET_add(task_set,
	/* ID:           */ 0,
	/* Desc:         */ "Create from stdin 1.",
	/* Man:          */ "seed,S",
	/* At least one: */ "max-lvl,blk-size",
	/* Forbidden:    */ "input,log-from-stdin,log-file-list",
	/* Ignore:       */ NULL);

	res |= TASK_SET_add(task_set,
	/* ID:           */ 0,
	/* Desc:         */ "Create from stdin 2.",
	/* Man:          */ "seed,S,log-from-stdin",
	/* At least one: */ "max-lvl,blk-size",
	/* Forbidden:    */ "input,log-file-list",
	/* Ignore:       */ NULL);

	res |= TASK_SET_add(task_set,
	/* ID:           */ 0,
	/* Desc:         */ "Create from log file list.",
	/* Man:          */ "seed,S,log-file-list",
	/* At least one: */ "max-lvl,blk-size",
	/* Forbidden:    */ "input,log-from-stdin",
	/* Ignore:       */ NULL);

	/* Development time error handling. */
	if (res != 0) {
		res = KT_UNKNOWN_ERROR;
		goto cleanup;
	}

cleanup:

	return res;
}

static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;

	res = get_pipe_out_error(set, err, NULL, "log,output-hash,o", NULL);
	if (res != KT_OK) goto cleanup;

	if (!PARAM_SET_isOneOfSetByName(set, "input,log-file-list")) {
		PARAM_SET_add(set, "log-from-stdin", NULL, "check_pipe_errors", PST_PRIORITY_VALID_BASE);
	}

	res = get_pipe_in_error(set, err, NULL, "input-hash,seed,log-file-list", "log-from-stdin");
	if (res != KT_OK) goto cleanup;

	PARAM_SET_clearValue(set, "log-from-stdin", "check_pipe_errors", PST_PRIORITY_VALID_BASE, 0);

cleanup:
	return res;
}

static int get_output_signature_name(char *sig_dir, char *outSigName, const char *inLogName, ERR_TRCKR *err, char **out) {
	int res = KT_UNKNOWN_ERROR;
	char *tmp = NULL;

	if (out == NULL) return KT_INVALID_ARGUMENT;

	if (outSigName == NULL) {
		const char *pathComponents[2];
		pathComponents[0] = sig_dir;

		if (inLogName == NULL) {
			res = merge_path(pathComponents, 1, (const char*[]){"stdin.logsig"}, 1, &tmp);
		} else {
			const char *fnameComponents[2] = {NULL, ".logsig"};
			fnameComponents[0] = inLogName;
			if (sig_dir) {
				const char *pure_file_name = NULL;
				pure_file_name = strrchr(inLogName, '/');
				if (pure_file_name == NULL) pure_file_name = inLogName;
				else pure_file_name++;
				fnameComponents[0] = pure_file_name;
			}
			res = merge_path(pathComponents, 1, fnameComponents, 2, &tmp);
		}
		ERR_CATCH_MSG(err, res, "Error: Could not generate output log signature file name.");
	} else {
		res = duplicate_name(outSigName, &tmp);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log signature file name.");
	}

	*out = tmp;
	tmp = NULL;
	res = KT_OK;

cleanup:

	KSI_free(tmp);

	return res;
}


static int check_if_output_files_will_not_be_overwritten_if_restricted(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err) {
	int res = KT_UNKNOWN_ERROR;
	char *sig_dir = NULL;
	char *user_out_sig = NULL;
	int i = 0;
	char *out_sig = NULL;

	if (set == NULL || mp == NULL || err == NULL) return KT_INVALID_ARGUMENT;
	if(PARAM_SET_isSetByName(set, "force-overwrite")) return KT_OK;

	res = PARAM_SET_getStr(set, "sig-dir", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &sig_dir);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &user_out_sig);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;


	do {
		char *user_in_log = NULL;

		res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, i, &user_in_log);
		if (res == PST_PARAMETER_EMPTY || res == PST_PARAMETER_VALUE_NOT_FOUND) {
			res = KT_OK;
			goto cleanup;
		}
		if (res != KT_OK) goto cleanup;

		res = get_output_signature_name(sig_dir, user_out_sig, user_in_log, err, &out_sig);
		if (res != KT_OK) goto cleanup;


		if (SMART_FILE_doFileExist(out_sig)) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: Overwriting of existing log signature file %s not allowed. Run 'logksi create' with '--force-overwrite' to force overwriting.", out_sig);
		}
		KSI_free(out_sig);
		out_sig = NULL;
		i++;
	} while(1);

	res = KT_OK;

cleanup:

	KSI_free(out_sig);

	return res;
}

static int generate_filenames(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res = KT_UNKNOWN_ERROR;
	IO_FILES tmp;
	char *sig_dir = NULL;
	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	files->user.bStdinLog = PARAM_SET_isSetByName(set, "log-from-stdin");

	res = PARAM_SET_getStr(set, "seed", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files->user.inRandom);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	if (files->user.inRandom) {
		res = duplicate_name(files->user.inRandom, &tmp.internal.inRandom);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate input random file name.");
	}

	res = PARAM_SET_getStr(set, "sig-dir", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &sig_dir);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;
	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files->user.outSig);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	if (files->user.inLog != NULL) {
		res = duplicate_name(files->user.inLog, &tmp.internal.inLog);
	} else {
		res = duplicate_name("-", &tmp.internal.inLog);
		files->user.bStdinLog = 1;
	}
	ERR_CATCH_MSG(err, res, "Error: Could not duplicate input log file name.");


	res = get_output_signature_name(
		sig_dir,
		files->user.outSig,
		files->user.inLog, err, &tmp.internal.outSig);
	if (res != KT_OK) goto cleanup;

	if (files->user.outSig && sig_dir) {
		res = KT_INVALID_CMD_PARAM;
		ERR_CATCH_MSG(err, res, "Error: Both -o and --sig-dir can not be used simultaneously!");
	}

	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

	logksi_internal_filenames_free(&tmp.internal);

	return res;
}

static int open_input_and_output_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;

	memset(&tmp.files, 0, sizeof(tmp.files));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (files->internal.inRandom) {
		res = SMART_FILE_open(files->internal.inRandom, "rbs", &tmp.files.inRandom);
		ERR_CATCH_MSG(err, res, "Unable to open input random file '%s'.", files->internal.inRandom)
	}

	if (files->internal.inLog) {
		res = SMART_FILE_open(files->internal.inLog, files->user.bStdinLog ? "rbs" : "rb", &tmp.files.inLog);
		ERR_CATCH_MSG(err, res, "Unable to open input log file '%s'.", files->internal.inLog)
	} else {
		res = SMART_FILE_open("-", "rbs", &tmp.files.inLog);
		ERR_CATCH_MSG(err, res, "Unable to open input log stream.")
	}

	res = SMART_FILE_open(files->internal.outSig, "wbTs", &tmp.files.outSig);
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

static int getLogFiles(PARAM_SET *set, ERR_TRCKR *err, int i, IO_FILES *files) {
	int res = KT_UNKNOWN_ERROR;

	if (set == NULL || err == NULL || i < 0) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_NONE, i, &files->user.inLog);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = KT_OK;

cleanup:

	return res;
}

static int check_io_naming_and_type_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;
	int in_count = 0;
	int in_count_all = 0;
	int isLogFileList = 0;
	int isLogFromStdin = 0;
	int isExplicitOutput = 0;

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

	isLogFileList = PARAM_SET_isSetByName(set, "log-file-list");
	isLogFromStdin = PARAM_SET_isSetByName(set, "log-from-stdin");
	isExplicitOutput = PARAM_SET_isSetByName(set, "o");

	if (in_count > 1) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: Only one log file is required, but there are %i!", in_count);
		ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion:  To create log signature from multiple log files see parameter --.\n");
		if (res != KT_OK) goto cleanup;
	}

	if (in_count_all > 0 && isLogFromStdin) {
			ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: It is not possible to create log signature from stdin (--log-from-stdin) and log file%s!",
				in_count_all > 1 ? "s" : "");
		if (res != KT_OK) goto cleanup;

	}
	if (isLogFileList && PARAM_SET_isOneOfSetByName(set, "logfile,multiple_logs,log-from-stdin")) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, "Error: It is not possible to use --log-file-list together with other log file inputs!");
		goto cleanup;
	}

	if (isExplicitOutput && (in_count_all > 1 || isLogFileList)) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_CMD_PARAM, isLogFileList ?
			"Error: It is not possible to specify explicit output signature file name for log file list!" :
			"Error: It is not possible to specify explicit output signature file name for multiple input log signature files!");
		ERR_TRCKR_addAdditionalInfo(err, "  * Suggestion: To store log signature files with automatically generated names to specified directory see parameter --sig-dir.\n");
		if (res != KT_OK) goto cleanup;
	}

	res = KT_OK;

cleanup:

	return res;
}