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

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ksi/ksi.h>
#include <ksi/compatibility.h>
#include <unistd.h>
#include <param_set/param_set.h>
#include <param_set/task_def.h>
#include <param_set/parameter.h>
#include <param_set/strn.h>
#include "tool_box/ksi_init.h"
#include "tool_box/param_control.h"
#include "tool_box/task_initializer.h"
#include "smart_file.h"
#include "logksi_err.h"
#include "conf_file.h"
#include "api_wrapper.h"
#include "printer.h"
#include "debug_print.h"
#include "tool.h"
#include "rsyslog.h"
#include "logksi.h"
#include "io_files.h"

static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int generate_filenames(PARAM_SET* set, ERR_TRCKR *err, IO_FILES *files);
static int open_input_and_output_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files, int forceOverwrite);
static int acquire_file_locks(ERR_TRCKR *err, MULTI_PRINTER *mp, IO_FILES *files);
static int recover_procedure(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI* blocks, IO_FILES *files, int resIn);
static int rename_temporary_and_backup_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);

#define PARAMS "{input}{o}{out-log}{insert-missing-hashes}{force-overwrite}{use-computed-hash-on-fail}{use-stored-hash-on-fail}{recover}{d}{log}{h|help}{hex-to-str}"

int integrate_run(int argc, char **argv, char **envp) {
	int res;
	int integrate_res = KT_OK;
	char buf[2048];
	PARAM_SET *set = NULL;
	TASK_SET *task_set = NULL;
	TASK *task = NULL;
	KSI_CTX *ksi = NULL;
	ERR_TRCKR *err = NULL;
	SMART_FILE *logfile = NULL;
	int d = 0;
	int forceOverwrite = 0;
	IO_FILES files;
	LOGKSI logksi;
	MULTI_PRINTER *mp = NULL;


	LOGKSI_initialize(&logksi);
	IO_FILES_init(&files);

	/**
	 * Extract command line parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc(PARAMS, "", buf, sizeof(buf)),
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

	res = generate_filenames(set, err, &files);
	if (res != KT_OK) goto cleanup;

	forceOverwrite = PARAM_SET_isSetByName(set, "force-overwrite");

	res = open_input_and_output_files(set, err, &files, forceOverwrite);
	if (res != KT_OK) goto cleanup;

	res = acquire_file_locks(err, mp, &files);
	if (res == KT_VERIFICATION_SKIPPED) {
		res = KT_OK;
		goto cleanup;
	} else if (res != KT_OK) goto cleanup;


	print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_EQUAL | DEBUG_LEVEL_1, "Integrating... ");
	integrate_res = logsignature_integrate(set, mp, err, ksi, &logksi, &files);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, integrate_res);
	res = recover_procedure(set, mp, err, &logksi, &files, integrate_res);
	if (res != KT_OK) goto cleanup;

	res = rename_temporary_and_backup_files(set, err, &files);
	if (res != KT_OK) goto cleanup;

	res = KT_OK;

cleanup:

	close_input_and_output_files(err, res, &files);

	MULTI_PRINTER_printByID(mp, MP_ID_BLOCK);
	if (MULTI_PRINTER_hasDataByID(mp, MP_ID_LOGFILE_WARNINGS)) {
		print_debug("\n");
		MULTI_PRINTER_printByID(mp, MP_ID_LOGFILE_WARNINGS);
	}

	LOGKSI_KSI_ERRTrace_save(ksi);

	if (res != KT_OK || integrate_res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		LOGKSI_KSI_ERRTrace_LOG(ksi);
		print_errors("\n");
	}
	ERR_TRCKR_print(err, d);

	LOGKSI_freeAndClearInternals(&logksi);
	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);
	MULTI_PRINTER_free(mp);

	return LOGKSI_errToExitCode(res);
}

char *integrate_help_toString(char *buf, size_t len) {
	int res;
	char *ret = NULL;
	PARAM_SET *set;
	size_t count = 0;
	char tmp[1024];

	if (buf == NULL || len == 0) return NULL;


	/* Create set with documented parameters. */
	res = PARAM_SET_new(CONF_generate_param_set_desc(PARAMS, "", tmp, sizeof(tmp)), &set);
	if (res != PST_OK) goto cleanup;

	res = CONF_initialize_set_functions(set, "");
	if (res != PST_OK) goto cleanup;

	/* Temporary name change for formatting help text. */
	PARAM_SET_setPrintName(set, "input", "<logfile>", NULL);
	PARAM_SET_setHelpText(set, "input", NULL, "Name of the log file whose temporary files are to be integrated. The two temporary files created while asynchronously signing are:\\>2\n\\>4"
		"* the log signature blocks file: '<logfile>.logsig.parts/blocks.dat'; and\\>2\n\\>4"
		"* the log signature file containing the respective KSI signatures: '<logfile>.logsig.parts/block-signatures.dat'.");

	PARAM_SET_setHelpText(set, "o", "<out.logsig>", "Name of the integrated output log signature file. If not specified, the log signature file is saved as '<logfile>.logsig' in the same folder where the '<logfile>' is located. An attempt to overwrite an existing log signature file will result in an error. Use '-' as file name to redirect the output as a binary stream to stdout.");
	PARAM_SET_setHelpText(set, "out-log", "<out.logsig>", "Specify the name of recovered log file (only valid with --recover). If not specified, the log signature file is saved as <logfile>.recovered in the same folder where the <logfile> is located. An attempt to overwrite an existing log file will result in an error. Use '-' as file name to redirect the output as a binary stream to stdout result in an error. Use '-' to redirect the integrated log signature binary stream to stdout.");
	PARAM_SET_setHelpText(set, "recover", NULL, "Tries to recover as many blocks as possible from corrupted log and log signature temporary files. For example if block no. 6 is corrupted it is possible to recover log records and log signatures until the end of the block no. 5. By default output file names are derived from the log file name: <logfile>.recovered and <logfile>.recovered.logsig for log and log signature file accordingly. If the files already exist, error is returned (see --force-overwrite).");
	PARAM_SET_setHelpText(set, "force-overwrite", NULL, "Force overwriting of existing log signature file.");
	PARAM_SET_setHelpText(set, "d", NULL, "Print detailed information about processes and errors to stderr. To make output more verbose use -dd or -ddd.");
	PARAM_SET_setHelpText(set, "log", "<file>", "Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.");


	/* Format synopsis and parameters. */
	count += PST_snhiprintf(buf + count, len - count, 80, 0, 0, NULL, ' ', "Usage:\\>1\n\\>8"
	"logksi integrate <logfile> [-o <out.logsig>]\\>1\n\\>8"
	"logksi integrate <logfile> --recover [-o <out.logsig>]\n"
	"[--out-log <out.recovered.logsig>]"
	"\\>\n\n\n");

	ret = PARAM_SET_helpToString(set, "input,o,out-log,recover,force-overwrite,d,log", 1, 13, 80, buf + count, len - count);

cleanup:
	if (res != PST_OK || ret == NULL) {
		PST_snprintf(buf + count, len - count, "\nError: There were failures while generating help by PARAM_SET.\n");
	}
	PARAM_SET_free(set);
	return buf;
}


const char *integrate_get_desc(void) {
	return "Integrates individual log signature blocks file and KSI signatures file into a single log signature file.";
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
	PARAM_SET_addControl(set, "{input}", isFormatOk_inputFile, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{log}{o}{out-log}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{insert-missing-hashes}{force-overwrite}{use-computed-hash-on-fail}{use-stored-hash-on-fail}{d}{recover}{hex-to-str}", isFormatOk_flag, NULL, NULL, NULL);

	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);

	PARAM_SET_setParseOptions(set, "insert-missing-hashes,force-overwrite,use-computed-hash-on-fail,use-stored-hash-on-fail,recover,hex-to-str", PST_PRSCMD_HAS_NO_VALUE);
	PARAM_SET_setParseOptions(set, "d,h", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);

	/**
	 * Define possible tasks.
	 */
	/*					  ID	DESC													MAN			ATL		FORBIDDEN		IGN	*/
	TASK_SET_add(task_set, 0,	"Integrate log signature block with KSI signature.",	"input",	NULL,	NULL,			NULL);

	res = KT_OK;

cleanup:

	return res;
}

static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;

	res = get_pipe_out_error(set, err, NULL, "o,log,out-log", NULL);
	if (res != KT_OK) goto cleanup;

cleanup:
	return res;
}

static int generate_filenames(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;
	int isRecoveryMode = 0;
	int inCount = 0;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (set == NULL || err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}


	/* Resolve input files (log signature parts). */

	res = PARAM_SET_getValueCount(set, "input", NULL, PST_PRIORITY_HIGHEST, &inCount);
	if (res != KT_OK) goto cleanup;

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_FIRST, &files->user.inLog);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files->user.outSig);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	/* Input consists of two parts - blocks and signatures. Names of these files are generated
	   from the log file name or explicitly specified path to log signature parts. */
	if (inCount > 1) {
		char *partsDir = NULL;
		int isSlashAtEnd = 0;
		size_t len = 0;

		res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, 1, &partsDir);
		if (res != KT_OK) goto cleanup;

		len = partsDir != NULL ? strlen(partsDir) : 0;
		isSlashAtEnd = len > 0 && partsDir[len - 1] == '/';

		res = concat_names(partsDir, (isSlashAtEnd ? "blocks.dat" : "/blocks.dat"), &tmp.internal.partsBlk);
		ERR_CATCH_MSG(err, res, "Error: Could not generate input blocks file name.");

		res = concat_names(partsDir, (isSlashAtEnd ? "block-signatures.dat" : "/block-signatures.dat"), &tmp.internal.partsSig);
		ERR_CATCH_MSG(err, res, "Error: Could not generate input signatures file name.");
	} else {
		res = concat_names(files->user.inLog, ".logsig.parts/blocks.dat", &tmp.internal.partsBlk);
		ERR_CATCH_MSG(err, res, "Error: Could not generate input blocks file name.");

		res = concat_names(files->user.inLog, ".logsig.parts/block-signatures.dat", &tmp.internal.partsSig);
		ERR_CATCH_MSG(err, res, "Error: Could not generate input signatures file name.");
	}


	/* Resolve output files (log signature and in case of recovery mode, the output of recovered log file). */

	isRecoveryMode = PARAM_SET_isSetByName(set, "recover");

	/* Output log signature file name, if not specified, is generated from the log file name. */
	if (files->user.outSig == NULL) {
		res = concat_names(files->user.inLog, (isRecoveryMode ? ".recovered.logsig" : ".logsig"), &tmp.internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not generate output log signature file name.");
	} else {
		/* Output must go to a named temporary file that is renamed appropriately on success. */
		if (!strcmp(files->user.outSig, "-")) {
			/* Output must go to a nameless temporary file before redirecting it to stdout. */
			tmp.internal.bStdout = 1;
		}

		res = duplicate_name(files->user.outSig, &tmp.internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log signature file name.");
	}

	/* Output log signature file name, if not specified, is generated from the log file name. */
	if (isRecoveryMode) {
		res = PARAM_SET_getStr(set, "out-log", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files->user.outLog);
		if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

		if (files->user.outLog == NULL) {
			res = concat_names(files->user.inLog, (isRecoveryMode ? ".recovered" : ""), &tmp.internal.outLog);
			ERR_CATCH_MSG(err, res, "Error: Could not generate output log file name.");
		} else {
			/* Output must go to a named temporary file that is renamed appropriately on success. */
			if (!strcmp(files->user.outLog, "-")) {
				/* Output must go to a nameless temporary file before redirecting it to stdout. */
				tmp.internal.bStdoutLog = 1;
			}

			res = duplicate_name(files->user.outLog, &tmp.internal.outLog);
			ERR_CATCH_MSG(err, res, "Error: Could not duplicate output log file name.");
		}
	}


	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

	logksi_internal_filenames_free(&tmp.internal);

	return res;
}

static int open_input_and_output_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files, int forceOverwrite) {
	int res;
	int isRecoveryMode = 0;
	int partsBlkErr = 0;
	int partsSigErr = 0;
	IO_FILES tmp;

	memset(&tmp.files, 0, sizeof(tmp.files));

	if (set == NULL || err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	isRecoveryMode = PARAM_SET_isSetByName(set, "recover");

	partsBlkErr = SMART_FILE_open(files->internal.partsBlk, "rb", &tmp.files.partsBlk);
	partsSigErr = SMART_FILE_open(files->internal.partsSig, "rb", &tmp.files.partsSig);


	if (partsBlkErr == SMART_FILE_OK && partsSigErr == SMART_FILE_OK) {
		/* If both of the input files exist and the output log signature file also exists,
		 * the output log signature file must not be overwritten because it may contain KSI signatures
		 * obtained by sign recovery but not present in the input signatures file. */
		if (!forceOverwrite) {
			if (SMART_FILE_doFileExist(files->internal.outSig)) {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Overwriting of existing log signature file %s not allowed. Run 'logksi integrate' with '--force-overwrite' to force overwriting.", files->internal.outSig);
			}

			if (SMART_FILE_doFileExist(files->internal.outLog)) {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Overwriting of existing log file %s not allowed. Run 'logksi integrate' with '--force-overwrite' to force overwriting.", files->internal.outLog);
			}
		}

		/* Open output log file. */
		if (isRecoveryMode) {
			res = SMART_FILE_open(files->internal.outLog, (forceOverwrite ? "wbTX" : "wbTXf"), &tmp.files.outLog);
			ERR_CATCH_MSG(err, res, "Error: Could not create temporary output log file.");
		}

		res = SMART_FILE_open(files->internal.outSig, (forceOverwrite ? "wbTXs" : "wbTfXs"), &tmp.files.outSig);
		ERR_CATCH_MSG(err, res, "Error: Could not create temporary output log signature file.");
	} else if (partsBlkErr == SMART_FILE_DOES_NOT_EXIST && partsSigErr == SMART_FILE_DOES_NOT_EXIST) {
		/* If none of the input files exist, but the output log signature file exists,
		 * the output log signature file is the result of the synchronous signing process
		 * and must not be overwritten. A read mode file handle is needed for acquiring a file lock. */
		res = SMART_FILE_open(files->internal.outSig, "rb", &tmp.files.inSig);
		if (res == SMART_FILE_OK) {
			/* Reassign ouput file name as input file name to avoid potential removal as an incomplete output file. */
			files->internal.inSig = files->internal.outSig;
			files->internal.outSig = NULL;
		} else {
			if (res == SMART_FILE_DOES_NOT_EXIST) {
				res = KT_KSI_SIG_VER_IMPOSSIBLE;
				ERR_CATCH_MSG(err, res, "Error: Unable to find input blocks file '%s'.", files->internal.partsBlk);
			} else {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: Could not open output log signature file %s in read mode.", files->internal.inSig);
			}
		}
	} else {
		res = KT_KSI_SIG_VER_IMPOSSIBLE;
		if (!SMART_FILE_doFileExist(files->internal.partsBlk)) {
			ERR_CATCH_MSG(err, res, "Error: Unable to %s blocks file '%s'.", partsBlkErr == ENOENT ? "find ": "open", files->internal.partsBlk);
		} else {
			ERR_CATCH_MSG(err, res, "Error: Unable to %s signatures file '%s'.", partsSigErr == ENOENT ? "find ": "open", files->internal.partsSig);
		}
	}

	files->files = tmp.files;
	memset(&tmp.files, 0, sizeof(tmp.files));

	res = KT_OK;

cleanup:

	logksi_files_close(&tmp.files);
	return res;
}

static int acquire_file_locks(ERR_TRCKR *err, MULTI_PRINTER *mp, IO_FILES *files) {
	int res = KT_UNKNOWN_ERROR;

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/**
	 * For debugging see command lslocks,
	 * Logksi acquires POSIX style file locks.
	 */
	if (files->files.partsBlk && files->files.partsSig) {
		/* Check that the asynchronous signing process has completed writing to blocks and signatures files. */

		res = SMART_FILE_lock(files->files.partsBlk, SMART_FILE_READ_LOCK);
		ERR_CATCH_MSG(err, res, "Error: Could not acquire read lock for input blocks file %s.", files->internal.partsBlk);
		res = SMART_FILE_lock(files->files.partsSig, SMART_FILE_READ_LOCK);
		ERR_CATCH_MSG(err, res, "Error: Could not acquire read lock for input signatures file %s.", files->internal.partsSig);
		res = KT_OK;
	} else if (files->files.partsBlk == NULL && files->files.partsSig == NULL) {
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "Log signature parts not found:\n", SMART_FILE_getFname(files->files.inSig));
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, " %s\n", files->internal.partsBlk);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, " %s\n\n", files->internal.partsSig);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "Interpreting file '%s' as result of synchronous signing.\n", SMART_FILE_getFname(files->files.inSig));
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "There is nothing to integrate.\n\n", SMART_FILE_getFname(files->files.inSig));

		res = SMART_FILE_lock(files->files.inSig, SMART_FILE_READ_LOCK);
		ERR_CATCH_MSG(err, res, "Error: Could not acquire read lock for output log signature file %s.", files->internal.inSig);
		res = KT_VERIFICATION_SKIPPED;
	}

cleanup:

	return res;


}
static int recover_procedure(PARAM_SET *set, MULTI_PRINTER *mp, ERR_TRCKR *err, LOGKSI* logksi, IO_FILES *files, int resIn) {
	int res = KT_UNKNOWN_ERROR;
	int returnCode = resIn;
	SMART_FILE *originalLogFile = NULL;
	size_t i = 0;


	if (set == NULL || mp == NULL || err == NULL || logksi == NULL || files == NULL) {
		goto cleanup;
	}

	if (PARAM_SET_isSetByName(set, "recover")) {
		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_1, "Checking recoverability... ");
		if (files->files.outSig == NULL) {
			ERR_TRCKR_ADD(err, resIn, "Error: Unexpected behaviour where file pointer to signature file is NULL!");
			goto cleanup;
		}

		/* Check if there is a need and possibility to do something. */
		if (resIn == KT_OK) {
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, 0);
			print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "All blocks (%zu) have successfully integrated - no recovery process needed.\n", logksi->task.integrate.partNo);
			returnCode = KT_OK;
			goto cleanup;
		} else if (logksi->blockNo < 2) {
			print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, 1);
			ERR_TRCKR_ADD(err, resIn, "Error: Unable to recover any blocks as the first block is already corrupted!");
			goto cleanup;
		}

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, 0);
		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_1, "Removing corrupted data from log signature... ");

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, 0);
		print_progressDesc(mp, MP_ID_BLOCK, 0, DEBUG_LEVEL_1, "Copying valid log lines into recovered log file... ");

		/* Open original log file and copy recovered log lines into recovered log file. */
		res = SMART_FILE_open(files->user.inLog, "rb", &originalLogFile);
		if (res != SMART_FILE_OK) {
			ERR_TRCKR_ADD(err, resIn, "Error: Unable to open input logfile '%s'!", files->user.inLog);
			goto cleanup;
		}

		res = SMART_FILE_lock(originalLogFile, SMART_FILE_READ_LOCK);
		if (res != SMART_FILE_OK) {
			ERR_TRCKR_ADD(err, resIn, "Error: Unable to get read lock for input logfile '%s'!", files->user.inLog);
			goto cleanup;
		}

		for (i = 0; i < logksi->block.firstLineNo - 1; i++) {
			/* Maximum line size is 64K characters, without newline character. */
			size_t count = 0;
			char buf[0x10000 + 2];

			res = SMART_FILE_readLine(originalLogFile, buf, sizeof(buf) - 2, &count);
			if (res != SMART_FILE_OK) {
				ERR_TRCKR_ADD(err, resIn, "Error: Unable read logline nr %3zu!", i);
				goto cleanup;
			}
			buf[count] = '\n';
			buf[count + 1] = '\0';

			res = SMART_FILE_write(files->files.outLog, (unsigned char*)buf, count + 1, NULL);
			if (res != SMART_FILE_OK) {
				ERR_TRCKR_ADD(err, resIn, "Error: Unable write logline nr %3zu into recovered log file!", i);
				goto cleanup;
			}
		}

		res = SMART_FILE_markConsistent(files->files.outLog);
		ERR_CATCH_MSG(err, res, "Error: Could not close output log file %s.", files->internal.outLog);

		print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, 0);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "It was possible to recover %zu blocks (lines 1 - %zu).\n", logksi->blockNo - 1, logksi->block.firstLineNo - 1);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "Recovered log signature saved to '%s'\n", files->internal.outSig);
		print_debug_mp(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, "Recovered Log file saved to '%s'\n", files->internal.outLog);

		returnCode = KT_OK;
	}



cleanup:

	if (returnCode != KT_OK) {
		SMART_FILE_markInconsistent(files->files.outSig);
		SMART_FILE_markInconsistent(files->files.outLog);
	}

	SMART_FILE_close(originalLogFile);
	print_progressResult(mp, MP_ID_BLOCK, DEBUG_LEVEL_1, returnCode);

	return returnCode;
}

static int rename_temporary_and_backup_files(PARAM_SET *set, ERR_TRCKR *err, IO_FILES *files) {
	int res;

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	logksi_file_close(&files->files.outSig);
	logksi_file_close(&files->files.outLog);

	res = KT_OK;

cleanup:

	return res;
}

void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);

		logksi_internal_filenames_free(&files->internal);
	}
}
