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

static int extend_to_nearest_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext);
static int extend_to_specified_time(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext);
static int extend_to_specified_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext);
static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int generate_filenames(ERR_TRCKR *err, IO_FILES *files);
static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files);
static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files);

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

	memset(&files, 0, sizeof(files));

	/**
	 * Extract command line parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{input}{o}{d}{x}{T}{pub-str}{conf}{log}{h|help}", "XP", buf, sizeof(buf)),
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

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.user.log);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.user.sig);
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

	res = generate_filenames(err, &files);
	if (res != KT_OK) goto cleanup;

	res = open_input_and_output_files(err, &files);
	if (res != KT_OK) goto cleanup;

	res = logsignature_extend(set, err, ksi, extend_signature, &files);
	if (res != KT_OK) goto cleanup;

	res = rename_temporary_and_backup_files(err, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	/* If there is an error while closing files, report it only if everything else was OK. */
	close_input_and_output_files(err, res, &files);

	print_progressResult(res);
	LOGKSI_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		LOGKSI_KSI_ERRTrace_LOG(ksi);

		print_errors("\n");
		if (d) ERR_TRCKR_printExtendedErrors(err);
		else  ERR_TRCKR_printErrors(err);
	}

	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);

	return LOGKSI_errToExitCode(res);
}
char *extend_help_toString(char*buf, size_t len) {
	KSI_snprintf(buf, len,
		"Usage:\n"
		" %s extend [<logfile>] [-o <out.logsig>] -X <URL>\n"
		"    [--ext-user <user> --ext-key <key>] -P <URL> [--cnstr <oid=value>]... [more_options]\n"
		" %s extend [<logfile>] [-o <out.logsig>] -X <URL>\n"
		"    [--ext-user <user> --ext-key <key>] -P <URL> [--cnstr <oid=value>]... [--pub-str <str>] [more_options]\n"
		" %s extend [<logfile>] [-o <out.logsig>] --conf <logksi.conf> [more_options]\n"
		"\n"
		" <logfile>\n"
		"           - Name of the log file whose log signature file is to be extended. If not specified,\n"
		"             the log signature is read from stdin.\n"
		" -o <out.logsig>\n"
		"           - Name of the extended output log signature file. An existing log signature file is always overwritten.\n"
		"             If not specified, the log signature is saved to <logfile.logsig> while a backup of <logfile.logsig>\n"
		"             is saved in <logfile.logsig.bak>.\n"
		"             Use '-' to redirect the extended log signature binary stream to stdout.\n"
		"             If both input and output are not specified, stdin and stdout are used resepectively.\n"
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
		" -V        - Certificate file in PEM format for publications file verification.\n"
		"             All values from lower priority sources are ignored.\n"
		" -d        - Print detailed information about processes and errors to stderr.\n"
		" --conf <file>\n"
		"             Read configuration options from the given file.\n"
		"             Configuration options given explicitly on command line will\n"
		"             override the ones in the configuration file.\n"
		" --log <file>\n"
		"           - Write libksi log to the given file. Use '-' as file name to redirect the log to stdout.\n",
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName()
	);

	return buf;
}
const char *extend_get_desc(void) {
	return "Extends KSI signatures in a log signature file to the desired publication.";
}

static int extend_to_nearest_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext) {
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
	res = LOGKSI_receivePublicationsFile(err, ksi, &pubFile);
	ERR_CATCH_MSG(err, res, "Error: Unable receive publications file.");
	print_progressResult(res);

	if (!PARAM_SET_isSetByName(set, "publications-file-no-verify")) {
		print_progressDesc(d, "Verifying publications file... ");
		res = LOGKSI_verifyPublicationsFile(err, ksi, pubFile);
		ERR_CATCH_MSG(err, res, "Error: Unable to verify publications file.");
		print_progressResult(res);
	}

	print_progressDesc(d, "Extend the signature to the earliest available publication... ");
	res = LOGKSI_extendSignature(err, ksi, sig, context, &tmp);
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

static int extend_to_specified_time(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext) {
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
	print_progressDesc(d, "Extending the signature to %s (%" PRIu64 "u)... ",
			KSI_Integer_toDateString(pubTime, buf, sizeof(buf)),
			KSI_Integer_getUInt64(pubTime));
	res = LOGKSI_Signature_extendTo(err, sig, ksi, pubTime, context, &tmp);
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

static int extend_to_specified_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext) {
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
	res = LOGKSI_receivePublicationsFile(err, ksi, &pubFile);
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
		res = LOGKSI_verifyPublicationsFile(err, ksi, pubFile);
		ERR_CATCH_MSG(err, res, "Error: Unable to verify publications file.");
		print_progressResult(res);
	}

	print_progressDesc(d, "Extend the signature to the specified publication... ");
	res = LOGKSI_Signature_extend(err, sig, ksi, pub_rec, context, &tmp);
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
	PARAM_SET_addControl(set, "{input}", isFormatOk_inputFile, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{T}", isFormatOk_utcTime, isContentOk_utcTime, NULL, extract_utcTime);
	PARAM_SET_addControl(set, "{d}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{pub-str}", isFormatOk_pubString, NULL, NULL, extract_pubString);

	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
	PARAM_SET_setParseOptions(set, "d", PST_PRSCMD_HAS_NO_VALUE | PST_PRSCMD_NO_TYPOS);

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

static int generate_filenames(ERR_TRCKR *err, IO_FILES *files) {
	int res;
	IO_FILES tmp;

	memset(&tmp.internal, 0, sizeof(tmp.internal));

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* If not specified, the input signature is read from stdin. */
	if (files->user.log == NULL) {
		if (files->user.sig == NULL || !strcmp(files->user.sig, "-")) {
			/* Output must go to a nameless temporary file before redirecting it to stdout. */
			tmp.internal.bStdout = 1;
		} else {
			/* Output must go to a named temporary file that is renamed appropriately on success. */
			res = temp_name(files->user.sig, &tmp.internal.tempSig);
			ERR_CATCH_MSG(err, res, "Error: could not generate temporary output log signature file name.");
			tmp.internal.outSig = strdup(files->user.sig);
			if (tmp.internal.outSig == NULL) {
				res = KT_OUT_OF_MEMORY;
				ERR_CATCH_MSG(err, res, "Error: could not duplicate output log signature file name.");
			}
		}
	} else {
		/* Generate input log signature file name. */
		res = concat_names(files->user.log, ".logsig", &tmp.internal.inSig);
		ERR_CATCH_MSG(err, res, "Error: could not generate input log signature file name.");

		/* Check if output would overwrite the input log signature file. */
		if (files->user.sig == NULL || !strcmp(files->user.sig, tmp.internal.inSig)) {
			/* Output must to go to a temporary file before overwriting the input log signature file. */
			res = temp_name(tmp.internal.inSig, &tmp.internal.tempSig);
			ERR_CATCH_MSG(err, res, "Error: could not generate temporary output log signature file name.");
			/* Input must kept in a backup file when overwritten by the output log signature file. */
			res = concat_names(tmp.internal.inSig, ".bak", &tmp.internal.backupSig);
			ERR_CATCH_MSG(err, res, "Error: could not generate backup input log signature file name.");
		} else if (!strcmp(files->user.sig, "-")) {
			/* Output must go to a nameless temporary file before redirecting it to stdout. */
			tmp.internal.bStdout = 1;
		} else {
			/* Output must go to a named temporary file that is renamed appropriately on success. */
			res = temp_name(files->user.sig, &tmp.internal.tempSig);
			ERR_CATCH_MSG(err, res, "Error: could not generate temporary output log signature file name.");
			tmp.internal.outSig = strdup(files->user.sig);
			if (tmp.internal.outSig == NULL) {
				res = KT_OUT_OF_MEMORY;
				ERR_CATCH_MSG(err, res, "Error: could not duplicate output log signature file name.");
			}
		}
	}
	files->internal = tmp.internal;
	memset(&tmp.internal, 0, sizeof(tmp.internal));
	res = KT_OK;

cleanup:

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
		/* Make sure that the input log signature exists. */
		tmp.files.inSig = fopen(files->internal.inSig, "rb");
		if (tmp.files.inSig == NULL) {
			if (errno == ENOENT) {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: no matching log signature file found for log file %s.", files->user.log);
			} else {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: could not open input log signature file %s.", files->internal.inSig);
			}
		}
	} else {
		/* If not specified, the input is taken from stdin. */
		tmp.files.inSig = stdin;
	}

	/* Output goes either to a named or nameless temporary file. */
	if (files->internal.bStdout) {
		tmp.files.outSig = tmpfile();
	} else {
		tmp.files.outSig = fopen(files->internal.tempSig, "wb");
	}
	if (tmp.files.outSig == NULL) {
		res = KT_IO_ERROR;
		ERR_CATCH_MSG(err, res, "Error: could not create temporary output log signature file.");
	}

	files->files = tmp.files;
	memset(&tmp.files, 0, sizeof(tmp.files));

	res = KT_OK;

cleanup:

	logksi_files_close(&tmp.files);
	return res;
}

static int rename_temporary_and_backup_files(ERR_TRCKR *err, IO_FILES *files) {
	int res;
	char buf[1024];
	size_t count = 0;

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Check if input log signature must be backed up. */
	if (files->internal.backupSig) {
		/* Create a backup of the input log signature file by renaming it. */
		logksi_file_close(&files->files.inSig);
		res = logksi_remove_file(files->internal.backupSig);
		ERR_CATCH_MSG(err, res, "Error: could not remove existing backup file %s.", files->internal.backupSig);
		if (rename(files->internal.inSig, files->internal.backupSig) != 0) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not rename input log signature file %s to backup file %s.", files->internal.inSig, files->internal.backupSig);
		}
		/* Output must be saved in input log signature file, so the temporary file is renamed. */
		logksi_file_close(&files->files.outSig);
		if (rename(files->internal.tempSig, files->internal.inSig) != 0) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not rename temporary file %s to input log signature file %s.", files->internal.tempSig, files->internal.inSig);
		}
	} else if (files->internal.tempSig) {
		logksi_file_close(&files->files.inSig);
		res = logksi_remove_file(files->internal.outSig);
		ERR_CATCH_MSG(err, res, "Error: could not remove existing output log signature file %s.", files->internal.outSig);
		/* Output must be saved in output log signature file, so the temporary file is renamed. */
		logksi_file_close(&files->files.outSig);
		if (rename(files->internal.tempSig, files->internal.outSig) != 0) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not rename temporary file %s to output log signature file %s.", files->internal.tempSig, files->internal.outSig);
		}
	} else if (files->internal.bStdout) {
		/* Copy the contents of the (nameless) temporary output log signature file to stdout. */
		if (files->files.outSig == NULL) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not access temporary output log signature file in read mode.");
		}
		if (fseek(files->files.outSig, 0, SEEK_SET) != 0) {
			res = KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not seek temporary output log signature file.");
		}
		while(!feof(files->files.outSig)) {
			count = fread(buf, 1, sizeof(buf), files->files.outSig);
			if (fwrite(buf, 1, count, stdout) != count) {
				res = KT_IO_ERROR;
				ERR_CATCH_MSG(err, res, "Error: could not write temporary output log signature file to stdout.");
			}
		}
	}

	logksi_filename_free(&files->internal.backupSig);
	res = KT_OK;

cleanup:

	/* Restore initial situation if something failed. */
	if (files && files->internal.backupSig) {
		if (!SMART_FILE_doFileExist(files->internal.inSig)) {
			if (rename(files->internal.backupSig, files->internal.inSig) != 0) {
				res = KT_IO_ERROR;
			}
		}
	}
	return res;
}

static void close_input_and_output_files(ERR_TRCKR *err, int res, IO_FILES *files) {
	if (files) {
		logksi_files_close(&files->files);
		if (files->internal.tempSig && res != KT_OK) {
			if (remove(files->internal.tempSig) != 0) {
				if (err) ERR_TRCKR_ADD(err, KT_IO_ERROR, "Error: could not remove temporary output log signature %s.", files->internal.tempSig);
			}
		}
		logksi_internal_filenames_free(&files->internal);
	}
}
