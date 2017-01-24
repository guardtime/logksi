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

static int extend_to_nearest_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext);
static int extend_to_specified_time(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext);
static int extend_to_specified_publication(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_VerificationContext *context, KSI_Signature **ext);
static int generate_tasks_set(PARAM_SET *set, TASK_SET *task_set);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);
static int get_backup_name(char *org, char **backup);
static int get_temp_name(char **name);
static int open_input_and_output_files(ERR_TRCKR *err, IO_FILES *files);
static void close_input_and_output_files(int result, IO_FILES *files);

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

	res = PARAM_SET_getStr(set, "input", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.inLogName);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "o", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.outSigName);
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

	res = logsignature_extend(set, err, ksi, extend_signature, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	close_input_and_output_files(res, &files);

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
		" %s extend [<logfile>] [-o <out.logsig>] -X <URL>\n"
		"    [--ext-user <user> --ext-key <key>] -P <URL> [--cnstr <oid=value>]... [more_options]\n"
		" %s extend [<logfile>] [-o <out.logsig>] -X <URL>\n"
		"    [--ext-user <user> --ext-key <key>] -P <URL> [--cnstr <oid=value>]... [--pub-str <str>] [more_options]\n"
		" %s extend [<logfile>] [-o <out.logsig>] --conf <logksi.conf> [more_options]\n"
		"\n"
		" <logfile>\n"
		"           - File path to the log file whose log signature file is to be extended. If not specified,\n"
		"             the log signature is read from <stdin>.\n"
		" -o <out.logsig>\n"
		"           - Output file path for the extended log signature file. Use '-' to redirect the extended\n"
		"             log signature binary stream to <stdout>. If not specified, the log signature is saved\n"
		"             to <in.logsig> while a backup of <in.logsig> is saved in <in.logsig.bak>.\n"
		"             If specified, existing file is always overwritten.\n"
		"             If both input and output are not specified, <stdin> and <stdout> are used resepectively.\n"
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
		"             All values from lower priority source are ignored.\n"
		" -d        - Print detailed information about processes and errors to <stderr>.\n"
		" --conf <file>\n"
		"             Read configuration options from given file.\n"
		"             Configuration options given explicitly on command line will\n"
		"             override the ones in the configuration file.\n"
		" --log <file>\n"
		"           - Write libksi log to given file. Use '-' as file name to redirect\n"
		"             log to <stdout>.\n",
		TOOL_getName(),
		TOOL_getName(),
		TOOL_getName()
	);

	return buf;
}
const char *extend_get_desc(void) {
	return "Extends existing KSI signature to the given publication.";
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
	res = KSITOOL_extendSignature(err, ksi, sig, context, &tmp);
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
	print_progressDesc(d, "Extending the signature to %s (%i)... ",
			KSI_Integer_toDateString(pubTime, buf, sizeof(buf)),
			KSI_Integer_getUInt64(pubTime));
	res = KSITOOL_Signature_extendTo(err, sig, ksi, pubTime, context, &tmp);
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
	res = KSITOOL_Signature_extend(err, sig, ksi, pub_rec, context, &tmp);
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
	PARAM_SET_addControl(set, "{input}", isFormatOk_inputFile, isContentOk_inputFileWithPipe, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{T}", isFormatOk_utcTime, isContentOk_utcTime, NULL, extract_utcTime);
	PARAM_SET_addControl(set, "{d}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{pub-str}", isFormatOk_pubString, NULL, NULL, extract_pubString);

	PARAM_SET_setParseOptions(set, "input", PST_PRSCMD_COLLECT_LOOSE_VALUES | PST_PRSCMD_HAS_NO_FLAG | PST_PRSCMD_NO_TYPOS);
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

static int get_derived_name(char *org, const char *extension, char **derived) {
	int res;
	char *buf = NULL;

	if (org == NULL || extension == NULL || derived == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}
	buf = (char*)KSI_malloc(strlen(org) + strlen(extension) + 1);
	if (buf == NULL) {
		res = KT_OUT_OF_MEMORY;
		goto cleanup;
	}
	sprintf(buf, "%s%s", org, extension);
	*derived = buf;
	res = KT_OK;

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

	if (err == NULL || files == NULL) {
		res = KT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Default input file is stdin. */
	if (files->inLogName == NULL) {
		/* Default output file is a temporary file that is copied to stdout on success. */
		if (files->outSigName == NULL || !strcmp(files->outSigName, "-")) {
			res = get_temp_name(&tmp.tempSigName);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			tmp.outSigName = tmp.tempSigName;
		} else {
			tmp.outSigName = files->outSigName;
		}
	} else {
		res = get_derived_name(files->inLogName, ".logsig", &tmp.derivedSigName);
		ERR_CATCH_MSG(err, res, "Error: out of memory.");

		/* Default output file is the same as input, but a backup of the input file is retained. */
		if (files->outSigName == NULL || !strcmp(tmp.derivedSigName, files->outSigName)) {
			res = get_backup_name(tmp.derivedSigName, &buf);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			remove(buf);
			res = (rename(tmp.derivedSigName, buf) == 0) ? KT_OK : KT_IO_ERROR;
			ERR_CATCH_MSG(err, res, "Error: could not rename file %s to %s.", tmp.derivedSigName, buf);
			tmp.backupSigName = buf;
			buf = NULL;
			tmp.inSigName = tmp.backupSigName;
			tmp.outSigName = tmp.derivedSigName;
		} else if (!strcmp(files->outSigName, "-")) {
			res = get_temp_name(&tmp.tempSigName);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			tmp.inSigName = tmp.derivedSigName;
			tmp.outSigName = tmp.tempSigName;
		} else {
			tmp.inSigName = tmp.derivedSigName;
			tmp.outSigName = files->outSigName;
		}
	}

	if (tmp.inSigName) {
		tmp.inSigFile = fopen(tmp.inSigName, "rb");
		res = (tmp.inSigFile == NULL) ? KT_IO_ERROR : KT_OK;
		ERR_CATCH_MSG(err, res, "Error: could not open file %s.", tmp.inSigName);
	} else {
		tmp.inSigFile = stdin;
	}

	if (tmp.outSigName) {
		tmp.outSigFile = fopen(tmp.outSigName, "wb");
		res = (tmp.outSigFile == NULL) ? KT_IO_ERROR : KT_OK;
		ERR_CATCH_MSG(err, res, "Error: could not create file %s.", tmp.outSigName);
	} else {
		tmp.outSigFile = stdout;
	}

	tmp.inLogName = files->inLogName;
	tmp.outSigName = files->outSigName;
	*files = tmp;
	memset(&tmp, 0, sizeof(tmp));
	res = KT_OK;

cleanup:

	if (tmp.inSigFile == stdin) tmp.inSigFile = NULL;
	if (tmp.outSigFile == stdout) tmp.outSigFile = NULL;

	if (tmp.backupSigName) {
		if (tmp.inSigFile) fclose(tmp.inSigFile);
		tmp.inSigFile = NULL;
		rename(tmp.backupSigName, files->inSigName);
		KSI_free(tmp.backupSigName);
	}
	if (tmp.tempSigName) {
		if (tmp.outSigFile) fclose(tmp.outSigFile);
		tmp.outSigFile = NULL;
		KSI_free(tmp.tempSigName);
	}
	KSI_free(buf);

	if (tmp.derivedSigName) {
		KSI_free(tmp.derivedSigName);
	}

	if (tmp.inSigFile) fclose(tmp.inSigFile);
	if (tmp.outSigFile) fclose(tmp.outSigFile);

	return res;
}

static void close_input_and_output_files(int result, IO_FILES *files) {
	char buf[1024];
	size_t count = 0;

	if (files == NULL) return;

	if (files->inSigFile == stdin) files->inSigFile = NULL;
	if (files->outSigFile == stdout) files->outSigFile = NULL;

	if (files->tempSigName) {
		if (result == KT_OK) {
			freopen(NULL, "rb", files->outSigFile);
			while (!feof(files->outSigFile)) {
				count = fread(buf, 1, sizeof(buf), files->outSigFile);
				fwrite(buf, 1, count, stdout);
			}
		}
		fclose(files->outSigFile);
		files->outSigFile = NULL;
		remove(files->tempSigName);
		KSI_free(files->tempSigName);
	}

	if (files->backupSigName) {
		if (result != KT_OK) {
			fclose(files->outSigFile);
			files->outSigFile = NULL;
			remove(files->derivedSigName);
			fclose(files->inSigFile);
			files->inSigFile = NULL;
			rename(files->backupSigName, files->derivedSigName);
		}
		KSI_free(files->backupSigName);
	}

	if (files->derivedSigName) {
		KSI_free(files->derivedSigName);
	}

	if (files->inSigFile) fclose(files->inSigFile);
	if (files->outSigFile) fclose(files->outSigFile);
}
