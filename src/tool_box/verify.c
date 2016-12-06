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
#include "smart_file.h"
#include "err_trckr.h"
#include "api_wrapper.h"
#include "printer.h"
#include "debug_print.h"
#include "obj_printer.h"
#include "conf_file.h"
#include "tool.h"
#include "rsyslog.h"

enum {
	/* Trust anchor based verification. */
	ANC_BASED_DEFAULT,
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

static int signature_verify_general(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_internally(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_key_based(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_publication_based_with_user_pub(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_publication_based_with_pubfile(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi,  KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_calendar_based(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int open_log_and_signature_files(ERR_TRCKR *err, IO_FILES *files);
static void close_log_and_signature_files(IO_FILES *files);

int verify_run(int argc, char **argv, char **envp) {
	int res;
	char buf[2048];
	PARAM_SET *set = NULL;
	TASK_SET *task_set = NULL;
	TASK *task = NULL;
	KSI_CTX *ksi = NULL;
	ERR_TRCKR *err = NULL;
	SMART_FILE *logfile = NULL;
	int d = 0;
	KSI_Signature *sig = NULL;
	IO_FILES files;
	VERIFYING_FUNCTION verify_signature = NULL;

	memset(&files, 0, sizeof(files));

	/**
	 * Extract command line parameters and also add configuration specific parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{i}{x}{s}{d}{pub-str}{ver-int}{ver-cal}{ver-key}{ver-pub}{dump}{conf}{log}{h|help}", "XP", buf, sizeof(buf)),
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

	d = PARAM_SET_isSetByName(set, "d");

	res = PARAM_SET_getStr(set, "i", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.inLogName);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	res = PARAM_SET_getStr(set, "s", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &files.inSigName);
	if (res != KT_OK && res != PST_PARAMETER_EMPTY) goto cleanup;

	switch(TASK_getID(task)) {
		case ANC_BASED_DEFAULT:
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

	res = open_log_and_signature_files(err, &files);
	if (res != KT_OK) goto cleanup;

	res = logsignature_verify(set, err, ksi, verify_signature, &files);
	if (res != KT_OK) goto cleanup;

cleanup:

	close_log_and_signature_files(&files);

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
	KSI_Signature_free(sig);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);

	return KSITOOL_errToExitCode(res);
}

char *verify_help_toString(char *buf, size_t len) {
	size_t count = 0;

	count += KSI_snprintf(buf + count, len - count,
		"Usage:"
		" %s verify -i <log> [-s <logsignature.ls11>] [more_options]\n"
		" %s verify --ver-int -i <log> [-s <logsignature.ls11>] [more_options]\n"
		" %s verify --ver-cal -i <log> [-s <logsignature.ls11>] -X <URL>\n"
		"     [--ext-user <user> --ext-key <key>] [more_options]\n"
		" %s verify --ver-key -i <log> [-s <logsignature.ls11>] -P <URL>\n"
		"     [--cnstr <oid=value>]... [more_options]\n"
		" %s verify --ver-pub -i <log> [-s <logsignature.ls11>] --pub-str <pubstring>\n"
		"     [-x -X <URL>  [--ext-user <user> --ext-key <key>]] [more_options]\n"
		" %s verify --ver-pub -i <log> [-s <logsignature.ls11>] -P <URL> [--cnstr <oid=value>]...\n"
		"        [-x -X <URL>  [--ext-user <user> --ext-key <key>]] [more_options]\n"
		"\n"
		" --ver-int - Perform internal verification.\n"
		" --ver-cal - Perform calendar-based verification (use extending service).\n"
		" --ver-key - Perform key-based verification.\n"
		" --ver-pub - Perform publication-based verification (use with -x to permit extending).\n"
		" -i <log>\n"
		"           - Log file to be verified.\n"
		" -s <logsignature.ls11>\n"
		"             Log signature file to be verified. If omitted, the log signature file name is\n"
		"             derived by adding .ls11 or .ksisig to <log>. It is expected to be found in the\n"
		"             same folder as the <log> file.\n"
		" -x        - Permit to use extender for publication-based verification.\n"
		" -X <URL>  - Extending service (KSI Extender) URL.\n"
		" --ext-user <user>\n"
		"           - Username for extending service.\n"
		" --ext-key <key>\n"
		"           - HMAC key for extending service.\n"
		" --pub-str <str>\n"
		"           - Publication string to verify with.\n"
		" -P <URL>  - Publications file URL (or file with URI scheme 'file://').\n"
		" --cnstr <oid=value>\n"
		"           - OID of the PKI certificate field (e.g. e-mail address) and the expected\n"
		"             value to qualify the certificate for verification of publications file\n"
		"             PKI signature. At least one constraint must be defined.\n"
		" -V        - Certificate file in PEM format for publications file verification.\n"
		"             All values from lower priority source are ignored.\n"
		"\n"
		" -d        - Print detailed information about processes and errors to stderr.\n"
		" --dump    - Dump signature and document hash being verified in human-readable format to stdout.\n"
		" --conf <file>\n"
		"             Read configuration options from given file. It must be noted\n"
		"             that configuration options given explicitly on command line will\n"
		"             override the ones in the configuration file.\n"
		" --log <file>\n"
		"           - Write libksi log to given file. Use '-' as file name to redirect log to stdout.\n",
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
	PARAM_SET_addControl(set, "{log}", isFormatOk_path, NULL, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{i}{s}", isFormatOk_inputFile, isContentOk_inputFile, convertRepair_path, NULL);
//	PARAM_SET_addControl(set, "{s}", isFormatOk_inputFile, isContentOk_inputFile, convertRepair_path, NULL);
	PARAM_SET_addControl(set, "{d}{x}{ver-int}{ver-cal}{ver-key}{ver-pub}{dump}", isFormatOk_flag, NULL, NULL, NULL);
	PARAM_SET_addControl(set, "{pub-str}", isFormatOk_pubString, NULL, NULL, extract_pubString);

	/*						ID						DESC								MAN							ATL		FORBIDDEN											IGN	*/
	TASK_SET_add(task_set,	ANC_BASED_DEFAULT,		"Verify.",							"i",						NULL,	"ver-int,ver-cal,ver-key,ver-pub,P,cnstr,pub-str",	NULL);
	TASK_SET_add(task_set,	ANC_BASED_PUB_FILE,		"Verify, "
													"use publications file, "
													"extending is restricted.",			"i,P,cnstr",				NULL,	"ver-int,ver-cal,ver-key,ver-pub,x,T,pub-str",		NULL);
	TASK_SET_add(task_set,	ANC_BASED_PUB_FILE_X,	"Verify, "
													"use publications file, "
													"extending is permitted.",			"i,P,cnstr,x,X",			NULL,	"ver-int,ver-cal,ver-key,ver-pub,T,pub-str",		NULL);
	TASK_SET_add(task_set,	ANC_BASED_PUB_SRT,		"Verify, "
													"use publications string, "
													"extending is restricted.",			"i,pub-str",				NULL,	"ver-int,ver-cal,ver-key,ver-pub,x",				NULL);
	TASK_SET_add(task_set,	ANC_BASED_PUB_SRT_X,	"Verify, "
													"use publications string, "
													"extending is permitted.",			"i,pub-str,x,X",			NULL,	"ver-int,ver-cal,ver-key,ver-pub",					NULL);

	TASK_SET_add(task_set,	INT_BASED,				"Verify internally.",				"ver-int,i",				NULL,	"ver-cal,ver-key,ver-pub,T,x,pub-str",				NULL);

	TASK_SET_add(task_set,	CAL_BASED,				"Calendar based verification.",		"ver-cal,i,X",				NULL,	"ver-int,ver-key,ver-pub,pub-str",					NULL);

	TASK_SET_add(task_set,	KEY_BASED,				"Key based verification.",			"ver-key,i,P,cnstr",		NULL,	"ver-int,ver-cal,ver-pub,T,x,pub-str",				NULL);

	TASK_SET_add(task_set,	PUB_BASED_FILE,			"Publication based verification, "
													"use publications file, "
													"extending is restricted.",			"ver-pub,i,P,cnstr",		NULL,	"ver-int,ver-cal,ver-key,x,T,pub-str",				NULL);
	TASK_SET_add(task_set,	PUB_BASED_FILE_X,		"Publication based verification, "
													"use publications file, "
													"extending is permitted.",			"ver-pub,i,P,cnstr,x,X",	NULL,	"ver-int,ver-cal,ver-key,T,pub-str",				NULL);

	TASK_SET_add(task_set,	PUB_BASED_STR,			"Publication based verification, "
													"use publications string, "
													"extending is restricted.",			"ver-pub,i,pub-str",		NULL,	"ver-int,ver-cal,ver-key,x,T",						NULL);
	TASK_SET_add(task_set,	PUB_BASED_STR_X,		"Publication based verification, "
													"use publications string, "
													"extending is permitted.",			"ver-pub,i,pub-str,x,X",	NULL,	"ver-int,ver-cal,ver-key,T",						NULL);
cleanup:

	return res;
}

static int signature_verify_general(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi,
									KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out) {
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
	print_progressDesc(d, "%s... ", task);
	res = KSITOOL_SignatureVerify_general(err, sig, ksi, hsh, pub_data, x, out);
	if (*out != NULL) {
		ERR_CATCH_MSG(err, res, "Error: [%s] %s. %s failed.", OBJPRINT_getVerificationErrorCode((*out)->finalResult.errorCode),
				OBJPRINT_getVerificationErrorDescription((*out)->finalResult.errorCode), task);
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);

	KSI_PublicationData_free(pub_data);

	return res;
}

static int signature_verify_internally(PARAM_SET *set, ERR_TRCKR *err,
									   KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh,
									   KSI_PolicyVerificationResult **out) {
	int res;
	int d;
	static const char *task = "Signature internal verification";

	d = PARAM_SET_isSetByName(set, "d");

	print_progressDesc(d, "%s... ", task);
	res = KSITOOL_SignatureVerify_internally(err, sig, ksi, hsh, out);
	if (*out != NULL) {
		ERR_CATCH_MSG(err, res, "Error: [%s] %s. %s failed.", OBJPRINT_getVerificationErrorCode((*out)->finalResult.errorCode),
				OBJPRINT_getVerificationErrorDescription((*out)->finalResult.errorCode), task);
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);

	return res;
}


static int signature_verify_key_based(PARAM_SET *set, ERR_TRCKR *err,
									  KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh,
									  KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	static const char *task = "Signature key-based verification";

	/**
	 * Verify signature.
	 */
	print_progressDesc(d, "%s... ", task);
	res = KSITOOL_SignatureVerify_keyBased(err, sig, ksi, hsh, out);
	if (*out != NULL) {
		ERR_CATCH_MSG(err, res, "Error: [%s] %s. %s failed.", OBJPRINT_getVerificationErrorCode((*out)->finalResult.errorCode),
				OBJPRINT_getVerificationErrorDescription((*out)->finalResult.errorCode), task);
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);

	return res;
}

static int signature_verify_publication_based_with_user_pub(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi,
															KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out) {
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
	print_progressDesc(d, "%s... ", task);
	res = KSITOOL_SignatureVerify_userProvidedPublicationBased(err, sig, ksi, hsh, pub_data, x, out);
	if (*out != NULL) {
		ERR_CATCH_MSG(err, res, "Error: [%s] %s. %s failed.", OBJPRINT_getVerificationErrorCode((*out)->finalResult.errorCode),
				OBJPRINT_getVerificationErrorDescription((*out)->finalResult.errorCode), task);
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);

	KSI_PublicationData_free(pub_data);

	return res;
}

static int signature_verify_publication_based_with_pubfile(PARAM_SET *set, ERR_TRCKR *err,
														   KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh,
														   KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	int x = PARAM_SET_isSetByName(set, "x");
	static const char *task = "Signature publication-based verification with publications file";

	/**
	 * Verify signature.
	 */
	print_progressDesc(d, "%s... ", task);
	res = KSITOOL_SignatureVerify_publicationsFileBased(err, sig, ksi, hsh, x, out);
	if (*out != NULL) {
		ERR_CATCH_MSG(err, res, "Error: [%s] %s. %s failed.", OBJPRINT_getVerificationErrorCode((*out)->finalResult.errorCode),
				OBJPRINT_getVerificationErrorDescription((*out)->finalResult.errorCode), task);
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);

	return res;
}

static int signature_verify_calendar_based(PARAM_SET *set, ERR_TRCKR *err,
										   KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh,
										   KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	KSI_Integer *pubTime = NULL;
	static const char *task = "Signature calendar-based verification";

	/**
	 * Verify signature.
	 */
	print_progressDesc(d, "%s... ", task);
	res = KSITOOL_SignatureVerify_calendarBased(err, sig, ksi, hsh, out);
	if (*out != NULL) {
		ERR_CATCH_MSG(err, res, "Error: [%s] %s. %s failed.", OBJPRINT_getVerificationErrorCode((*out)->finalResult.errorCode),
				OBJPRINT_getVerificationErrorDescription((*out)->finalResult.errorCode), task);
	} else {
		ERR_CATCH_MSG(err, res, "Error: %s failed.", task);
	}

	res = KT_OK;

cleanup:

	print_progressResult(res);

	KSI_Integer_free(pubTime);

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

static int open_log_and_signature_files(ERR_TRCKR *err, IO_FILES *files) {
	int res = KT_IO_ERROR;
	IO_FILES tmp;
	int i = 0;

	memset(&tmp, 0, sizeof(tmp));

	if (files->inSigName == NULL) {
		/* Default log signature file name is derived from the log file name. */
		const char *extensions[] = {".ls11", ".ksisig", NULL};
		while (extensions[i]) {
			res = get_derived_name(files->inLogName, extensions[i], &tmp.derivedSigName);
			ERR_CATCH_MSG(err, res, "Error: out of memory.");
			if (SMART_FILE_doFileExist(tmp.derivedSigName)) break;
			KSI_free(tmp.derivedSigName);
			tmp.derivedSigName = NULL;
			i++;
		}
		if (tmp.derivedSigName == NULL) {
			res = KT_KSI_SIG_VER_IMPOSSIBLE;
			ERR_CATCH_MSG(err, res, "Error: no matching log signature file found for log file %s.", files->inLogName);
		}
		tmp.inSigName = tmp.derivedSigName;
	} else {
		tmp.inSigName = files->inSigName;
	}
	tmp.inLogName = files->inLogName;

	if (tmp.inSigName) {
		tmp.inSigFile = fopen(tmp.inSigName, "rb");
		res = (tmp.inSigFile == NULL) ? KT_IO_ERROR : KT_OK;
		ERR_CATCH_MSG(err, res, "Error: could not open file %s.", tmp.inSigName);
	}

	if (tmp.inLogName) {
		tmp.inLogFile = fopen(tmp.inLogName, "rb");
		res = (tmp.inLogFile == NULL) ? KT_IO_ERROR : KT_OK;
		ERR_CATCH_MSG(err, res, "Error: could not open file %s.", tmp.inLogName);
	}

	tmp.inSigName = files->inSigName;
	tmp.inLogName = files->inLogName;
	*files = tmp;
	memset(&tmp, 0, sizeof(tmp));
	res = KT_OK;

cleanup:

	if (tmp.derivedSigName) {
		if (tmp.inSigFile) fclose(tmp.inSigFile);
		tmp.inSigFile = NULL;
		KSI_free(tmp.derivedSigName);
	}

	if (tmp.inSigFile) fclose(tmp.inSigFile);
	if (tmp.inLogFile) fclose(tmp.inLogFile);

	return res;
}

static void close_log_and_signature_files(IO_FILES *files) {
	if (files->derivedSigName) {
		KSI_free(files->derivedSigName);
	}

	if (files->inSigFile) fclose(files->inSigFile);
	if (files->inLogFile) fclose(files->inLogFile);
}
