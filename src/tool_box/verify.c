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

static int signature_verify(int id, PARAM_SET *set, ERR_TRCKR *err, COMPOSITE *extra, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_general(PARAM_SET *set, ERR_TRCKR *err, COMPOSITE *extra, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_internally(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_key_based(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_publication_based_with_user_pub(PARAM_SET *set, ERR_TRCKR *err, COMPOSITE *extra, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_publication_based_with_pubfile(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi,  KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int signature_verify_calendar_based(PARAM_SET *set, ERR_TRCKR *err, KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh, KSI_PolicyVerificationResult **out);
static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err);

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
	COMPOSITE extra;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_HashAlgorithm alg = KSI_HASHALG_INVALID;

	/**
	 * Extract command line parameters and also add configuration specific parameters.
	 */
	res = PARAM_SET_new(
			CONF_generate_param_set_desc("{i}{x}{f}{d}{pub-str}{ver-int}{ver-cal}{ver-key}{ver-pub}{dump}{conf}{log}{h|help}", "XP", buf, sizeof(buf)),
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

	res = check_pipe_errors(set, err);
	if (res != KT_OK) goto cleanup;


	extra.ctx = ksi;
	extra.err = err;
	extra.fname_out = NULL;

	print_progressDesc(d, "Reading signature... ");
	res = PARAM_SET_getObjExtended(set, "i", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &extra, (void**)&sig);
	if (res != PST_OK) goto cleanup;
	print_progressResult(res);

	/**
	 * Get document hash if provided by user.
	 */
	if (PARAM_SET_isSetByName(set, "f")) {
		res = KSI_Signature_getHashAlgorithm(sig, &alg);
		if (res != KSI_OK) goto cleanup;
		extra.h_alg = &alg;

		print_progressDesc(d, "Reading documents hash... ");
		/* TODO: fix hash extractor from file. */
		res = PARAM_SET_getObjExtended(set, "f", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, &extra, (void**)&hsh);
		if (res != PST_OK) goto cleanup;
		print_progressResult(res);
	}

	/**
	 * Verify the signature accordingly to the selected method.
	 */
	res = signature_verify(TASK_getID(task), set, err, &extra, ksi, sig, hsh, &result);
	/* Fall through: if (res != KT_OK) goto cleanup; */

	if (PARAM_SET_isSetByName(set, "dump")) {
		/**
		 * Dump signature.
		 */
		print_result("\n");
		OBJPRINT_signatureDump(sig, print_result);
		/**
		 * Dump verification result data.
		 */
		print_result("\n");
		OBJPRINT_signatureVerificationResultDump(result, print_result);
		/**
		 * Dump document hash.
		 */
		if (PARAM_SET_isSetByName(set, "f")) {
			print_result("\n");
			OBJPRINT_Hash(hsh, "Document hash: ", print_result);
		}
	}

cleanup:
	print_progressResult(res);
	KSITOOL_KSI_ERRTrace_save(ksi);

	if (res != KT_OK) {
		if (ERR_TRCKR_getErrCount(err) == 0) {ERR_TRCKR_ADD(err, res, NULL);}
		KSITOOL_KSI_ERRTrace_LOG(ksi);
		print_debug("\n");
		DEBUG_verifySignature(ksi, res, sig, result, hsh);

		print_errors("\n");
		if (d) ERR_TRCKR_printExtendedErrors(err);
		else  ERR_TRCKR_printErrors(err);
	}

	SMART_FILE_close(logfile);
	PARAM_SET_free(set);
	TASK_SET_free(task_set);
	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_PolicyVerificationResult_free(result);
	ERR_TRCKR_free(err);
	KSI_CTX_free(ksi);

	return KSITOOL_errToExitCode(res);
}

char *verify_help_toString(char *buf, size_t len) {
	size_t count = 0;

	count += KSI_snprintf(buf + count, len - count,
		"Usage:"
		" %s verify -i <in.ksig> [-f <data>] [more_options]\n"
		" %s verify --ver-int -i <in.ksig> [-f <data>] [more_options]\n"
		" %s verify --ver-cal -i <in.ksig> [-f <data>] -X <URL>\n"
		"     [--ext-user <user> --ext-key <key>] [more_options]\n"
		" %s verify --ver-key -i <in.ksig> [-f <data>] -P <URL>\n"
		"     [--cnstr <oid=value>]... [more_options]\n"
		" %s verify --ver-pub -i <in.ksig> [-f <data>] --pub-str <pubstring>\n"
		"     [-x -X <URL>  [--ext-user <user> --ext-key <key>]] [more_options]\n"
		" %s verify --ver-pub -i <in.ksig> [-f <data>] -P <URL> [--cnstr <oid=value>]...\n"
		"        [-x -X <URL>  [--ext-user <user> --ext-key <key>]] [more_options]\n"
		"\n"
		" --ver-int - Perform internal verification.\n"
		" --ver-cal - Perform calendar-based verification (use extending service).\n"
		" --ver-key - Perform key-based verification.\n"
		" --ver-pub - Perform publication-based verification (use with -x to permit extending).\n"
		" -i <in.ksig>\n"
		"           - Signature file to be verified. Use '-' as file name to read\n"
		"             the signature from stdin.\n"
		" -f <data> - Path to file to be hashed or data hash imprint to extract the hash\n"
		"             value that is going to be verified. Hash format: <alg>:<hash in hex>.\n"
		"             Use '-' as file name to read data to be hashed from stdin.\n"
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
	return "Verifies existing KSI signature.";
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
	PARAM_SET_addControl(set, "{i}", isFormatOk_inputFile, isContentOk_inputFileWithPipe, convertRepair_path, extract_inputSignature);
	PARAM_SET_addControl(set, "{f}", isFormatOk_inputHash, isContentOk_inputHash, convertRepair_path, extract_inputHash);
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

static int signature_verify(int id, PARAM_SET *set, ERR_TRCKR *err, COMPOSITE *extra,
							KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh,
							KSI_PolicyVerificationResult **out) {
	int res;

	if (set == NULL || err == NULL || ksi == NULL || sig == NULL || out == NULL) {
		ERR_TRCKR_ADD(err, res = KT_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	switch(id) {
		case ANC_BASED_DEFAULT:
		case ANC_BASED_PUB_FILE:
		case ANC_BASED_PUB_FILE_X:
		case ANC_BASED_PUB_SRT:
		case ANC_BASED_PUB_SRT_X:
			res = signature_verify_general(set, err, extra, ksi, sig, hsh, out);
			goto cleanup;
		case INT_BASED:
			res = signature_verify_internally(set, err, ksi, sig, hsh, out);
			goto cleanup;
		case CAL_BASED:
			res = signature_verify_calendar_based(set, err, ksi, sig, hsh, out);
			goto cleanup;
		case KEY_BASED:
			res = signature_verify_key_based(set, err, ksi, sig, hsh, out);
			goto cleanup;
		case PUB_BASED_FILE:
		case PUB_BASED_FILE_X:
			res = signature_verify_publication_based_with_pubfile(set, err, ksi, sig, hsh, out);
			goto cleanup;
		case PUB_BASED_STR:
		case PUB_BASED_STR_X:
			res = signature_verify_publication_based_with_user_pub(set, err, extra, ksi, sig, hsh, out);
			goto cleanup;
		default:
			ERR_CATCH_MSG(err, (res = KT_UNKNOWN_ERROR), "Error: Unknown signature verification task.");
			goto cleanup;
	}

cleanup:
	print_progressResult(res);

	return res;
}

static int signature_verify_general(PARAM_SET *set, ERR_TRCKR *err, COMPOSITE *extra,
									KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh,
									KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	int x = PARAM_SET_isSetByName(set, "x");
	KSI_PublicationData *pub_data = NULL;
	static const char *task = "Signature verification according to trust anchor";

	/**
	 * Get Publication data if available.
	 */
	if (PARAM_SET_isSetByName(set, "pub-str")) {
		res = PARAM_SET_getObjExtended(set, "pub-str", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, extra, (void**)&pub_data);
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

static int signature_verify_publication_based_with_user_pub(PARAM_SET *set, ERR_TRCKR *err, COMPOSITE *extra,
															KSI_CTX *ksi, KSI_Signature *sig, KSI_DataHash *hsh,
															KSI_PolicyVerificationResult **out) {
	int res;
	int d = PARAM_SET_isSetByName(set, "d");
	int x = PARAM_SET_isSetByName(set, "x");
	KSI_PublicationData *pub_data = NULL;
	static const char *task = "Signature publication-based verification with user publication string";

	/**
	 * Get Publication data.
	 */
	res = PARAM_SET_getObjExtended(set, "pub-str", NULL, PST_PRIORITY_HIGHEST, PST_INDEX_LAST, extra, (void**)&pub_data);
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

static int check_pipe_errors(PARAM_SET *set, ERR_TRCKR *err) {
	int res;

	res = get_pipe_in_error(set, err, NULL, "i,f", NULL);
	if (res != KT_OK) goto cleanup;

cleanup:
	return res;
}
