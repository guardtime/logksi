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
#include <ksi/compatibility.h>
#include "param_set/param_set.h"
#include "logksi_err.h"
#include "printer.h"
#include "conf_file.h"
#include "tool.h"
#include "default_tasks.h"
#include "common.h"

static void print_conf_file(const char *fname, int (*print)(const char *format, ... ));

int conf_run(int argc, char** argv, char **envp) {
	int res;
	PARAM_SET *set = NULL;
	PARAM_SET *configuration = NULL;
	char buf[0xffff];

	res = PARAM_SET_new("{h|help}{dump}{d}", &set);
	if (res != PST_OK) goto cleanup;


	res = PARAM_SET_parseCMD(set, argc, argv, "CMD", 3);
	if (res != PST_OK) {
		print_errors("Error: Unable to parse command-line.\n");
		goto cleanup;
	}

	res = CONF_createSet(&configuration);
	if (res != KT_OK) goto cleanup;

	/**
	 * Check for typos and unknown parameters.
     */
	if (PARAM_SET_isTypoFailure(set)) {
			print_errors("%s\n", PARAM_SET_typosToString(set, PST_TOSTR_DOUBLE_HYPHEN, NULL, buf, sizeof(buf)));
			res = KT_INVALID_CMD_PARAM;
			goto cleanup;
	} else if (PARAM_SET_isUnknown(set)){
			print_errors("%s\n", PARAM_SET_unknownsToString(set, "Error: ", buf, sizeof(buf)));
			res = KT_INVALID_CMD_PARAM;
			goto cleanup;
	}

	if (!CONF_isEnvSet()) {
		res = CONF_fromEnvironment(configuration, "KSI_CONF", envp, 0, 1);
		res = conf_report_errors(configuration, CONF_getEnvNameContent(), res);
		if (res != KT_OK) goto cleanup;
	}
	if (PARAM_SET_isSetByName(set, "dump")) {
		if (CONF_isEnvSet()) {
			print_conf_file(CONF_getEnvNameContent(), print_result);
			print_result("\n");
		}
	} else if (PARAM_SET_isSetByName(set, "d")) {
		if (CONF_isEnvSet()) {
			print_debug("%s\n", CONF_getEnvNameContent());
		}
	} else {
		print_result("%s\n", conf_help_toString(buf, sizeof(buf)));
	}

	res = KT_OK;

cleanup:

	PARAM_SET_free(set);
	PARAM_SET_free(configuration);

	return LOGKSI_errToExitCode(res);
}

char *conf_help_toString(char *buf, size_t len) {
	size_t count = 0;

	if (buf == NULL || len == 0) return NULL;

	count += KSI_snprintf(buf + count, len - count,
		"Usage:\n"
		" %s conf -h | -d | --dump \n"
		" -d        - Print KSI_CONF value to stderr if is configured.\n"
		" --dump    - Dump configuration file pointed by KSI_CONF to stdout.\n"
		" -h        - Print the current help message.\n",
		TOOL_getName()
	);

	count += KSI_snprintf(buf + count, len - count,
		"KSI configuration file help:\n\n"
		"  The log signature command-line tool has several configuration options related to\n"
		"  the KSI service configuration (e.g. KSI signing service URL and access credentials).\n"
		"  The configuration options are described below. There are following ways to specify\n"
		"  these configuration options:\n\n"

		"   * directly on command line (highest priority);\n"
		"   * in a file specified by the '--conf' command-line argument;\n"
		"   * in a file specified by the KSI_CONF environment variable (lowest priority).\n\n"

		"  If a configuration option is specified in more than one source (e.g. both directly\n"
		"  on command-line argument and in a configuration file) the source with the highest\n"
		"  priority will be used. A short parameter or multiple flags must have prefix '-' and\n"
		"  long parameters have prefix '--'. If some parameter values contain whitespace\n"
		"  characters double quote marks (\") must be used to wrap the entire value. If double\n"
		"  quote mark or backslash have to be used inside the value part an escape character\n"
		"  (\\) must be typed before the character(\\\" or \\\\). If configuration option with\n"
		"  unknown or invalid key-value pairs is used, an error is generated.\n\n"

		"  In configuration file each key-value pair must be placed on a single line. Start\n"
		"  the line with # to write a comment. Not full paths (V, W and P with URI scheme\n"
		"  'file://') are interpreted as relative to the configuration file.\n\n"

		"All known parameters:\n"
		);

	count += KSI_snprintf(buf + count, len - count,
		" -S <URL>  - Signing service (KSI Aggregator) URL.\n"
		" --aggr-user <user>\n"
		"           - Username for signing service.\n"
		" --aggr-key <key>\n"
		"           - HMAC key for signing service.\n"
		" --aggr-hmac-alg <alg>\n"
		"           - Hash algorithm to be used for computing HMAC on outgoing messages towards\n"
		"             KSI aggregator. If not set, default algorithm is used.\n"
		" -X <URL>  - Extending service (KSI Extender) URL.\n"
		" --ext-user <user>\n"
		"           - Username for extending service.\n"
		" --ext-key <key>\n"
		"           - HMAC key for extending service.\n"
		" --ext-hmac-alg <alg>\n"
		"           - Hash algorithm to be used for computing HMAC on outgoing messages towards\n"
		"             KSI extender. If not set, default algorithm is used.\n"
		" -P <URL>  - Publications file URL (or file with URI scheme 'file://').\n"
		" --cnstr <oid=value>\n"
		"           - OID of the PKI certificate field (e.g. e-mail address) and the expected\n"
		"             value to qualify the certificate for verification of publications file\n"
		"             PKI signature. At least one constraint must be defined.\n"
		" -V        - Certificate file in PEM format for publications file verification.\n"
		" -W <dir>  - OpenSSL-style trust store directory for publications file verification.\n"
		" -C <int>  - Set network connect timeout in seconds (is not supported with TCP client).\n"
		" -c <int>  - Set network transfer timeout, after successful connect, in seconds.\n"
		" --publications-file-no-verify\n"
		"           - A flag to force the tool to trust the publications file without\n"
		"             verifying it. The flag can only be defined on command-line to avoid\n"
		"             the usage of insecure configuration files. It must be noted that the\n"
		"             option is insecure and may only be used for testing.\n"
		"\n"
		"\n"
		);

	/*count += */KSI_snprintf(buf + count, len - count,
		"An example configuration file:\n\n"
		" # --- BEGINNING ---\n"
		" # KSI Signing service parameters:\n"
		" -S http://example.gateway.com:3333/gt-signingservice\n"
		" --aggr-user anon\n"
		" --aggr-key anon\n"
		"\n"
		" # KSI Extending service:\n"
		" # Note that ext-key real value is &h/J\"kv\\G##\n"
		" -X http://example.gateway.com:8010/gt-extendingservice\n"
		" --ext-user anon\n"
		" --ext-key \"&h/J\\\"kv\\\\G##\"\n"
		"\n"
		" # KSI Publications file:\n"
		" -P http://verify.guardtime.com/ksi-publications.bin\n"
		" --cnstr email=publications@guardtime.com\n"
		" --cnstr \"org=Guardtime AS\"\n"
		" # --- END ---\n"
		"\n"
		);


	return buf;
}

const char *conf_get_desc(void) {
	return "KSI Service configuration file utility.";
}

static void print_conf_file(const char *fname, int (*print)(const char *format, ... )) {
	FILE *f = NULL;
	char buf[1024];
	size_t count = 0;

	if (fname == NULL || print == NULL) return;

	f = fopen(fname, "r");
	if (f == NULL) print("Error: Unable to read file for printing '%s'.\n", fname);

	while (!feof(f)) {
		buf[0] = '\0';
		count = fread(buf, 1, sizeof(buf) - 1, f);
		if (feof(f)) buf[count] = '\0';
		print("%s", buf);
	}
	fclose(f);
	return;
}
