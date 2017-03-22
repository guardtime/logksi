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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ksi/ksi.h>
#include "logksi_err.h"
#include "param_set/param_set.h"
#include "smart_file.h"
#include "api_wrapper.h"

static int logksi_ErrToExitcode(int error_code) {
	switch (error_code) {
		case KSI_OK:
			return EXIT_SUCCESS;
		case KT_OUT_OF_MEMORY:
			return EXIT_OUT_OF_MEMORY;
		case KT_INVALID_ARGUMENT:
		case KT_COMPONENT_HAS_NO_IMPLEMENTATION:
		case KT_INDEX_OVF:
		case KT_UNKNOWN_ERROR:
			return EXIT_FAILURE;
		case KT_UNABLE_TO_SET_STREAM_MODE:
		case KT_IO_ERROR:
			return EXIT_IO_ERROR;
		case KT_INVALID_INPUT_FORMAT:
			return EXIT_INVALID_FORMAT;
		case KT_UNKNOWN_HASH_ALG:
			return EXIT_CRYPTO_ERROR;
		case KT_INVALID_CMD_PARAM:
			return EXIT_INVALID_CL_PARAMETERS;
		case KT_NO_PRIVILEGES:
			return EXIT_NO_PRIVILEGES;
		case KT_INVALID_CONF:
			return EXIT_INVALID_CONF;
		case KT_KSI_SIG_VER_IMPOSSIBLE:
		case KT_VERIFICATION_FAILURE:
			return EXIT_VERIFY_ERROR;
		case KT_PUBFILE_HAS_NO_PUBREC_TO_EXTEND_TO:
			return EXIT_EXTEND_ERROR;
		case KT_AGGR_LVL_LIMIT_TOO_SMALL:
			return EXIT_AGGRE_ERROR;
		default:
			return EXIT_FAILURE;
	}
}

static int param_set_ErrToExitcode(int error_code) {
	switch (error_code) {
		case PST_OK:
			return EXIT_SUCCESS;
		case PST_OUT_OF_MEMORY:
			return EXIT_OUT_OF_MEMORY;
		case PST_IO_ERROR:
			return EXIT_IO_ERROR;
		case PST_INVALID_FORMAT:
			return EXIT_INVALID_FORMAT;
		case PST_TASK_MULTIPLE_CONSISTENT_TASKS:
		case PST_TASK_ZERO_CONSISTENT_TASKS:
			return EXIT_INVALID_CL_PARAMETERS;
		default:
			return EXIT_FAILURE;
	}
}

static int smart_file_ErrToExitcode(int error_code) {
	switch (error_code) {
		case SMART_FILE_OK:
			return EXIT_SUCCESS;
		case SMART_FILE_OUT_OF_MEM:
			return EXIT_OUT_OF_MEMORY;
		case SMART_FILE_INVALID_MODE:
		case SMART_FILE_UNABLE_TO_OPEN:
		case SMART_FILE_UNABLE_TO_READ:
		case SMART_FILE_UNABLE_TO_WRITE:
		case SMART_FILE_DOES_NOT_EXIST:
		case SMART_FILE_PIPE_ERROR:
			return EXIT_IO_ERROR;
		case SMART_FILE_ACCESS_DENIED:
			return EXIT_NO_PRIVILEGES;
		default:
			return EXIT_FAILURE;
	}
}

static const char* logksiErrToString(int error_code) {
	switch (error_code) {
		case KSI_OK:
			return "OK.";
		case KT_OUT_OF_MEMORY:
			return "Logksi tool out of memory.";
		case KT_INVALID_ARGUMENT:
			return "Invalid argument.";
		case KT_UNABLE_TO_SET_STREAM_MODE:
			return "Unable to set stream mode.";
		case KT_IO_ERROR:
			return "IO error.";
		case KT_INDEX_OVF:
			return "Index is too large.";
		case KT_INVALID_INPUT_FORMAT:
			return "Invalid input data format";
		case KT_HASH_LENGTH_IS_NOT_EVEN:
			return "The hash length is not even number.";
		case KT_INVALID_HEX_CHAR:
			return "The hex data contains invalid characters.";
		case KT_UNKNOWN_HASH_ALG:
			return "The hash algorithm is unknown or unimplemented.";
		case KT_INVALID_CMD_PARAM:
			return "The command-line parameters is invalid or missing.";
		case KT_NO_PRIVILEGES:
			return "User has no privileges.";
		case KT_KSI_SIG_VER_IMPOSSIBLE:
			return "Verification can't be performed.";
		case KT_VERIFICATION_FAILURE:
			return "Log signature verification failed.";
		case KT_PUBFILE_HAS_NO_PUBREC_TO_EXTEND_TO:
			return "No publication record found to extend to.";
		case KT_AGGR_LVL_LIMIT_TOO_SMALL:
			return "Local aggregation tree size limit is too small.";
		case KT_UNKNOWN_ERROR:
			return "Unknown error.";
		default:
			return "Unknown error.";
	}
}


int LOGKSI_errToExitCode(int error) {
	int exit;

	if (error < LOGKSI_ERR_BASE)
		exit = LOGKSI_KSI_ERR_toExitCode(error);
	else if (error >= LOGKSI_ERR_BASE && error < PARAM_SET_ERROR_BASE)
		exit = logksi_ErrToExitcode(error);
	else if (error >= PARAM_SET_ERROR_BASE && error < SMART_FILE_ERROR_BASE)
		exit = param_set_ErrToExitcode(error);
	else
		exit = smart_file_ErrToExitcode(error);

	return exit;
}

const char* LOGKSI_errToString(int error) {
	const char* str;

	if (error < LOGKSI_ERR_BASE)
		str = KSI_getErrorString(error);
	else if (error >= LOGKSI_ERR_BASE && error < PARAM_SET_ERROR_BASE)
		str = logksiErrToString(error);
	else if (error >= PARAM_SET_ERROR_BASE && error < SMART_FILE_ERROR_BASE)
		str = PARAM_SET_errorToString(error);
	else
		str = SMART_FILE_errorToString(error);

	return str;
}
