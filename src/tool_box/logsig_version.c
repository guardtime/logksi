/*
 * Copyright 2013-2019 Guardtime, Inc.
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
#include <stdlib.h>
#include <param_set/strn.h>
#include "logksi_err.h"
#include "smart_file.h"
#include "logsig_version.h"

struct magic_reference_st {
	const char* name;
	LOGSIG_VERSION ver;
};

#define _LGVR(v) {#v, v}
struct magic_reference_st magic_reference[NOF_VERS] = {_LGVR(LOGSIG11), _LGVR(LOGSIG12), _LGVR(RECSIG11), _LGVR(RECSIG12), _LGVR(LOG12BLK), _LGVR(LOG12SIG)};
#undef _LGVR

static LOGSIG_VERSION file_version_by_string(const char *str) {
	int i = 0;
	if (str == NULL) return UNKN_VER;

	for (i = 0; i < NOF_VERS; i++) {
		if (strcmp(str, magic_reference[i].name) == 0) return magic_reference[i].ver;
	}

	return UNKN_VER;
}

const char* LOGSIG_VERSION_toString(LOGSIG_VERSION ver) {
	int i = 0;

	for (i = 0; i < NOF_VERS; i++) {
		if (magic_reference[i].ver == ver) return magic_reference[i].name;
	}

	return "<unknown file version>";
}

LOGSIG_VERSION LOGSIG_VERSION_getIntProofVer(LOGSIG_VERSION ver) {
	switch(ver) {
		case LOGSIG11: return RECSIG11;
		case LOGSIG12: return RECSIG12;
		default: return UNKN_VER;
	}
}

/**
 * Extracts file type by reading its magic bytes.
 * \param in		#SMART_FILE object wherefrom the magic bytes are read.
 * \return File version (#LOGSIG_VERSION) if successful or #UNKN_VER otherwise.
 */
LOGSIG_VERSION LOGSIG_VERSION_getFileVer(SMART_FILE *in) {
	int res = KT_UNKNOWN_ERROR;
	char magic_from_file[MAGIC_SIZE + 1];
	size_t count = 0xff;

	if (in == NULL)	return UNKN_VER;

	res = SMART_FILE_read(in, (unsigned char*)magic_from_file, MAGIC_SIZE, &count);
	if (res != SMART_FILE_OK || count != MAGIC_SIZE) return UNKN_VER;

	magic_from_file[MAGIC_SIZE] = '\0';
	return file_version_by_string(magic_from_file);
}
