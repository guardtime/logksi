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

#ifndef TLV_OBJECT_H
#define	TLV_OBJECT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <ksi/ksi.h>
#include <ksi/tlv_element.h>
#include <ksi/fast_tlv.h>
#include "err_trckr.h"
#include "smart_file.h"

int tlv_element_get_uint(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, size_t *out);
int tlv_element_get_octet_string(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_OctetString **out);
int tlv_element_get_hash(ERR_TRCKR *err, KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_DataHash **out);
int tlv_element_set_uint(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_uint64_t val);
int tlv_element_set_hash(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_DataHash *hash);
int tlv_element_set_signature(KSI_TlvElement *tlv, KSI_CTX *ksi, unsigned tag, KSI_Signature *sig);
int tlv_element_create_hash(KSI_DataHash *hash, unsigned tag, KSI_TlvElement **tlv);
int tlv_element_write_hash(KSI_DataHash *hash, unsigned tag, SMART_FILE *out);
int tlv_element_parse_and_check_sub_elements(ERR_TRCKR *err, KSI_CTX *ksi, unsigned char *dat, size_t dat_len, size_t hdr_len, KSI_TlvElement **out);
int LOGKSI_FTLV_smartFileRead(SMART_FILE *sf, unsigned char *buf, size_t len, size_t *consumed, struct fast_tlv_s *t);

#ifdef	__cplusplus
}
#endif

#endif	/* TLV_OBJECT_H */