/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MBEDTLS_ECC_INTERNAL_H
#define MBEDTLS_ECC_INTERNAL_H

#include "mbedtls/ecp.h"
#include "pub_key.h"
#include "pri_key.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ECC_PUB_KEY_CLASS "MBEDTLS.ECC.PUB_KEY"
#define MBEDTLS_ECC_PRI_KEY_CLASS "MBEDTLS.ECC.PRI_KEY"
#define ECC_P256_BITS 256
#define ECC_P256_COORDINATE_LEN 32

typedef struct {
    HcfPubKey base;
    mbedtls_ecp_keypair *ecKey;
    int32_t keyBits;
    char *fieldType;
} MbedtlsEccPubKey;

typedef struct {
    HcfPriKey base;
    mbedtls_ecp_keypair *ecKey;
    int32_t keyBits;
    char *fieldType;
} MbedtlsEccPriKey;

#ifdef __cplusplus
}
#endif
#endif
