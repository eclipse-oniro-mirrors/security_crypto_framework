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

#include "mbedtls_ecdh.h"

#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls_common.h"
#include "mbedtls_ecc_internal.h"
#include "log.h"
#include "memory.h"
#include "utils.h"
#include "result.h"

#define MBEDTLS_ECDH_CLASS "MBEDTLS.KEY_AGREEMENT.ECDH"

static HcfResult MbedtlsEcdhInitRng(mbedtls_entropy_context **entropy, mbedtls_ctr_drbg_context **ctrDrbg)
{
    if ((entropy == NULL) || (ctrDrbg == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    *entropy = (mbedtls_entropy_context *)HcfMalloc(sizeof(mbedtls_entropy_context), 0);
    if (*entropy == NULL) {
        return HCF_ERR_MALLOC;
    }
    *ctrDrbg = (mbedtls_ctr_drbg_context *)HcfMalloc(sizeof(mbedtls_ctr_drbg_context), 0);
    if (*ctrDrbg == NULL) {
        HcfFree(*entropy);
        *entropy = NULL;
        return HCF_ERR_MALLOC;
    }
    mbedtls_entropy_init(*entropy);
    mbedtls_ctr_drbg_init(*ctrDrbg);
    int32_t ret = mbedtls_ctr_drbg_seed(*ctrDrbg, mbedtls_entropy_func, *entropy, NULL, 0);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("ctr_drbg_seed failed ret %d.", ret);
        mbedtls_entropy_free(*entropy);
        mbedtls_ctr_drbg_free(*ctrDrbg);
        HcfFree(*entropy);
        HcfFree(*ctrDrbg);
        *entropy = NULL;
        *ctrDrbg = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static void MbedtlsEcdhFreeRng(mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctrDrbg)
{
    if (ctrDrbg != NULL) {
        mbedtls_ctr_drbg_free(ctrDrbg);
        HcfFree(ctrDrbg);
    }
    if (entropy != NULL) {
        mbedtls_entropy_free(entropy);
        HcfFree(entropy);
    }
}

typedef struct {
    HcfKeyAgreementSpi base;
} MbedtlsKeyAgreementSpiEcdhImpl;

static mbedtls_ecp_keypair *GetPubKeyEcKey(HcfPubKey *self)
{
    if ((self == NULL) || (!HcfIsClassMatch((HcfObjectBase *)self, MBEDTLS_ECC_PUB_KEY_CLASS))) {
        return NULL;
    }
    return ((MbedtlsEccPubKey *)self)->ecKey;
}

static mbedtls_ecp_keypair *GetPriKeyEcKey(HcfPriKey *self)
{
    if ((self == NULL) || (!HcfIsClassMatch((HcfObjectBase *)self, MBEDTLS_ECC_PRI_KEY_CLASS))) {
        return NULL;
    }
    return ((MbedtlsEccPriKey *)self)->ecKey;
}

static const char *GetEcdhClass(void)
{
    return MBEDTLS_ECDH_CLASS;
}

static void DestroyEcdh(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEcdhClass())) {
        return;
    }
    HcfFree(self);
}

static HcfResult MbedtlsEcdhComputeSharedSecret(mbedtls_ecp_keypair *priEcKey,
    mbedtls_ecp_keypair *pubEcKey, mbedtls_ecp_point *R)
{
    mbedtls_entropy_context *entropy = NULL;
    mbedtls_ctr_drbg_context *ctrDrbg = NULL;
    HcfResult ret = MbedtlsEcdhInitRng(&entropy, &ctrDrbg);
    if (ret != HCF_SUCCESS) {
        LOGE("MbedtlsEcdhInitRng failed ret %d.", ret);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int32_t res = mbedtls_ecp_check_pubkey(&priEcKey->MBEDTLS_PRIVATE(grp),
        &pubEcKey->MBEDTLS_PRIVATE(Q));
    if (res != HCF_MBEDTLS_SUCCESS) {
        LOGE("ecp_check_pubkey failed res %d.", res);
        MbedtlsEcdhFreeRng(entropy, ctrDrbg);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = mbedtls_ecp_mul(&priEcKey->MBEDTLS_PRIVATE(grp), R, &priEcKey->MBEDTLS_PRIVATE(d),
        &pubEcKey->MBEDTLS_PRIVATE(Q), mbedtls_ctr_drbg_random, ctrDrbg);
    MbedtlsEcdhFreeRng(entropy, ctrDrbg);
    if (res != HCF_MBEDTLS_SUCCESS) {
        LOGE("ecp_mul for shared secret failed res %d.", res);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult MbedtlsEcdhWriteSharedSecret(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
    HcfBlob *returnSecret)
{
    size_t secretLen = (grp->pbits + HCF_BITS_PER_BYTE - 1) / HCF_BITS_PER_BYTE;
    if (secretLen == 0) {
        LOGE("ecp group pbits is 0, secretLen is 0.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSecret->data = (uint8_t *)HcfMalloc(secretLen, 0);
    if (returnSecret->data == NULL) {
        return HCF_ERR_MALLOC;
    }
    if (mbedtls_mpi_write_binary(&R->MBEDTLS_PRIVATE(X), returnSecret->data,
        secretLen) != HCF_MBEDTLS_SUCCESS) {
        LOGE("mpi_write_binary failed for shared secret.");
        HcfFree(returnSecret->data);
        returnSecret->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnSecret->len = secretLen;
    return HCF_SUCCESS;
}

static HcfResult MbedtlsEcdhEngineGenerateSecret(HcfKeyAgreementSpi *self, HcfPriKey *priKey,
    HcfPubKey *pubKey, HcfBlob *returnSecret)
{
    if ((self == NULL) || (priKey == NULL) || (pubKey == NULL) || (returnSecret == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEcdhClass())) {
        return HCF_INVALID_PARAMS;
    }
    mbedtls_ecp_keypair *priEcKey = GetPriKeyEcKey(priKey);
    mbedtls_ecp_keypair *pubEcKey = GetPubKeyEcKey(pubKey);
    if ((priEcKey == NULL) || (pubEcKey == NULL)) {
        LOGE("Invalid ecc priKey or pubKey for ecdh.");
        return HCF_INVALID_PARAMS;
    }
    mbedtls_ecp_point R;
    mbedtls_ecp_point_init(&R);
    HcfResult ret = MbedtlsEcdhComputeSharedSecret(priEcKey, pubEcKey, &R);
    if (ret != HCF_SUCCESS) {
        mbedtls_ecp_point_free(&R);
        return ret;
    }
    ret = MbedtlsEcdhWriteSharedSecret(&priEcKey->MBEDTLS_PRIVATE(grp), &R, returnSecret);
    mbedtls_ecp_point_free(&R);
    return ret;
}

HcfResult HcfKeyAgreementSpiMbedtlsEcdhCreate(HcfKeyAgreementParams *params, HcfKeyAgreementSpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    MbedtlsKeyAgreementSpiEcdhImpl *returnImpl =
        (MbedtlsKeyAgreementSpiEcdhImpl *)HcfMalloc(sizeof(MbedtlsKeyAgreementSpiEcdhImpl), 0);
    if (returnImpl == NULL) {
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetEcdhClass;
    returnImpl->base.base.destroy = DestroyEcdh;
    returnImpl->base.engineGenerateSecret = MbedtlsEcdhEngineGenerateSecret;
    *returnObj = (HcfKeyAgreementSpi *)returnImpl;
    return HCF_SUCCESS;
}
