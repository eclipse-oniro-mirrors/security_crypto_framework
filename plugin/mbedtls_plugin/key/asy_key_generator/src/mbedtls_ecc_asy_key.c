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

#include "mbedtls_ecc_asy_key.h"

#include <securec.h>

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

#define MBEDTLS_ECC_KEY_GENERATOR_CLASS "MBEDTLS.ECC.KEY_GENERATOR"
#define MBEDTLS_ECC_KEY_PAIR_CLASS "MBEDTLS.ECC.KEY_PAIR"
#define MBEDTLS_ECC_ALGORITHM "EC"
#define MBEDTLS_ECC_PUB_KEY_FORMAT "X.509"
#define MBEDTLS_ECC_PRI_KEY_FORMAT "PKCS#8"
#define MBEDTLS_ECC_FIELD_TYPE "Fp"
#define ECC_PUBKEY_UNCOMPRESSED_PREFIX 0x04
#define ECC_UNCOMPRESSED_POINT_LEN (1 + 2 * ECC_P256_COORDINATE_LEN)
#define X509_FORMAT_PREFIX "X509|"
#define UNCOMPRESSED_FORMAT "UNCOMPRESSED"

#define EC_PRIVATE_K 6
#define EC_PRIVATE_04_X_Y_K 7
#define EC_PUBLIC_X_Y 8
#define EC_PUBLIC_04_X_Y 9
#define EC_PUBLIC_COMPRESS_X 10

typedef struct {
    HcfKeyPair base;
} MbedtlsEccKeyPair;

typedef struct {
    HcfAsyKeyGeneratorSpi base;
    int32_t keyBits;
} MbedtlsAsyKeyGeneratorSpiEccImpl;

static mbedtls_ecp_group_id MbedtlsEccGetGroupId(int32_t keyBits)
{
    if (keyBits == ECC_P256_BITS) {
        return MBEDTLS_ECP_DP_SECP256R1;
    }
    return MBEDTLS_ECP_DP_NONE;
}

static HcfResult MbedtlsEccInitRng(mbedtls_entropy_context **entropy, mbedtls_ctr_drbg_context **ctrDrbg)
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
        *entropy = NULL;
        HcfFree(*ctrDrbg);
        *ctrDrbg = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static void MbedtlsEccFreeRng(mbedtls_entropy_context *entropy, mbedtls_ctr_drbg_context *ctrDrbg)
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

static const char *GetEccKeyGeneratorClass(void)
{
    return MBEDTLS_ECC_KEY_GENERATOR_CLASS;
}

static const char *GetEccKeyPairClass(void)
{
    return MBEDTLS_ECC_KEY_PAIR_CLASS;
}

static const char *GetEccPubKeyClass(void)
{
    return MBEDTLS_ECC_PUB_KEY_CLASS;
}

static const char *GetEccPriKeyClass(void)
{
    return MBEDTLS_ECC_PRI_KEY_CLASS;
}

static void DestroyEccPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEccPubKeyClass())) {
        return;
    }
    MbedtlsEccPubKey *impl = (MbedtlsEccPubKey *)self;
    if (impl->ecKey != NULL) {
        mbedtls_ecp_keypair_free(impl->ecKey);
        HcfFree(impl->ecKey);
        impl->ecKey = NULL;
    }
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroyEccPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEccPriKeyClass())) {
        return;
    }
    MbedtlsEccPriKey *impl = (MbedtlsEccPriKey *)self;
    if (impl->ecKey != NULL) {
        mbedtls_ecp_keypair_free(impl->ecKey);
        HcfFree(impl->ecKey);
        impl->ecKey = NULL;
    }
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroyEccKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEccKeyPairClass())) {
        return;
    }
    MbedtlsEccKeyPair *impl = (MbedtlsEccKeyPair *)self;
    if (impl->base.pubKey != NULL) {
        DestroyEccPubKey((HcfObjectBase *)impl->base.pubKey);
        impl->base.pubKey = NULL;
    }
    if (impl->base.priKey != NULL) {
        DestroyEccPriKey((HcfObjectBase *)impl->base.priKey);
        impl->base.priKey = NULL;
    }
    HcfFree(impl);
}

static const char *GetEccPubKeyAlgorithm(HcfKey *self)
{
    if ((self == NULL) || (!HcfIsClassMatch((HcfObjectBase *)self, GetEccPubKeyClass()))) {
        return NULL;
    }
    return MBEDTLS_ECC_ALGORITHM;
}

static const char *GetEccPriKeyAlgorithm(HcfKey *self)
{
    if ((self == NULL) || (!HcfIsClassMatch((HcfObjectBase *)self, GetEccPriKeyClass()))) {
        return NULL;
    }
    return MBEDTLS_ECC_ALGORITHM;
}

static const char *GetEccPubKeyFormat(HcfKey *self)
{
    if ((self == NULL) || (!HcfIsClassMatch((HcfObjectBase *)self, GetEccPubKeyClass()))) {
        return NULL;
    }
    return MBEDTLS_ECC_PUB_KEY_FORMAT;
}

static const char *GetEccPriKeyFormat(HcfKey *self)
{
    if ((self == NULL) || (!HcfIsClassMatch((HcfObjectBase *)self, GetEccPriKeyClass()))) {
        return NULL;
    }
    return MBEDTLS_ECC_PRI_KEY_FORMAT;
}

static HcfResult WriteUncompressedPoint(const mbedtls_ecp_keypair *ecKey, HcfBlob *returnBlob)
{
    if ((ecKey == NULL) || (returnBlob == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    uint8_t *buf = (uint8_t *)HcfMalloc(ECC_UNCOMPRESSED_POINT_LEN, 0);
    if (buf == NULL) {
        return HCF_ERR_MALLOC;
    }
    size_t olen = 0;
    int32_t ret = mbedtls_ecp_point_write_binary(&ecKey->MBEDTLS_PRIVATE(grp), &ecKey->MBEDTLS_PRIVATE(Q),
        MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, ECC_UNCOMPRESSED_POINT_LEN);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("point_write_binary failed ret %d.", ret);
        HcfFree(buf);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = buf;
    returnBlob->len = olen;
    return HCF_SUCCESS;
}

static HcfResult CheckEccPubKeyFormat(const char *format)
{
    if (format == NULL) {
        return HCF_INVALID_PARAMS;
    }
    size_t prefixLen = strlen(X509_FORMAT_PREFIX);
    if (strncmp(format, X509_FORMAT_PREFIX, prefixLen) != 0) {
        LOGE("Invalid x509 prefix.");
        return HCF_INVALID_PARAMS;
    }
    const char *suffix = format + prefixLen;
    if (strcmp(suffix, UNCOMPRESSED_FORMAT) != 0) {
        LOGE("Only UNCOMPRESSED format is supported.");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static void EccPriKeyClearMem(HcfPriKey *self)
{
    if ((self == NULL) || (!HcfIsClassMatch((HcfObjectBase *)self, GetEccPriKeyClass()))) {
        return;
    }
    MbedtlsEccPriKey *impl = (MbedtlsEccPriKey *)self;
    if (impl->ecKey != NULL) {
        mbedtls_ecp_point_free(&impl->ecKey->MBEDTLS_PRIVATE(Q));
        mbedtls_mpi_free(&impl->ecKey->MBEDTLS_PRIVATE(d));
    }
}

static char *CopyFieldType(void)
{
    char *fieldType = (char *)HcfMalloc(strlen(MBEDTLS_ECC_FIELD_TYPE) + 1, 0);
    if (fieldType == NULL) {
        return NULL;
    }
    (void)strcpy_s(fieldType, strlen(MBEDTLS_ECC_FIELD_TYPE) + 1, MBEDTLS_ECC_FIELD_TYPE);
    return fieldType;
}

static HcfResult GetEccPubKeyData(const HcfPubKey *self, uint32_t type, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccPubKeyClass())) {
        LOGE("Invalid input parameter type.");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsEccPubKey *impl = (MbedtlsEccPubKey *)self;
    if (impl->ecKey == NULL) {
        LOGE("ecKey is null.");
        return HCF_INVALID_PARAMS;
    }
    if (type == EC_PUBLIC_04_X_Y) {
        return WriteUncompressedPoint(impl->ecKey, returnBlob);
    }
    LOGE("Unsupported type %u for public key.", type);
    return HCF_NOT_SUPPORT;
}

static HcfResult PackEccPubKey(mbedtls_ecp_keypair *ecKey, int32_t keyBits, HcfPubKey **returnObj)
{
    MbedtlsEccPubKey *returnPubKey = (MbedtlsEccPubKey *)HcfMalloc(sizeof(MbedtlsEccPubKey), 0);
    if (returnPubKey == NULL) {
        return HCF_ERR_MALLOC;
    }
    returnPubKey->base.base.base.getClass = GetEccPubKeyClass;
    returnPubKey->base.base.base.destroy = DestroyEccPubKey;
    returnPubKey->base.base.getAlgorithm = GetEccPubKeyAlgorithm;
    returnPubKey->base.base.getFormat = GetEccPubKeyFormat;
    returnPubKey->base.getKeyData = GetEccPubKeyData;
    returnPubKey->ecKey = ecKey;
    returnPubKey->keyBits = keyBits;
    returnPubKey->fieldType = CopyFieldType();
    *returnObj = (HcfPubKey *)returnPubKey;
    return HCF_SUCCESS;
}

static HcfResult PackEccPriKey(mbedtls_ecp_keypair *ecKey, int32_t keyBits, HcfPriKey **returnObj)
{
    MbedtlsEccPriKey *returnPriKey = (MbedtlsEccPriKey *)HcfMalloc(sizeof(MbedtlsEccPriKey), 0);
    if (returnPriKey == NULL) {
        return HCF_ERR_MALLOC;
    }
    returnPriKey->base.base.base.getClass = GetEccPriKeyClass;
    returnPriKey->base.base.base.destroy = DestroyEccPriKey;
    returnPriKey->base.base.getAlgorithm = GetEccPriKeyAlgorithm;
    returnPriKey->base.base.getFormat = GetEccPriKeyFormat;
    returnPriKey->base.clearMem = EccPriKeyClearMem;
    returnPriKey->ecKey = ecKey;
    returnPriKey->keyBits = keyBits;
    returnPriKey->fieldType = CopyFieldType();
    *returnObj = (HcfPriKey *)returnPriKey;
    return HCF_SUCCESS;
}

static HcfResult PackEccKeyPair(mbedtls_ecp_keypair *pubEcKey, mbedtls_ecp_keypair *priEcKey, int32_t keyBits,
    HcfKeyPair **returnObj)
{
    MbedtlsEccKeyPair *returnKeyPair = (MbedtlsEccKeyPair *)HcfMalloc(sizeof(MbedtlsEccKeyPair), 0);
    if (returnKeyPair == NULL) {
        return HCF_ERR_MALLOC;
    }
    returnKeyPair->base.base.getClass = GetEccKeyPairClass;
    returnKeyPair->base.base.destroy = DestroyEccKeyPair;
    HcfResult ret = PackEccPubKey(pubEcKey, keyBits, &returnKeyPair->base.pubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("PackEccPubKey failed.");
        HcfFree(returnKeyPair);
        mbedtls_ecp_keypair_free(pubEcKey);
        HcfFree(pubEcKey);
        if (priEcKey != NULL) {
            mbedtls_ecp_keypair_free(priEcKey);
            HcfFree(priEcKey);
        }
        return ret;
    }
    if (priEcKey != NULL) {
        ret = PackEccPriKey(priEcKey, keyBits, &returnKeyPair->base.priKey);
        if (ret != HCF_SUCCESS) {
            LOGE("PackEccPriKey failed.");
            DestroyEccKeyPair((HcfObjectBase *)returnKeyPair);
            mbedtls_ecp_keypair_free(priEcKey);
            HcfFree(priEcKey);
            return ret;
        }
    }
    *returnObj = (HcfKeyPair *)returnKeyPair;
    return HCF_SUCCESS;
}

static mbedtls_ecp_keypair *MbedtlsEccKeyDup(const mbedtls_ecp_keypair *src)
{
    if (src == NULL) {
        return NULL;
    }
    mbedtls_ecp_keypair *dst = (mbedtls_ecp_keypair *)HcfMalloc(sizeof(mbedtls_ecp_keypair), 0);
    if (dst == NULL) {
        return NULL;
    }
    mbedtls_ecp_keypair_init(dst);
    int32_t ret = mbedtls_ecp_group_copy(&dst->MBEDTLS_PRIVATE(grp), &src->MBEDTLS_PRIVATE(grp));
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("group_copy failed ret %d.", ret);
        mbedtls_ecp_keypair_free(dst);
        HcfFree(dst);
        return NULL;
    }
    ret = mbedtls_ecp_copy(&dst->MBEDTLS_PRIVATE(Q), &src->MBEDTLS_PRIVATE(Q));
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("point copy failed ret %d.", ret);
        mbedtls_ecp_keypair_free(dst);
        HcfFree(dst);
        return NULL;
    }
    ret = mbedtls_mpi_copy(&dst->MBEDTLS_PRIVATE(d), &src->MBEDTLS_PRIVATE(d));
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mpi copy failed ret %d.", ret);
        mbedtls_ecp_keypair_free(dst);
        HcfFree(dst);
        return NULL;
    }
    return dst;
}

static HcfResult MbedtlsEccGenKeyPairInner(mbedtls_ecp_group_id grpId, int32_t keyBits, HcfKeyPair **returnKeyPair)
{
    mbedtls_entropy_context *entropy = NULL;
    mbedtls_ctr_drbg_context *ctrDrbg = NULL;
    HcfResult ret = MbedtlsEccInitRng(&entropy, &ctrDrbg);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    mbedtls_ecp_keypair ecKey;
    mbedtls_ecp_keypair_init(&ecKey);
    int32_t res = mbedtls_ecp_group_load(&ecKey.MBEDTLS_PRIVATE(grp), grpId);
    if (res != HCF_MBEDTLS_SUCCESS) {
        LOGE("group_load failed res %d.", res);
        MbedtlsEccFreeRng(entropy, ctrDrbg);
        mbedtls_ecp_keypair_free(&ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = mbedtls_ecp_gen_keypair(&ecKey.MBEDTLS_PRIVATE(grp), &ecKey.MBEDTLS_PRIVATE(d),
        &ecKey.MBEDTLS_PRIVATE(Q), mbedtls_ctr_drbg_random, ctrDrbg);
    MbedtlsEccFreeRng(entropy, ctrDrbg);
    if (res != HCF_MBEDTLS_SUCCESS) {
        LOGE("gen_keypair failed res %d.", res);
        mbedtls_ecp_keypair_free(&ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    mbedtls_ecp_keypair *pubEcKey = MbedtlsEccKeyDup(&ecKey);
    mbedtls_ecp_keypair *priEcKey = MbedtlsEccKeyDup(&ecKey);
    mbedtls_ecp_keypair_free(&ecKey);
    if ((pubEcKey == NULL) || (priEcKey == NULL)) {
        LOGE("dup ecc key failed.");
        if (pubEcKey != NULL) {
            mbedtls_ecp_keypair_free(pubEcKey);
            HcfFree(pubEcKey);
        }
        if (priEcKey != NULL) {
            mbedtls_ecp_keypair_free(priEcKey);
            HcfFree(priEcKey);
        }
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = PackEccKeyPair(pubEcKey, priEcKey, keyBits, returnKeyPair);
    if (ret != HCF_SUCCESS) {
        LOGE("PackEccKeyPair failed ret %d.", ret);
    }
    return ret;
}

static HcfResult MbedtlsEccEngineGenerateKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccKeyGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }
    int32_t keyBits = ((MbedtlsAsyKeyGeneratorSpiEccImpl *)self)->keyBits;
    mbedtls_ecp_group_id grpId = MbedtlsEccGetGroupId(keyBits);
    if (grpId == MBEDTLS_ECP_DP_NONE) {
        LOGE("Unsupported ecc key bits %d.", keyBits);
        return HCF_INVALID_PARAMS;
    }
    return MbedtlsEccGenKeyPairInner(grpId, keyBits, returnKeyPair);
}

static HcfResult MbedtlsEccConvertKeyInner(mbedtls_ecp_group_id grpId, int32_t keyBits,
    HcfBlob *pubKeyBlob, HcfKeyPair **returnKeyPair)
{
    mbedtls_ecp_keypair *ecKey = (mbedtls_ecp_keypair *)HcfMalloc(sizeof(mbedtls_ecp_keypair), 0);
    if (ecKey == NULL) {
        return HCF_ERR_MALLOC;
    }
    mbedtls_ecp_keypair_init(ecKey);
    int32_t ret = mbedtls_ecp_group_load(&ecKey->MBEDTLS_PRIVATE(grp), grpId);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("group_load failed ret %d.", ret);
        mbedtls_ecp_keypair_free(ecKey);
        HcfFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = mbedtls_ecp_point_read_binary(&ecKey->MBEDTLS_PRIVATE(grp), &ecKey->MBEDTLS_PRIVATE(Q),
        pubKeyBlob->data, pubKeyBlob->len);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("point_read_binary failed ret %d.", ret);
        mbedtls_ecp_keypair_free(ecKey);
        HcfFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (mbedtls_ecp_check_pubkey(&ecKey->MBEDTLS_PRIVATE(grp), &ecKey->MBEDTLS_PRIVATE(Q)) != HCF_MBEDTLS_SUCCESS) {
        LOGE("check pubkey failed.");
        mbedtls_ecp_keypair_free(ecKey);
        HcfFree(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    mbedtls_ecp_keypair *pubEcKey = MbedtlsEccKeyDup(ecKey);
    mbedtls_ecp_keypair_free(ecKey);
    HcfFree(ecKey);
    if (pubEcKey == NULL) {
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = PackEccKeyPair(pubEcKey, NULL, keyBits, returnKeyPair);
    if (res != HCF_SUCCESS) {
        LOGE("PackEccKeyPair failed res %d.", res);
    }
    return res;
}

static HcfResult MbedtlsEccEngineConvertKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params,
    HcfBlob *pubKeyBlob, HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    if (priKeyBlob != NULL && priKeyBlob->data != NULL) {
        LOGE("Mbedtls ecc only support public key convert.");
        return HCF_NOT_SUPPORT;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, GetEccKeyGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }
    if ((pubKeyBlob == NULL) || (pubKeyBlob->data == NULL) || (pubKeyBlob->len != ECC_UNCOMPRESSED_POINT_LEN) ||
        (pubKeyBlob->data[0] != ECC_PUBKEY_UNCOMPRESSED_PREFIX)) {
        LOGE("Invalid pub key data, expect 04||X||Y.");
        return HCF_INVALID_PARAMS;
    }
    int32_t keyBits = ((MbedtlsAsyKeyGeneratorSpiEccImpl *)self)->keyBits;
    mbedtls_ecp_group_id grpId = MbedtlsEccGetGroupId(keyBits);
    if (grpId == MBEDTLS_ECP_DP_NONE) {
        return HCF_INVALID_PARAMS;
    }
    return MbedtlsEccConvertKeyInner(grpId, keyBits, pubKeyBlob, returnKeyPair);
}

static void DestroyEccKeyGenerator(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetEccKeyGeneratorClass())) {
        return;
    }
    HcfFree(self);
}

HcfResult HcfAsyKeyGeneratorSpiMbedtlsEccCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    if (params->bits != 0 && params->bits != ECC_P256_BITS && params->bits != HCF_ALG_ECC_256) {
        LOGE("Mbedtls ecc only support p256v1, but bits is %d.", params->bits);
        return HCF_INVALID_PARAMS;
    }
    MbedtlsAsyKeyGeneratorSpiEccImpl *returnImpl =
        (MbedtlsAsyKeyGeneratorSpiEccImpl *)HcfMalloc(sizeof(MbedtlsAsyKeyGeneratorSpiEccImpl), 0);
    if (returnImpl == NULL) {
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetEccKeyGeneratorClass;
    returnImpl->base.base.destroy = DestroyEccKeyGenerator;
    returnImpl->base.engineGenerateKeyPair = MbedtlsEccEngineGenerateKeyPair;
    returnImpl->base.engineConvertKey = MbedtlsEccEngineConvertKey;
    returnImpl->keyBits = ECC_P256_BITS;
    *returnObj = (HcfAsyKeyGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
