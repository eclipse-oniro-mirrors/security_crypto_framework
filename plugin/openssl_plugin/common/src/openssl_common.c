/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "openssl_common.h"

#include "securec.h"

#include <string.h>
#include <openssl/err.h>
#include "config.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "result.h"
#include "params_parser.h"
#include "utils.h"

#define PRIMES_2 2
#define PRIMES_3 3
#define PRIMES_4 4
#define PRIMES_5 5

#define HCF_OPENSSL_DIGEST_NONE_STR "NONE"
#define HCF_OPENSSL_DIGEST_MD5_STR "MD5"
#define HCF_OPENSSL_DIGEST_SM3_STR "SM3"
#define HCF_OPENSSL_DIGEST_SHA1_STR "SHA1"
#define HCF_OPENSSL_DIGEST_SHA224_STR "SHA224"
#define HCF_OPENSSL_DIGEST_SHA256_STR "SHA256"
#define HCF_OPENSSL_DIGEST_SHA384_STR "SHA384"
#define HCF_OPENSSL_DIGEST_SHA512_STR "SHA512"
#define HCF_OPENSSL_MGF1 "MGF1"

static const uint32_t ASCII_CODE_ZERO = 48;

typedef struct {
    int32_t bits; // keyLen
    int32_t nid; // nid
    char *groupName;
} NidTypeAlg;

static const NidTypeAlg NID_TYPE_MAP[] = {
    { HCF_ALG_ECC_224, NID_secp224r1, "secp224r1" },
    { HCF_ALG_ECC_256, NID_X9_62_prime256v1, "prime256v1" },
    { HCF_ALG_ECC_384, NID_secp384r1, "secp384r1" },
    { HCF_ALG_ECC_521, NID_secp521r1, "secp521r1" },
    { HCF_ALG_SM2_256, NID_sm2, "sm2" },
    { HCF_ALG_ECC_BP160R1, NID_brainpoolP160r1, "brainpoolP160r1" },
    { HCF_ALG_ECC_BP160T1, NID_brainpoolP160t1, "brainpoolP160t1" },
    { HCF_ALG_ECC_BP192R1, NID_brainpoolP192r1, "brainpoolP192r1" },
    { HCF_ALG_ECC_BP192T1, NID_brainpoolP192t1, "brainpoolP192t1" },
    { HCF_ALG_ECC_BP224R1, NID_brainpoolP224r1, "brainpoolP224r1" },
    { HCF_ALG_ECC_BP224T1, NID_brainpoolP224t1, "brainpoolP224t1" },
    { HCF_ALG_ECC_BP256R1, NID_brainpoolP256r1, "brainpoolP256r1" },
    { HCF_ALG_ECC_BP256T1, NID_brainpoolP256t1, "brainpoolP256t1" },
    { HCF_ALG_ECC_BP320R1, NID_brainpoolP320r1, "brainpoolP320r1" },
    { HCF_ALG_ECC_BP320T1, NID_brainpoolP320t1, "brainpoolP320t1" },
    { HCF_ALG_ECC_BP384R1, NID_brainpoolP384r1, "brainpoolP384r1" },
    { HCF_ALG_ECC_BP384T1, NID_brainpoolP384t1, "brainpoolP384t1" },
    { HCF_ALG_ECC_BP512R1, NID_brainpoolP512r1, "brainpoolP512r1" },
    { HCF_ALG_ECC_BP512T1, NID_brainpoolP512t1, "brainpoolP512t1" },
};

typedef struct {
    int32_t curveId;
    char *curveName;
} CurveNameAlg;

static const CurveNameAlg CURVE_NAME_MAP[] = {
    { NID_secp224r1, "NID_secp224r1" },
    { NID_X9_62_prime256v1, "NID_X9_62_prime256v1" },
    { NID_secp384r1, "NID_secp384r1" },
    { NID_secp521r1, "NID_secp521r1" },
    { NID_brainpoolP160r1, "NID_brainpoolP160r1" },
    { NID_brainpoolP160t1, "NID_brainpoolP160t1" },
    { NID_brainpoolP192r1, "NID_brainpoolP192r1" },
    { NID_brainpoolP192t1, "NID_brainpoolP192t1" },
    { NID_brainpoolP224r1, "NID_brainpoolP224r1" },
    { NID_brainpoolP224t1, "NID_brainpoolP224t1" },
    { NID_brainpoolP256r1, "NID_brainpoolP256r1" },
    { NID_brainpoolP256t1, "NID_brainpoolP256t1" },
    { NID_brainpoolP320r1, "NID_brainpoolP320r1" },
    { NID_brainpoolP320t1, "NID_brainpoolP320t1" },
    { NID_brainpoolP384r1, "NID_brainpoolP384r1" },
    { NID_brainpoolP384t1, "NID_brainpoolP384t1" },
    { NID_brainpoolP512r1, "NID_brainpoolP512r1" },
    { NID_brainpoolP512t1, "NID_brainpoolP512t1" }
};

typedef struct {
    int32_t bits;
    char *algName;
} AlgNameType;

static const AlgNameType ALG_NAME_TYPE_MAP[] = {
    { HCF_ALG_ECC_224, "ECC" },
    { HCF_ALG_ECC_256, "ECC" },
    { HCF_ALG_ECC_384, "ECC" },
    { HCF_ALG_ECC_521, "ECC" },
    { HCF_ALG_SM2_256, "SM2" },
    { HCF_ALG_ECC_BP160R1, "ECC" },
    { HCF_ALG_ECC_BP160T1, "ECC" },
    { HCF_ALG_ECC_BP192R1, "ECC" },
    { HCF_ALG_ECC_BP192T1, "ECC" },
    { HCF_ALG_ECC_BP224R1, "ECC" },
    { HCF_ALG_ECC_BP224T1, "ECC" },
    { HCF_ALG_ECC_BP256R1, "ECC" },
    { HCF_ALG_ECC_BP256T1, "ECC" },
    { HCF_ALG_ECC_BP320R1, "ECC" },
    { HCF_ALG_ECC_BP320T1, "ECC" },
    { HCF_ALG_ECC_BP384R1, "ECC" },
    { HCF_ALG_ECC_BP384T1, "ECC" },
    { HCF_ALG_ECC_BP512R1, "ECC" },
    { HCF_ALG_ECC_BP512T1, "ECC" }
};

typedef struct {
    int32_t formatValue;
    int32_t formatType;
} FormatType;

static const FormatType FORMAT_TYPE_MAP[] = {
    { HCF_UNCOMPRESSED_FORMAT_VALUE, POINT_CONVERSION_UNCOMPRESSED },
    { HCF_COMPRESSED_FORMAT_VALUE, POINT_CONVERSION_COMPRESSED }
};

HcfResult GetCurveNameByCurveId(int32_t curveId, char **curveName)
{
    if (curveName == NULL) {
        LOGE("Invalid curveName");
        return HCF_INVALID_PARAMS;
    }
    for (uint32_t i = 0; i < sizeof(CURVE_NAME_MAP) / sizeof(CURVE_NAME_MAP[0]); i++) {
        if (CURVE_NAME_MAP[i].curveId == curveId) {
            *curveName = CURVE_NAME_MAP[i].curveName;
            return HCF_SUCCESS;
        }
    }
    LOGE("Invalid curve id:%d", curveId);
    return HCF_INVALID_PARAMS;
}

HcfResult GetNidByCurveNameValue(int32_t curveNameValue, int32_t *nid)
{
    if (nid == NULL) {
        LOGE("Invalid nid");
        return HCF_INVALID_PARAMS;
    }
    for (uint32_t i = 0; i < sizeof(NID_TYPE_MAP) / sizeof(NID_TYPE_MAP[0]); i++) {
        if (NID_TYPE_MAP[i].bits == curveNameValue) {
            *nid = NID_TYPE_MAP[i].nid;
            return HCF_SUCCESS;
        }
    }
    LOGE("Invalid curveNameValue value: %d", curveNameValue);
    return HCF_INVALID_PARAMS;
}

HcfResult GetGroupNameByNid(int32_t nid, char **groupName)
{
    if (groupName == NULL) {
        LOGE("Invalid groupName");
        return HCF_INVALID_PARAMS;
    }
    for (uint32_t i = 0; i < sizeof(NID_TYPE_MAP) / sizeof(NID_TYPE_MAP[0]); i++) {
        if (NID_TYPE_MAP[i].nid == nid) {
            *groupName = NID_TYPE_MAP[i].groupName;
            return HCF_SUCCESS;
        }
    }
    LOGE("Invalid nid:%d", nid);
    return HCF_INVALID_PARAMS;
}

HcfResult GetFormatTypeByFormatValue(int32_t formatValue, int32_t *formatType)
{
    if (formatType == NULL) {
        LOGE("Invalid formatType");
        return HCF_INVALID_PARAMS;
    }
    for (uint32_t i = 0; i < sizeof(FORMAT_TYPE_MAP) / sizeof(FORMAT_TYPE_MAP[0]); i++) {
        if (FORMAT_TYPE_MAP[i].formatValue == formatValue) {
            *formatType = FORMAT_TYPE_MAP[i].formatType;
            return HCF_SUCCESS;
        }
    }
    LOGE("Invalid format value: %d", formatValue);
    return HCF_INVALID_PARAMS;
}

HcfResult GetAlgNameByBits(int32_t keyLen, char **algName)
{
    if (algName == NULL) {
        LOGE("Invalid algName");
        return HCF_INVALID_PARAMS;
    }
    for (uint32_t i = 0; i < sizeof(ALG_NAME_TYPE_MAP) / sizeof(ALG_NAME_TYPE_MAP[0]); i++) {
        if (ALG_NAME_TYPE_MAP[i].bits == keyLen) {
            size_t srcAlgNameLen = HcfStrlen(ALG_NAME_TYPE_MAP[i].algName);
            if (srcAlgNameLen == 0) {
                LOGE("algName is empty!");
                return HCF_ERR_MALLOC;
            }
            *algName = (char *)HcfMalloc(srcAlgNameLen + 1, 0);
            if (*algName == NULL) {
                LOGE("algName malloc failed.");
                return HCF_ERR_MALLOC;
            }
            if (memcpy_s(*algName, srcAlgNameLen, ALG_NAME_TYPE_MAP[i].algName, srcAlgNameLen) != EOK) {
                LOGE("memcpy algName failed.");
                HcfFree(*algName);
                *algName = NULL;
                return HCF_ERR_MALLOC;
            }
            return HCF_SUCCESS;
        }
    }
    LOGD("[error] Invalid key size:%d", keyLen);
    return HCF_INVALID_PARAMS;
}

HcfResult GetOpensslCurveId(int32_t keyLen, int32_t *returnCurveId)
{
    if (returnCurveId == NULL) {
        LOGE("Invalid algName");
        return HCF_INVALID_PARAMS;
    }
    for (uint32_t i = 0; i < sizeof(NID_TYPE_MAP) / sizeof(NID_TYPE_MAP[0]); i++) {
        if (NID_TYPE_MAP[i].bits == keyLen) {
            *returnCurveId = NID_TYPE_MAP[i].nid;
            return HCF_SUCCESS;
        }
    }
    LOGE("invalid key size:%d", keyLen);
    return HCF_INVALID_PARAMS;
}

HcfResult GetOpensslDigestAlg(uint32_t alg, EVP_MD **digestAlg)
{
    if (digestAlg == NULL) {
        LOGE("Invalid MD pointer");
        return HCF_INVALID_PARAMS;
    }
    switch (alg) {
        case HCF_OPENSSL_DIGEST_NONE:
            *digestAlg = NULL;
            break;
        case HCF_OPENSSL_DIGEST_MD5:
            *digestAlg = (EVP_MD *)EVP_md5();
            break;
        case HCF_OPENSSL_DIGEST_SM3:
            *digestAlg = (EVP_MD *)EVP_sm3();
            break;
        case HCF_OPENSSL_DIGEST_SHA1:
            *digestAlg = (EVP_MD *)EVP_sha1();
            break;
        case HCF_OPENSSL_DIGEST_SHA224:
            *digestAlg = (EVP_MD *)EVP_sha224();
            break;
        case HCF_OPENSSL_DIGEST_SHA256:
            *digestAlg = (EVP_MD *)EVP_sha256();
            break;
        case HCF_OPENSSL_DIGEST_SHA384:
            *digestAlg = (EVP_MD *)EVP_sha384();
            break;
        case HCF_OPENSSL_DIGEST_SHA512:
            *digestAlg = (EVP_MD *)EVP_sha512();
            break;
        default:
            LOGD("[error] Invalid digest num is %u.", alg);
            return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

HcfResult GetRsaSpecStringMd(const HcfAlgParaValue md, char **returnString)
{
    if (returnString == NULL) {
        LOGE("return string is null");
        return HCF_INVALID_PARAMS;
    }
    char *tmp = NULL;
    switch (md) {
        case HCF_OPENSSL_DIGEST_MD5:
            tmp = HCF_OPENSSL_DIGEST_MD5_STR;
            break;
        case HCF_OPENSSL_DIGEST_SM3:
            tmp = HCF_OPENSSL_DIGEST_SM3_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA1:
            tmp = HCF_OPENSSL_DIGEST_SHA1_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA224:
            tmp = HCF_OPENSSL_DIGEST_SHA224_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA256:
            tmp = HCF_OPENSSL_DIGEST_SHA256_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA384:
            tmp = HCF_OPENSSL_DIGEST_SHA384_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA512:
            tmp = HCF_OPENSSL_DIGEST_SHA512_STR;
            break;
        default:
            LOGE("Invalid digest num is %u.", md);
            return HCF_INVALID_PARAMS;
    }
    size_t mdLen = HcfStrlen(tmp);
    if (mdLen == 0) {
        LOGE("mdLen is empty!");
        return HCF_ERR_MALLOC;
    }
    char *mdStr = (char *)HcfMalloc(mdLen + 1, 0);
    if (mdStr == NULL) {
        LOGE("Failed to allocate md name memory");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(mdStr, mdLen, tmp, mdLen);
    *returnString = mdStr;
    return HCF_SUCCESS;
}

HcfResult GetRsaSpecStringMGF(char **returnString)
{
    if (returnString == NULL) {
        LOGE("return string is null");
        return HCF_INVALID_PARAMS;
    }
    size_t mgf1Len = HcfStrlen(HCF_OPENSSL_MGF1);
    if (mgf1Len == 0) {
        LOGE("mgf1Len is empty!");
        return HCF_ERR_MALLOC;
    }
    char *mgf1Str = (char *)HcfMalloc(mgf1Len + 1, 0);
    if (mgf1Str == NULL) {
        LOGE("Failed to allocate mgf1 name memory");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(mgf1Str, mgf1Len, HCF_OPENSSL_MGF1, mgf1Len);
    *returnString = mgf1Str;
    return HCF_SUCCESS;
}

HcfResult GetSm2SpecStringSm3(char **returnString)
{
    if (returnString == NULL) {
        LOGE("return string is null");
        return HCF_INVALID_PARAMS;
    }
    size_t sm2Len = HcfStrlen(HCF_OPENSSL_DIGEST_SM3_STR);
    if (sm2Len == 0) {
        LOGE("sm2Len is empty!");
        return HCF_ERR_MALLOC;
    }
    char *sm2Str = (char *)HcfMalloc(sm2Len + 1, 0);
    if (sm2Str == NULL) {
        LOGE("Failed to allocate sm2 name memory");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(sm2Str, sm2Len, HCF_OPENSSL_DIGEST_SM3_STR, sm2Len) != EOK) {
        LOGE("memcpy sm2Str failed.");
        HcfFree(sm2Str);
        return HCF_ERR_MALLOC;
    }
    *returnString = sm2Str;
    return HCF_SUCCESS;
}

void HcfPrintOpensslError(void)
{
    char szErr[LOG_PRINT_MAX_LEN] = {0}; // Then maximum length of the OpenSSL error string is 256.
    unsigned long errCode;

    errCode = ERR_get_error();
    ERR_error_string_n(errCode, szErr, LOG_PRINT_MAX_LEN);

    LOGD("[error] [Openssl]: engine fail, error code = %lu, error string = %s", errCode, szErr);
}

HcfResult GetOpensslPadding(int32_t padding, int32_t *opensslPadding)
{
    if (opensslPadding == NULL) {
        LOGE("return openssl padding pointer is null");
        return HCF_INVALID_PARAMS;
    }
    switch (padding) {
        case HCF_ALG_NOPADDING:
            *opensslPadding = RSA_NO_PADDING;
            return HCF_SUCCESS;

        case HCF_OPENSSL_RSA_PKCS1_PADDING:
            *opensslPadding = RSA_PKCS1_PADDING;
            return HCF_SUCCESS;

        case HCF_OPENSSL_RSA_PKCS1_OAEP_PADDING:
            *opensslPadding = RSA_PKCS1_OAEP_PADDING;
            return HCF_SUCCESS;

        case HCF_OPENSSL_RSA_PSS_PADDING:
            *opensslPadding = RSA_PKCS1_PSS_PADDING;
            return HCF_SUCCESS;

        default:
            LOGD("[error] Invalid framwork padding = %d", padding);
            return HCF_INVALID_PARAMS;
    }
}

int32_t GetRealPrimes(int32_t primesFlag)
{
    switch (primesFlag) {
        case HCF_OPENSSL_PRIMES_2:
            return PRIMES_2;
        case HCF_OPENSSL_PRIMES_3:
            return PRIMES_3;
        case HCF_OPENSSL_PRIMES_4:
            return PRIMES_4;
        case HCF_OPENSSL_PRIMES_5:
            return PRIMES_5;
        default:
            LOGD("set default primes 2");
            return PRIMES_2;
    }
}

bool IsBigEndian(void)
{
    uint32_t *pointer = (uint32_t *)&ASCII_CODE_ZERO;
    char firstChar = *((char *)pointer);
    if (firstChar == '0') {
        return false;
    } else {
        return true;
    }
}

HcfResult BigIntegerToBigNum(const HcfBigInteger *src, BIGNUM **dest)
{
    if (src == NULL || dest == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (IsBigEndian()) {
        *dest = OpensslBin2Bn((src->data), (src->len), NULL);
    } else {
        *dest = OpensslLeBin2Bn((src->data), (src->len), NULL);
    }

    if (*dest == NULL) {
        LOGD("[error] translate BigInteger to BIGNUM failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult BigNumToBigInteger(const BIGNUM *src, HcfBigInteger *dest)
{
    if (src == NULL || dest == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    int len = OpensslBnNumBytes(src);
    if (len <= 0) {
        LOGD("[error] Invalid input parameter.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    dest->data = (unsigned char *)HcfMalloc(len, 0);
    if (dest->data == NULL) {
        LOGE("Alloc dest->data memeory failed.");
        return HCF_ERR_MALLOC;
    }
    dest->len = len;

    int resLen = -1;
    if (IsBigEndian()) {
        resLen = OpensslBn2BinPad(src, dest->data, dest->len);
    } else {
        resLen = OpensslBn2LeBinPad(src, dest->data, dest->len);
    }

    if (resLen != len) {
        LOGD("[error] translate BIGNUM to BigInteger failed.");
        HcfPrintOpensslError();
        HcfFree(dest->data);
        dest->data = NULL;
        dest->len = 0;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult KeyDerive(EVP_PKEY *priKey, EVP_PKEY *pubKey, HcfBlob *returnSecret)
{
    EVP_PKEY_CTX *ctx = OpensslEvpPkeyCtxNew(priKey, NULL);
    if (ctx == NULL) {
        LOGD("[error] EVP_PKEY_CTX_new failed!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    do {
        if (OpensslEvpPkeyDeriveInit(ctx) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Evp key derive init failed!");
            HcfPrintOpensslError();
            break;
        }
        if (OpensslEvpPkeyDeriveSetPeer(ctx, pubKey) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Evp key derive set peer failed!");
            HcfPrintOpensslError();
            break;
        }
        size_t maxLen;
        if (OpensslEvpPkeyDerive(ctx, NULL, &maxLen) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Evp key derive failed!");
            HcfPrintOpensslError();
            break;
        }
        uint8_t *secretData = (uint8_t *)HcfMalloc(maxLen, 0);
        if (secretData == NULL) {
            LOGE("Failed to allocate secretData memory!");
            ret = HCF_ERR_MALLOC;
            break;
        }
        size_t actualLen = maxLen;
        if (OpensslEvpPkeyDerive(ctx, secretData, &actualLen) != HCF_OPENSSL_SUCCESS) {
            LOGD("[error] Evp key derive failed!");
            HcfPrintOpensslError();
            HcfFree(secretData);
            break;
        }
        if (actualLen > maxLen) {
            LOGD("[error] signature data too long.");
            HcfFree(secretData);
            break;
        }
        returnSecret->data = secretData;
        returnSecret->len = actualLen;
        ret = HCF_SUCCESS;
    } while (0);
    OpensslEvpPkeyCtxFree(ctx);
    return ret;
}

HcfResult GetKeyEncodedPem(EVP_PKEY *pkey, const char *outPutStruct, int selection, char **returnString)
{
    OSSL_ENCODER_CTX *ctx = OpensslOsslEncoderCtxNewForPkey(pkey, selection, "PEM", outPutStruct, NULL);
    if (ctx == NULL) {
        LOGE("OSSL_ENCODER_CTX_new_for_pkey failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }

    unsigned char *data = NULL;
    size_t dataLen = 0;
    if (OpensslOsslEncoderToData(ctx, &data, &dataLen) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        OpensslOsslEncoderCtxFree(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnString = (char *)data;
    OpensslOsslEncoderCtxFree(ctx);
    return HCF_SUCCESS;
}
