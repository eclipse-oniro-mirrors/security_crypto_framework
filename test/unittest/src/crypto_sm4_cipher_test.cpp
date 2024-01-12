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

#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include "securec.h"
#include "aes_openssl.h"
#include "blob.h"
#include "cipher.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "log.h"
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"
#include "sm4_common.h"
#include "sm4_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSM4CipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest004, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest005, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }
    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest006, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest007, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest008, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest009, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest016, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CTR|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest017, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CTR|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest018, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CTR|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest022, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest023, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest024, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest025, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest026, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest027, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest044, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest045, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate(nullptr, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest052, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("SM4_128|CCC|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should not select CCC for SM4 generator.");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest055, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKeyForSm4("SM4_128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKeyForSm4 failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4Encrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest057, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKeyForSm4("SM4_128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKeyForSm4 failed!");
        goto CLEAR_UP;
    }

    // allow input without encryption mode. It will use default aes128ecb.
    ret = HcfCipherCreate("SM4_128|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }
CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest060, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKeyForSm4("SM4_128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKeyForSm4 failed!");
        goto CLEAR_UP;
    }

    // allow input without encryption mode. It will pick the last PKCS5, and use default aes128ecb.
    ret = HcfCipherCreate("SM4_128|NoPadding|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }
CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest062, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;

    res = HcfCipherSm4GeneratorSpiCreate(nullptr, &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest063, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm4GeneratorSpiCreate(&params, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest064, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    retkey = GenerateSymKeyForSm4("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init((HcfCipherGeneratorSpi *)(&obj), ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest065, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    retkey = GenerateSymKeyForSm4("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(nullptr, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest066, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest067, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    retkey = GenerateSymKeyForSm4("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    cipher->base.destroy(nullptr);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest069, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };

    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    retkey = GenerateSymKeyForSm4("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob blob;
    res = cipher->update(nullptr, &input, &blob);
    EXPECT_NE(res, 0);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest070, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };

    retkey = GenerateSymKeyForSm4("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob blob;
    res = cipher->update(cipher, nullptr, &blob);
    EXPECT_NE(res, 0);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest071, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };

    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    retkey = GenerateSymKeyForSm4("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->update(cipher, &input, nullptr);
    EXPECT_NE(res, 0);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest073, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(nullptr, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest074, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest075, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfBlob input = {
        .data = nullptr,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest077, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    uint8_t plan[] = "12312123123";
    HcfBlob input = {
        .data = (uint8_t *)plan,
        .len = -1
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest078, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfBlob input = {
        .data = nullptr,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->update(cipher, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest079, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKeyForSm4("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKeyForSm4 failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest080, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKeyForSm4("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKeyForSm4 failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CTR|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest081, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKeyForSm4("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKeyForSm4 failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}
}