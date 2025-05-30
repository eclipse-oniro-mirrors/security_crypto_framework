/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "aes_common.h"
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
class CryptoSM4EcbCipherTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest001, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest002, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest003, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest019, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|NoPadding", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest020, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest021, TestSize.Level0)
{
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS7", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest034, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSm4SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(nullptr, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest035, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSm4SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(cipher), nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest036, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = GenerateSm4SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->update(nullptr, &input, &output);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest037, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = GenerateSm4SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->update(reinterpret_cast<HcfCipher *>(key), &input, &output);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest038, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = GenerateSm4SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(nullptr, &input, &output);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest039, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    int ret = GenerateSm4SymKey(&key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(reinterpret_cast<HcfCipher *>(key), &input, &output);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest046, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(cipher);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoAesCipherTest048, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    int ret = GenerateSymKeyForSm4("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4EncryptWithInput(cipher, key, &input, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4DecryptEmptyMsg(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoAesCipherTest049, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob input = { .data = nullptr, .len = 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    int ret = GenerateSymKeyForSm4("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4EncryptWithInput(cipher, key, &input, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4DecryptEmptyMsg(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest053, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(generator, &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(reinterpret_cast<HcfCipher *>(generator), ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest054, TestSize.Level0)
{
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };

    int ret = GenerateSymKeyForSm4("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    ASSERT_EQ(ret, 0);

    ret = cipher->doFinal(cipher, &input, nullptr);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest058, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKeyForSm4("SM4_128", &key);
    ASSERT_EQ(ret, 0);

    // allow input with more than one padding mode. It will pick the last PKCS5.
    ret = HcfCipherCreate("SM4_128|ECB|NoPadding|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_EQ(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_EQ(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest059, TestSize.Level0)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    int ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    ASSERT_EQ(ret, 0);

    ret = generator->generateSymKey(reinterpret_cast<HcfSymKeyGenerator *>(cipher), &key);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4EcbCipherTest, CryptoSm4CipherTest061, TestSize.Level0)
{
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    int ret = GenerateSymKeyForSm4("AES256", &key);
    ASSERT_EQ(ret, 0);

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    ASSERT_EQ(ret, 0);

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    ASSERT_NE(ret, 0);

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    ASSERT_NE(ret, 0);

    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
}
}