/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <cstring>

#include "asy_key_generator.h"
#include "blob.h"
#include "sm2_openssl.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSm2SignTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *sm2256KeyPair_;
};

HcfKeyPair *CryptoSm2SignTest::sm2256KeyPair_ = nullptr;

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

void CryptoSm2SignTest::SetUp() {}
void CryptoSm2SignTest::TearDown() {}

void CryptoSm2SignTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    sm2256KeyPair_ = keyPair;

    HcfObjDestroy(generator);
}

void CryptoSm2SignTest::TearDownTestCase()
{
    HcfObjDestroy(sm2256KeyPair_);
}

static const char *GetMockClass(void)
{
    return "HcfMock";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest002, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate(nullptr, &sign);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest003, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &sign);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest004, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM5|SM3", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest005, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM5", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest006, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|MD5", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest007, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2SM3", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest008, TestSize.Level0)
{
    int32_t res = HcfSignCreate("SM2|SM3", nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest009, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *className = sign->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest010, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy((HcfObjectBase *)sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest011, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest012, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(&obj);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest013, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(sign);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest014, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest016, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest017, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(nullptr, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest019, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest020, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest022, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest023, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(nullptr, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest025, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest026, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest027, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest028, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest029, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest030, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest031, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(nullptr, nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest033, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest034, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &input, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest035, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &input, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest036, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->sign(sign, nullptr, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest037, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out2 = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out2);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->init(verify, nullptr, sm2256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    verify->update(verify, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);
    ASSERT_EQ(flag, true);

    verify->update(verify, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    flag = verify->verify(verify, nullptr, &out2);
    ASSERT_EQ(flag, true);

    free(out.data);
    free(out2.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest038, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out2 = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out2);

    free(out2.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest039, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("SM2|SM3", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    res = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest040, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("SM2|SM3", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    res = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest041, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiSm2Create(nullptr, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest042, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    int32_t res = HcfSignSpiSm2Create(&params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest043, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineInit((HcfSignSpi *)&obj, nullptr, sm2256KeyPair_->priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest045, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = spiObj->engineUpdate(nullptr, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest047, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineUpdate(spiObj, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest049, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

static void MemoryMallocTestFunc(uint32_t mallocCount, HcfBlob *input)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        HcfAsyKeyGenerator *generator = nullptr;
        int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfSign *sign = nullptr;
        res = HcfSignCreate("SM2|SM3", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyPair);
            continue;
        }
        res = sign->init(sign, nullptr, keyPair->priKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        res = sign->update(sign, input);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        res = sign->sign(sign, nullptr, &out);
        HcfObjDestroy(sign);
        HcfObjDestroy(keyPair);
        if (res == HCF_SUCCESS) {
            free(out.data);
        }
    }
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest051, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("SM2|SM3", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    res = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);

    uint32_t mallocCount = GetMallocNum();
    MemoryMallocTestFunc(mallocCount, &input);

    EndRecordMallocNum();
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfBlob *input)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfAsyKeyGenerator *generator = nullptr;
        int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfSign *sign = nullptr;
        res = HcfSignCreate("SM2|SM3", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyPair);
            continue;
        }
        res = sign->init(sign, nullptr, keyPair->priKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        res = sign->update(sign, input);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        res = sign->sign(sign, input, &out);
        HcfObjDestroy(sign);
        HcfObjDestroy(keyPair);
        if (res == HCF_SUCCESS) {
            free(out.data);
        }
    }
}

HWTEST_F(CryptoSm2SignTest, CryptoSm2SignTest052, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("SM2|SM3", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    res = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, &input);

    EndRecordOpensslCallNum();
}
}