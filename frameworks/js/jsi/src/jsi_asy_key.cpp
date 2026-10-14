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

#include "jsi_api.h"
#include "jsi_api_common.h"
#include "jsi_api_errcode.h"
#include "jsi_utils.h"
#include "jsi_list.h"
#include "securec.h"
#include "jsi.h"
#include "jsi_types.h"
#include "log.h"

namespace OHOS {
namespace ACELite {

JSIValue CryptoFrameworkLiteModule::ConstructKeyPairJsObject(HcfKeyPair *keyPair)
{
    JSIValue keyPairObj = JSI::CreateObject();
    if (keyPairObj == nullptr) {
        LOGE("Create keyPairObj failed!");
        return nullptr;
    }
    JSI::SetNumberProperty(keyPairObj, "keyPairObj", (double)(uint32_t)keyPair);

    if (keyPair->pubKey != nullptr) {
        JSIValue pubKeyObj = ConstructPubKeyJsObject(keyPair->pubKey);
        if (pubKeyObj != nullptr) {
            JSI::SetNamedProperty(keyPairObj, "pubKey", pubKeyObj);
            JSI::ReleaseValue(pubKeyObj);
        }
    }

    if (keyPair->priKey != nullptr) {
        JSIValue priKeyObj = ConstructPriKeyJsObject(keyPair->priKey);
        if (priKeyObj != nullptr) {
            JSI::SetNamedProperty(keyPairObj, "priKey", priKeyObj);
            JSI::ReleaseValue(priKeyObj);
        }
    }
    return keyPairObj;
}

JSIValue CryptoFrameworkLiteModule::CreateAsyKeyGenerator(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("CreateAsyKeyGenerator args is err!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    char *alg = JSI::ValueToString(args[0]);
    if (alg == nullptr) {
        LOGE("CreateAsyKeyGenerator alg is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(reinterpret_cast<const char *>(alg), &generator);
    if (res != HCF_SUCCESS) {
        LOGE("CreateAsyKeyGenerator is generator err res %d!", res);
        JSI::ReleaseString(alg);
        return ThrowErrorCodeResult(res);
    }
    res = ListAddObjNode(JSI_ALG_ASY_KEY_GENERATOR, (uint32_t)generator);
    if (res != HCF_SUCCESS) {
        LOGE("asy key generator add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(generator));
        JSI::ReleaseString(alg);
        return ThrowErrorCodeResult(res);
    }

    JSIValue serviceObj = JSI::CreateObject();
    JSIValue generateKeyPair = JSI::CreateFunction(GenerateKeyPair);
    JSIValue generateKeyPairSync = JSI::CreateFunction(GenerateKeyPairSync);
    JSIValue convertKey = JSI::CreateFunction(ConvertKey);
    JSIValue convertKeySync = JSI::CreateFunction(ConvertKeySync);
    JSIValue convertPemKey = JSI::CreateFunction(ConvertPemKey);
    JSIValue convertPemKeySync = JSI::CreateFunction(ConvertPemKeySync);
    JSI::SetNamedProperty(serviceObj, "generateKeyPair", generateKeyPair);
    JSI::SetNamedProperty(serviceObj, "generateKeyPairSync", generateKeyPairSync);
    JSI::SetNamedProperty(serviceObj, "convertKey", convertKey);
    JSI::SetNamedProperty(serviceObj, "convertKeySync", convertKeySync);
    JSI::SetNamedProperty(serviceObj, "convertPemKey", convertPemKey);
    JSI::SetNamedProperty(serviceObj, "convertPemKeySync", convertPemKeySync);
    JSI::SetNumberProperty(serviceObj, "generatorObj", (double)(uint32_t)generator);
    JSI::ReleaseValueList(generateKeyPair, generateKeyPairSync, convertKey, convertKeySync,
        convertPemKey, convertPemKeySync, ARGS_END);

    JSI::ReleaseString(alg);
    return serviceObj;
}

JSIValue CryptoFrameworkLiteModule::GenerateKeyPairSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)args;
    (void)argsNum;
    HcfAsyKeyGenerator *generator =
        reinterpret_cast<HcfAsyKeyGenerator *>((uint32_t)JSI::GetNumberProperty(thisVal, "generatorObj"));
    if (generator == nullptr) {
        LOGE("GenerateKeyPairSync generator is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    HcfKeyPair *keyPair = nullptr;
    HcfResult res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        LOGE("GenerateKeyPairSync generateKeyPair err res %d!", res);
        return ThrowErrorCodeResult(res);
    }
    res = ListAddObjNode(JSI_ALG_ASY_KEY_PAIR, (uint32_t)keyPair);
    if (res != HCF_SUCCESS) {
        LOGE("GenerateKeyPairSync add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(keyPair));
        return ThrowErrorCodeResult(res);
    }

    JSIValue keyPairObj = ConstructKeyPairJsObject(keyPair);
    if (keyPairObj == nullptr) {
        LOGE("GenerateKeyPairSync construct keyPair obj failed!");
        return ThrowErrorCodeResult(HCF_ERR_CRYPTO_OPERATION);
    }
    return keyPairObj;
}

JSIValue CryptoFrameworkLiteModule::GenerateKeyPair(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("GenerateKeyPair args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "GenerateKeyPair args is err!");
    }
    if (args[ARRAY_INDEX_ZERO] == nullptr) {
        LOGE("GenerateKeyPair promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "GenerateKeyPair is not supported.");
    }
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ZERO], HCF_NOT_SUPPORT, JSI::CreateNull());
    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::ConvertKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_TWO)) {
        LOGE("ConvertKeySync args is err!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    if (JSI::ValueIsObject(args[ARRAY_INDEX_ONE])) {
        LOGE("ConvertKeySync priKey is not supported.");
        return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
    }
    HcfAsyKeyGenerator *generator =
        reinterpret_cast<HcfAsyKeyGenerator *>((uint32_t)JSI::GetNumberProperty(thisVal, "generatorObj"));
    if (generator == nullptr) {
        LOGE("ConvertKeySync generator is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    HcfResult errCode = ParseUint8ArrayToBlob(inValue, &pubKeyBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("ConvertKeySync pubKeyBlob is null!");
        return ThrowErrorCodeResult(errCode);
    }

    HcfKeyPair *keyPair = nullptr;
    HcfResult res = generator->convertKey(generator, nullptr, &pubKeyBlob, nullptr, &keyPair);
    HcfBlobDataClearAndFree(&pubKeyBlob);
    if (res != HCF_SUCCESS) {
        LOGE("ConvertKeySync convertKey err res %d!", res);
        return ThrowErrorCodeResult(res);
    }
    res = ListAddObjNode(JSI_ALG_ASY_KEY_PAIR, (uint32_t)keyPair);
    if (res != HCF_SUCCESS) {
        LOGE("ConvertKeySync add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(keyPair));
        return ThrowErrorCodeResult(res);
    }

    JSIValue keyPairObj = ConstructKeyPairJsObject(keyPair);
    if (keyPairObj == nullptr) {
        LOGE("ConvertKeySync construct keyPair obj failed!");
        return ThrowErrorCodeResult(HCF_ERR_CRYPTO_OPERATION);
    }
    return keyPairObj;
}

static bool ConvertKeyParseParams(const JSIValue thisVal, const JSIValue *args,
    JSIValue callback, HcfAsyKeyGenerator **generator, HcfBlob *pubKeyBlob)
{
    if (JSI::ValueIsObject(args[ARRAY_INDEX_ONE])) {
        LOGE("ConvertKey priKey is not supported.");
        CallbackErrorCodeOrDataResult(thisVal, callback, HCF_NOT_SUPPORT, JSI::CreateNull());
        return false;
    }
    *generator = reinterpret_cast<HcfAsyKeyGenerator *>((uint32_t)JSI::GetNumberProperty(thisVal, "generatorObj"));
    if (*generator == nullptr) {
        LOGE("ConvertKey generator is null!");
        CallbackErrorCodeOrDataResult(thisVal, callback, HCF_INVALID_PARAMS, JSI::CreateNull());
        return false;
    }
    JSIValue inValue = JSI::GetNamedProperty(args[ARRAY_INDEX_ZERO], "data");
    HcfResult errCode = ParseUint8ArrayToBlob(inValue, pubKeyBlob);
    if (errCode != HCF_SUCCESS) {
        LOGE("ConvertKey pubKeyBlob is null!");
        CallbackErrorCodeOrDataResult(thisVal, callback, errCode, JSI::CreateNull());
        return false;
    }
    return true;
}

JSIValue CryptoFrameworkLiteModule::ConvertKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_THREE)) {
        LOGE("ConvertKey args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "ConvertKey args is err!");
    }
    if (args[ARRAY_INDEX_TWO] == nullptr) {
        LOGE("ConvertKey promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "ConvertKey is not supported.");
    }
    HcfAsyKeyGenerator *generator = nullptr;
    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    if (!ConvertKeyParseParams(thisVal, args, args[ARRAY_INDEX_TWO], &generator, &pubKeyBlob)) {
        return JSI::CreateUndefined();
    }
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = generator->convertKey(generator, nullptr, &pubKeyBlob, nullptr, &keyPair);
    HcfBlobDataClearAndFree(&pubKeyBlob);
    if (res != HCF_SUCCESS) {
        LOGE("ConvertKey convertKey err res %d!", res);
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_TWO], res, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    res = ListAddObjNode(JSI_ALG_ASY_KEY_PAIR, (uint32_t)keyPair);
    if (res != HCF_SUCCESS) {
        LOGE("ConvertKey add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(keyPair));
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_TWO], res, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    JSIValue keyPairObj = ConstructKeyPairJsObject(keyPair);
    if (keyPairObj == nullptr) {
        LOGE("ConvertKey construct keyPair obj failed!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_TWO], HCF_ERR_CRYPTO_OPERATION, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_TWO], HCF_SUCCESS, keyPairObj);
    return JSI::CreateUndefined();
}

JSIValue CryptoFrameworkLiteModule::ConvertPemKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::ConvertPemKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

void CryptoFrameworkLiteModule::AsyKeyGeneratorDestroy(void)
{
    ListDestroy(JSI_ALG_ASY_KEY_GENERATOR);
}

void CryptoFrameworkLiteModule::AsyKeyPairDestroy(void)
{
    ListDestroy(JSI_ALG_ASY_KEY_PAIR);
}

} // namespace ACELite
} // namespace OHOS
