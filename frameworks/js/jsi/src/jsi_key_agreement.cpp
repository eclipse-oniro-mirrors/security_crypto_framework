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

JSIValue CryptoFrameworkLiteModule::CreateKeyAgreement(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("CreateKeyAgreement args is err!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    char *alg = JSI::ValueToString(args[0]);
    if (alg == nullptr) {
        LOGE("CreateKeyAgreement alg is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(reinterpret_cast<const char *>(alg), &keyAgreement);
    if (res != HCF_SUCCESS) {
        LOGE("CreateKeyAgreement is keyAgreement err res %d!", res);
        JSI::ReleaseString(alg);
        return ThrowErrorCodeResult(res);
    }
    res = ListAddObjNode(JSI_ALG_KEY_AGREEMENT, (uint32_t)keyAgreement);
    if (res != HCF_SUCCESS) {
        LOGE("key agreement add node is %d err!", res);
        HcfObjDestroy(static_cast<void *>(keyAgreement));
        JSI::ReleaseString(alg);
        return ThrowErrorCodeResult(res);
    }

    JSIValue serviceObj = JSI::CreateObject();
    JSIValue generateSecret = JSI::CreateFunction(GenerateSecret);
    JSIValue generateSecretSync = JSI::CreateFunction(GenerateSecretSync);
    JSI::SetNamedProperty(serviceObj, "generateSecret", generateSecret);
    JSI::SetNamedProperty(serviceObj, "generateSecretSync", generateSecretSync);
    JSI::SetNumberProperty(serviceObj, "keyAgreementObj", (double)(uint32_t)keyAgreement);
    JSI::ReleaseValueList(generateSecret, generateSecretSync, ARGS_END);

    JSI::ReleaseString(alg);
    return serviceObj;
}

JSIValue CryptoFrameworkLiteModule::GenerateSecretSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_TWO)) {
        LOGE("GenerateSecretSync args is err!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    HcfKeyAgreement *keyAgreement =
        reinterpret_cast<HcfKeyAgreement *>((uint32_t)JSI::GetNumberProperty(thisVal, "keyAgreementObj"));
    if (keyAgreement == nullptr) {
        LOGE("GenerateSecretSync keyAgreement is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    HcfPriKey *priKey =
        reinterpret_cast<HcfPriKey *>((uint32_t)JSI::GetNumberProperty(args[ARRAY_INDEX_ZERO], "priKeyObj"));
    if (priKey == nullptr) {
        LOGE("GenerateSecretSync priKey is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    HcfPubKey *pubKey =
        reinterpret_cast<HcfPubKey *>((uint32_t)JSI::GetNumberProperty(args[ARRAY_INDEX_ONE], "pubKeyObj"));
    if (pubKey == nullptr) {
        LOGE("GenerateSecretSync pubKey is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }

    HcfBlob returnSecret = { .data = nullptr, .len = 0 };
    HcfResult res = keyAgreement->generateSecret(keyAgreement, priKey, pubKey, &returnSecret);
    if (res != HCF_SUCCESS) {
        LOGE("GenerateSecretSync generateSecret err res %d!", res);
        HcfBlobDataClearAndFree(&returnSecret);
        return ThrowErrorCodeResult(res);
    }

    JSIValue outValue = ConstructJSIReturnResult(&returnSecret);
    HcfBlobDataClearAndFree(&returnSecret);
    return outValue;
}

JSIValue CryptoFrameworkLiteModule::GenerateSecret(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_THREE)) {
        LOGE("GenerateSecret args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "GenerateSecret args is err!");
    }
    if (args[ARRAY_INDEX_TWO] == nullptr) {
        LOGE("GenerateSecret promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "GenerateSecret is not supported.");
    }
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_TWO], HCF_NOT_SUPPORT, JSI::CreateNull());
    return JSI::CreateUndefined();
}

void CryptoFrameworkLiteModule::KeyAgreementDestroy(void)
{
    ListDestroy(JSI_ALG_KEY_AGREEMENT);
}

} // namespace ACELite
} // namespace OHOS
