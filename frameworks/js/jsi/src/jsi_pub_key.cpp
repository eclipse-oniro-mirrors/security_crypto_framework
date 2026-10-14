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

JSIValue CryptoFrameworkLiteModule::ConstructPubKeyJsObject(HcfPubKey *pubKey)
{
    JSIValue pubKeyObj = JSI::CreateObject();
    if (pubKeyObj == nullptr) {
        LOGE("Create pubKeyObj failed!");
        return nullptr;
    }
    JSI::SetNumberProperty(pubKeyObj, "pubKeyObj", (double)(uint32_t)pubKey);
    JSIValue getEncodedDer = JSI::CreateFunction(PubKeyGetEncodedDer);
    JSIValue getEncoded = JSI::CreateFunction(PubKeyGetEncoded);
    JSIValue getEncodedPem = JSI::CreateFunction(PubKeyGetEncodedPem);
    JSIValue getAsyKeySpec = JSI::CreateFunction(PubKeyGetAsyKeySpec);
    JSIValue getKeySize = JSI::CreateFunction(PubKeyGetKeySize);
    JSIValue getKeyData = JSI::CreateFunction(PubKeyGetKeyData);
    JSIValue getKeyDataSync = JSI::CreateFunction(PubKeyGetKeyDataSync);
    JSI::SetNamedProperty(pubKeyObj, "getEncodedDer", getEncodedDer);
    JSI::SetNamedProperty(pubKeyObj, "getEncoded", getEncoded);
    JSI::SetNamedProperty(pubKeyObj, "getEncodedPem", getEncodedPem);
    JSI::SetNamedProperty(pubKeyObj, "getAsyKeySpec", getAsyKeySpec);
    JSI::SetNamedProperty(pubKeyObj, "getKeySize", getKeySize);
    JSI::SetNamedProperty(pubKeyObj, "getKeyData", getKeyData);
    JSI::SetNamedProperty(pubKeyObj, "getKeyDataSync", getKeyDataSync);
    JSI::ReleaseValueList(getEncodedDer, getEncoded, getEncodedPem, getAsyKeySpec, getKeySize, getKeyData,
        getKeyDataSync, ARGS_END);
    return pubKeyObj;
}

JSIValue CryptoFrameworkLiteModule::PubKeyGetEncodedDer(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PubKeyGetEncoded(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PubKeyGetEncodedPem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PubKeyGetAsyKeySpec(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PubKeyGetKeySize(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PubKeyGetKeyDataSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARRAY_INDEX_ONE)) {
        LOGE("PubKeyGetKeyDataSync args is err!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    HcfPubKey *pubKey = reinterpret_cast<HcfPubKey *>((uint32_t)JSI::GetNumberProperty(thisVal, "pubKeyObj"));
    if (pubKey == nullptr) {
        LOGE("PubKeyGetKeyDataSync pubKey is null!");
        return ThrowErrorCodeResult(HCF_INVALID_PARAMS);
    }
    uint32_t type = (uint32_t)JSI::ValueToNumber(args[ARRAY_INDEX_ZERO]);
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult res = pubKey->getKeyData(pubKey, type, &returnBlob);
    if (res != HCF_SUCCESS) {
        LOGE("PubKeyGetKeyDataSync getKeyData err res %d!", res);
        return ThrowErrorCodeResult(res);
    }
    JSIValue outValue = ConstructJSIReturnResult(&returnBlob);
    HcfBlobDataClearAndFree(&returnBlob);
    return outValue;
}

JSIValue CryptoFrameworkLiteModule::PubKeyGetKeyData(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    if ((args == nullptr) || (argsNum != ARGS_SIZE_TWO)) {
        LOGE("PubKeyGetKeyData args is err!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "PubKeyGetKeyData args is err!");
    }
    if (args[ARRAY_INDEX_ONE] == nullptr) {
        LOGE("PubKeyGetKeyData promise is not supported.");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_NOT_SUPPORT),
            "PubKeyGetKeyData is not supported.");
    }
    HcfPubKey *pubKey = reinterpret_cast<HcfPubKey *>((uint32_t)JSI::GetNumberProperty(thisVal, "pubKeyObj"));
    if (pubKey == nullptr) {
        LOGE("PubKeyGetKeyData pubKey is null!");
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_INVALID_PARAMS, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    uint32_t type = (uint32_t)JSI::ValueToNumber(args[ARRAY_INDEX_ZERO]);
    HcfBlob returnBlob = { .data = nullptr, .len = 0 };
    HcfResult res = pubKey->getKeyData(pubKey, type, &returnBlob);
    if (res != HCF_SUCCESS) {
        LOGE("PubKeyGetKeyData getKeyData err res %d!", res);
        CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], res, JSI::CreateNull());
        return JSI::CreateUndefined();
    }
    JSIValue outValue = ConstructJSIReturnResult(&returnBlob);
    HcfBlobDataClearAndFree(&returnBlob);
    CallbackErrorCodeOrDataResult(thisVal, args[ARRAY_INDEX_ONE], HCF_SUCCESS, outValue);
    return JSI::CreateUndefined();
}

} // namespace ACELite
} // namespace OHOS
