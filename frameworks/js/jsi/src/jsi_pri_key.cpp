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

JSIValue CryptoFrameworkLiteModule::ConstructPriKeyJsObject(HcfPriKey *priKey)
{
    JSIValue priKeyObj = JSI::CreateObject();
    if (priKeyObj == nullptr) {
        LOGE("Create priKeyObj failed!");
        return nullptr;
    }
    JSI::SetNumberProperty(priKeyObj, "priKeyObj", (double)(uint32_t)priKey);
    JSIValue getEncoded = JSI::CreateFunction(PriKeyGetEncoded);
    JSIValue getEncodedDer = JSI::CreateFunction(PriKeyGetEncodedDer);
    JSIValue getEncodedPem = JSI::CreateFunction(PriKeyGetEncodedPem);
    JSIValue getAsyKeySpec = JSI::CreateFunction(PriKeyGetAsyKeySpec);
    JSIValue getKeySize = JSI::CreateFunction(PriKeyGetKeySize);
    JSIValue getPubKey = JSI::CreateFunction(PriKeyGetPubKey);
    JSIValue getPubKeySync = JSI::CreateFunction(PriKeyGetPubKeySync);
    JSIValue getKeyData = JSI::CreateFunction(PriKeyGetKeyData);
    JSIValue getKeyDataSync = JSI::CreateFunction(PriKeyGetKeyDataSync);
    JSIValue clearMem = JSI::CreateFunction(PriKeyClearMem);
    JSI::SetNamedProperty(priKeyObj, "getEncoded", getEncoded);
    JSI::SetNamedProperty(priKeyObj, "getEncodedDer", getEncodedDer);
    JSI::SetNamedProperty(priKeyObj, "getEncodedPem", getEncodedPem);
    JSI::SetNamedProperty(priKeyObj, "getAsyKeySpec", getAsyKeySpec);
    JSI::SetNamedProperty(priKeyObj, "getKeySize", getKeySize);
    JSI::SetNamedProperty(priKeyObj, "getPubKey", getPubKey);
    JSI::SetNamedProperty(priKeyObj, "getPubKeySync", getPubKeySync);
    JSI::SetNamedProperty(priKeyObj, "getKeyData", getKeyData);
    JSI::SetNamedProperty(priKeyObj, "getKeyDataSync", getKeyDataSync);
    JSI::SetNamedProperty(priKeyObj, "clearMem", clearMem);
    JSI::ReleaseValueList(getEncoded, getEncodedDer, getEncodedPem, getAsyKeySpec, getKeySize, getPubKey,
        getPubKeySync, getKeyData, getKeyDataSync, clearMem, ARGS_END);
    return priKeyObj;
}

JSIValue CryptoFrameworkLiteModule::PriKeyGetEncoded(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PriKeyGetEncodedDer(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PriKeyGetEncodedPem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PriKeyGetAsyKeySpec(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PriKeyGetKeySize(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PriKeyGetPubKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PriKeyGetPubKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PriKeyGetKeyData(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PriKeyGetKeyDataSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)thisVal;
    (void)args;
    (void)argsNum;
    return ThrowErrorCodeResult(HCF_NOT_SUPPORT);
}

JSIValue CryptoFrameworkLiteModule::PriKeyClearMem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum)
{
    (void)args;
    (void)argsNum;
    HcfPriKey *priKey = reinterpret_cast<HcfPriKey *>((uint32_t)JSI::GetNumberProperty(thisVal, "priKeyObj"));
    if (priKey == nullptr) {
        LOGE("PriKeyClearMem priKey is null!");
        return JSI::CreateErrorWithCode(GetJsiErrValueByErrCode(HCF_INVALID_PARAMS), "PriKeyClearMem priKey is null!");
    }
    priKey->clearMem(priKey);
    return ThrowErrorCodeResult(HCF_SUCCESS);
}

} // namespace ACELite
} // namespace OHOS
