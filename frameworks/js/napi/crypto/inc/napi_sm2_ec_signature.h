/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef HCF_NAPI_SM2_EC_SIGNATURE_H
#define HCF_NAPI_SM2_EC_SIGNATURE_H

#include <cstdint>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "sm2_ec_signature_data.h"

namespace OHOS {
namespace CryptoFramework {
class NapiSm2EcSignature {
public:
    explicit NapiSm2EcSignature();
    ~NapiSm2EcSignature();

    static napi_value JsGenEcSignatureDataSpec(napi_env env, napi_callback_info info);
    static napi_value JsGenEcSignatureData(napi_env env, napi_callback_info info);
    static napi_value SignatureUtilsConstructor(napi_env env, napi_callback_info info);
    static napi_value SignatureUtilsConstructorClass(napi_env env);
    static void DefineNapiSm2EcSignatureJSClass(napi_env env, napi_value exports);
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
