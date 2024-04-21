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

#ifndef HCF_NAPI_DH_KEY_UTIL_H
#define HCF_NAPI_DH_KEY_UTIL_H

#include <cstdint>
#include "dh_key_util.h"
#include "log.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CryptoFramework {
class NapiDHKeyUtil {
public:
    explicit NapiDHKeyUtil();
    ~NapiDHKeyUtil();
    
    static napi_value JsGenDHCommonParamsSpec(napi_env env, napi_callback_info info);
    static napi_value DHKeyUtilConstructor(napi_env env, napi_callback_info info);
    static napi_value GenDHCommonParamSpec(napi_env env);
    static void DefineNapiDHKeyUtilJSClass(napi_env env, napi_value exports);
};
}  // namespace CryptoFramework
}  // namespace OHOS
#endif
