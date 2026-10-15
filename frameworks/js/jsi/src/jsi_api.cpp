/*
 * Copyright (C) 2024-2026 Huawei Device Co., Ltd.
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
#include "jsi_list.h"
#include "jsi.h"
#include "jsi_api_common.h"
#include "cipher.h"

namespace OHOS {
namespace ACELite {

static JSIValue CreateCryptoMode(void)
{
    JSIValue cryptoMode = JSI::CreateObject();
    JSI::SetNumberProperty(cryptoMode, "ENCRYPT_MODE", (double)ENCRYPT_MODE);
    JSI::SetNumberProperty(cryptoMode, "DECRYPT_MODE", (double)DECRYPT_MODE);
    return cryptoMode;
}

static JSIValue CreateAsyKeyDataItem(void)
{
    JSIValue asyKeyDataItem = JSI::CreateObject();
    JSI::SetNumberProperty(asyKeyDataItem, "EC_PRIVATE_K", (double)EC_PRIVATE_K);
    JSI::SetNumberProperty(asyKeyDataItem, "EC_PRIVATE_04_X_Y_K", (double)EC_PRIVATE_04_X_Y_K);
    JSI::SetNumberProperty(asyKeyDataItem, "EC_PUBLIC_X_Y", (double)EC_PUBLIC_X_Y);
    JSI::SetNumberProperty(asyKeyDataItem, "EC_PUBLIC_04_X_Y", (double)EC_PUBLIC_04_X_Y);
    JSI::SetNumberProperty(asyKeyDataItem, "EC_PUBLIC_COMPRESS_X", (double)EC_PUBLIC_COMPRESS_X);
    return asyKeyDataItem;
}

void InitCryptoFrameworkModule(JSIValue exports)
{
    JSI::SetModuleAPI(exports, "createMd", CryptoFrameworkLiteModule::CreateMd);
    JSI::SetModuleAPI(exports, "createMac", CryptoFrameworkLiteModule::CreateMac);
    JSI::SetModuleAPI(exports, "createRandom", CryptoFrameworkLiteModule::CreateRandom);
    JSI::SetModuleAPI(exports, "createSymKeyGenerator", CryptoFrameworkLiteModule::CreateSymKeyGenerator);
    JSI::SetModuleAPI(exports, "createCipher", CryptoFrameworkLiteModule::CreateCipher);
    JSIValue cryptoMode = CreateCryptoMode();
    JSI::SetNamedProperty(exports, "CryptoMode", cryptoMode);
    JSI::ReleaseValue(cryptoMode);
    JSIValue asyKeyDataItem = CreateAsyKeyDataItem();
    JSI::SetNamedProperty(exports, "AsyKeyDataItem", asyKeyDataItem);
    JSI::ReleaseValue(asyKeyDataItem);
    JSI::SetModuleAPI(exports, "createAsyKeyGenerator", CryptoFrameworkLiteModule::CreateAsyKeyGenerator);
    JSI::SetModuleAPI(exports, "createKeyAgreement", CryptoFrameworkLiteModule::CreateKeyAgreement);
    JSI::SetOnDestroy(exports, CryptoFrameworkLiteModule::OnDestroy);
    ListObjInit(JSI_ALG_MD);
    ListObjInit(JSI_ALG_MAC);
    ListObjInit(JSI_ALG_RAND);
    ListObjInit(JSI_ALG_SYM_KEY);
    ListObjInit(JSI_ALG_CIPHER);
    ListObjInit(JSI_ALG_ASY_KEY_GENERATOR);
    ListObjInit(JSI_ALG_ASY_KEY_PAIR);
    ListObjInit(JSI_ALG_KEY_AGREEMENT);
}

void CryptoFrameworkLiteModule::OnDestroy(void)
{
    CipherDestroy();
    SymKeyDestroy();
    KeyAgreementDestroy();
    AsyKeyPairDestroy();
    AsyKeyGeneratorDestroy();
    RandomDestroy();
    MacDestroy();
    MdDestroy();
}

} // ACELite
} // OHOS
