/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANI_SYM_KEY_H
#define ANI_SYM_KEY_H

#include "ani_common.h"
#include "sym_key.h"

namespace ANI::CryptoFramework {
using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;

class SymKeyImpl {
public:
    SymKeyImpl();
    explicit SymKeyImpl(HcfSymKey *obj);
    ~SymKeyImpl();

    void ClearMem();
    int64_t GetSymKeyObj();
    DataBlob GetEncoded();
    string GetFormat();
    string GetAlgName();

private:
    HcfSymKey *symKey = nullptr;
};
} // namespace ANI::CryptoFramework

#endif // ANI_SYM_KEY_H
