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

#ifndef ANI_MAC_H
#define ANI_MAC_H

#include "ani_common.h"
#include "mac.h"

namespace ANI::CryptoFramework {
using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;

class MacImpl {
public:
    MacImpl();
    explicit MacImpl(HcfMac *mac);
    ~MacImpl();

    void InitSync(weak::SymKey key);
    void UpdateSync(DataBlob const& input);
    DataBlob DoFinalSync();
    int32_t GetMacLength();
    string GetAlgName();

private:
    HcfMac *mac_ = nullptr;
};
} // namespace ANI::CryptoFramework

#endif // ANI_MAC_H
