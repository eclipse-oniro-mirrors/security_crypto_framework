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

#ifndef ANI_COMMON_H
#define ANI_COMMON_H

#include "stdexcept"
#include "taihe/runtime.hpp"
#include "ohos.security.cryptoFramework.cryptoFramework.proj.hpp"
#include "ohos.security.cryptoFramework.cryptoFramework.impl.hpp"

#include "log.h"
#include "blob.h"
#include "result.h"
#include "object_base.h"

#define ANI_LOGE_THROW(code, msg) \
    do { \
        taihe::set_business_error(code, msg); \
        LOGE(msg); \
    } while (0)

#endif // ANI_COMMON_H
