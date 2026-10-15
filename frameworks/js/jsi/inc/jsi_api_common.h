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

#ifndef JSI_API_COMMON_H
#define JSI_API_COMMON_H

#include "jsi.h"
#include "jsi/jsi_types.h"

#include "md.h"
#include "mac.h"
#include "rand.h"
#include "cipher.h"
#include "sym_key_generator.h"
#include "asy_key_generator.h"
#include "key_agreement.h"
#include "object_base.h"

namespace OHOS {
namespace ACELite {

typedef enum {
    JSI_ALG_MD = 1,
    JSI_ALG_RAND = 2,
    JSI_ALG_SYM_KEY = 3,
    JSI_ALG_CIPHER = 4,
    JSI_ALG_MAC = 5,
    JSI_ALG_ASY_KEY_GENERATOR = 6,
    JSI_ALG_ASY_KEY_PAIR = 7,
    JSI_ALG_KEY_AGREEMENT = 8,
    JSI_ALG_MAX
} LiteAlgType;

#define ARGS_SIZE_ONE 1
#define ARGS_SIZE_TWO 2
#define ARGS_SIZE_THREE 3
#define ARGS_SIZE_FOUR 4
#define ARRAY_INDEX_ZERO 0
#define ARRAY_INDEX_ONE 1
#define ARRAY_INDEX_TWO 2
#define ARRAY_INDEX_THREE 3
#define EC_PRIVATE_K 6
#define EC_PRIVATE_04_X_Y_K 7
#define EC_PUBLIC_X_Y 8
#define EC_PUBLIC_04_X_Y 9
#define EC_PUBLIC_COMPRESS_X 10

void JsiAsyncCallback(const JSIValue thisVal, JSIValue args, const JSIValue *params, uint8_t paramsNum);

}  // namespace ACELite
}  // namespace OHOS
#endif // JSI_API_COMMON_H
