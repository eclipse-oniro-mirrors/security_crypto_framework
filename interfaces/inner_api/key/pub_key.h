/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_PUB_KEY_H
#define HCF_PUB_KEY_H

#include "big_integer.h"
#include "key.h"

typedef struct HcfPubKey HcfPubKey;

struct HcfPubKey {
    HcfKey base;

    HcfResult (*getAsyKeySpecBigInteger)(const HcfPubKey *self, const AsyKeySpecItem item,
        HcfBigInteger *returnBigInteger);

    HcfResult (*getAsyKeySpecString)(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString);

    HcfResult (*getAsyKeySpecInt)(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt);

    HcfResult (*getEncodedDer)(const HcfPubKey *self, const char *format, HcfBlob *returnBlob);
};

#endif