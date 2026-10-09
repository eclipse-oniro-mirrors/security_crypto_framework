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

#include "params_parser.h"

#include <string.h>
#include "log.h"

static const HcfParaConfig PARAM_CONFIG[] = {
    {"AES128",       HCF_ALG_KEY_TYPE,       HCF_ALG_AES_128},

    {"CBC",          HCF_ALG_MODE,           HCF_ALG_MODE_CBC},
    {"GCM",          HCF_ALG_MODE,           HCF_ALG_MODE_GCM},

    {"NoPadding",    HCF_ALG_PADDING_TYPE,   HCF_ALG_NOPADDING},
    {"PKCS5",        HCF_ALG_PADDING_TYPE,   HCF_ALG_PADDING_PKCS5},
    {"PKCS7",        HCF_ALG_PADDING_TYPE,   HCF_ALG_PADDING_PKCS7},

    {"AES",          HCF_ALG_TYPE,           HCF_ALG_AES_DEFAULT},
    {"HMAC",         HCF_ALG_TYPE,           HCF_ALG_HMAC_DEFAULT},
};

static const HcfParaConfig *FindConfigByStr(const char *tag, uint32_t tagLen)
{
    if (tag == NULL) {
        LOGE("Tag is null when looking up config");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(PARAM_CONFIG) / sizeof(HcfParaConfig); ++i) {
        size_t cfgTagLen = strlen(PARAM_CONFIG[i].tag);
        if ((cfgTagLen == tagLen) && (strncmp(tag, PARAM_CONFIG[i].tag, tagLen) == 0)) {
            return &PARAM_CONFIG[i];
        }
    }
    LOGE("Config not found for given tag");
    return NULL;
}

HcfResult HcfParseAndSetParameter(const char *paramsStr, void *params, SetParameterFunc setFunc)
{
    if (paramsStr == NULL || setFunc == NULL) {
        LOGE("ParamsStr or setFunc is null");
        return HCF_INVALID_PARAMS;
    }
    const char *start = paramsStr;
    HcfResult ret = HCF_INVALID_PARAMS;
    const char *sep = NULL;
    do {
        sep = strchr(start, '|');
        uint32_t tagLen = (sep != NULL) ? (uint32_t)(sep - start) : (uint32_t)strlen(start);
        if (tagLen == 0) {
            LOGE("Empty tag in parameter string");
            break;
        }
        ret = (*setFunc)(FindConfigByStr(start, tagLen), params);
        if (ret != HCF_SUCCESS) {
            break;
        }
        if (sep != NULL) {
            start = sep + 1;
        }
    } while (sep != NULL);
    return ret;
}
