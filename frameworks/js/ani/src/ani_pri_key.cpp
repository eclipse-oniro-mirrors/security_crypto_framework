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

#include "ani_pri_key.h"
#include "key.h"

namespace {
using namespace ANI::CryptoFramework;

OptKeySpec GetAsyKeySpecNumber(HcfPriKey *priKey, HcfAsyKeySpecItem item)
{
    int num = 0;
    HcfResult res = priKey->getAsyKeySpecInt(priKey, item, &num);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get asy key spec int fail.");
        return OptKeySpec::make_INT32(-1);
    }
    return OptKeySpec::make_INT32(num);
}

OptKeySpec GetAsyKeySpecString(HcfPriKey *priKey, HcfAsyKeySpecItem item)
{
    char *str = nullptr;
    HcfResult res = priKey->getAsyKeySpecString(priKey, item, &str);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get asy key spec string fail.");
        return OptKeySpec::make_STRING("");
    }
    string data = string(str);
    HcfFree(str);
    return OptKeySpec::make_STRING(data);
}

OptKeySpec GetAsyKeySpecBigInt(HcfPriKey *priKey, HcfAsyKeySpecItem item)
{
    HcfBigInteger bigint = {};
    HcfResult res = priKey->getAsyKeySpecBigInteger(priKey, item, &bigint);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "get asy key spec biginteger failed.");
        return OptKeySpec::make_BIGINT(array<uint8_t>{});
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(bigint, data);
    HcfBlobDataClearAndFree(reinterpret_cast<HcfBlob *>(&bigint));
    return OptKeySpec::make_BIGINT(data);
}

string GetEncodedPemInner(const HcfPriKey *self, HcfParamsSpec *params, string_view format)
{
    if (self == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return "";
    }
    char *encoded = nullptr;
    HcfResult res = self->getEncodedPem(self, params, format.c_str(), &encoded);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncodedPem fail.");
        return "";
    }
    string str = string(encoded);
    HcfFree(encoded);
    return str;
}
} // namespace

namespace ANI::CryptoFramework {
PriKeyImpl::PriKeyImpl() {}

PriKeyImpl::PriKeyImpl(HcfPriKey *priKey) : priKey_(priKey) {}

PriKeyImpl::~PriKeyImpl()
{
    HcfObjDestroy(this->priKey_);
    this->priKey_ = nullptr;
}

int64_t PriKeyImpl::GetPriKeyObj()
{
    return reinterpret_cast<int64_t>(this->priKey_);
}

void PriKeyImpl::ClearMem()
{
    if (this->priKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return;
    }
    this->priKey_->clearMem(this->priKey_);
}

OptKeySpec PriKeyImpl::GetAsyKeySpec(ThAsyKeySpecItem itemType)
{
    if (this->priKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return OptKeySpec::make_INT32(-1);
    }
    HcfAsyKeySpecItem item = static_cast<HcfAsyKeySpecItem>(itemType.get_value());
    int type = GetAsyKeySpecType(item);
    if (type == SPEC_ITEM_TYPE_NUM) {
        return GetAsyKeySpecNumber(this->priKey_, item);
    } else if (type == SPEC_ITEM_TYPE_STR) {
        return GetAsyKeySpecString(this->priKey_, item);
    } else if (type == SPEC_ITEM_TYPE_BIG_INT) {
        return GetAsyKeySpecBigInt(this->priKey_, item);
    } else {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "asy key spec item not support!");
        return OptKeySpec::make_INT32(-1);
    }
}

DataBlob PriKeyImpl::GetEncodedDer(string_view format)
{
    if (this->priKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->priKey_->getEncodedDer(this->priKey_, format.c_str(), &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncodedDer fail.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string PriKeyImpl::GetEncodedPem(string_view format)
{
    return GetEncodedPemInner(this->priKey_, nullptr, format);
}

string PriKeyImpl::GetEncodedPemEx(string_view format, KeyEncodingConfig const& config)
{
    HcfKeyEncodingParamsSpec spec = {};
    spec.password = const_cast<char *>(config.password.c_str());
    spec.cipher = const_cast<char *>(config.cipherName.c_str());
    return GetEncodedPemInner(this->priKey_, reinterpret_cast<HcfParamsSpec *>(&spec), format);
}

int64_t PriKeyImpl::GetKeyObj()
{
    return reinterpret_cast<int64_t>(&this->priKey_->base);
}

DataBlob PriKeyImpl::GetEncoded()
{
    if (this->priKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->priKey_->base.getEncoded(&this->priKey_->base, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncoded failed.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string PriKeyImpl::GetFormat()
{
    if (this->priKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return "";
    }
    const char *format = this->priKey_->base.getFormat(&this->priKey_->base);
    return (format == nullptr) ? "" : string(format);
}

string PriKeyImpl::GetAlgName()
{
    if (this->priKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return "";
    }
    const char *algName = this->priKey_->base.getAlgorithm(&this->priKey_->base);
    return (algName == nullptr) ? "" : string(algName);
}
} // namespace ANI::CryptoFramework
