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

#include "ani_pub_key.h"

namespace ANI::CryptoFramework {
PubKeyImpl::PubKeyImpl() {}

PubKeyImpl::PubKeyImpl(HcfPubKey *pubKey) : pubKey_(pubKey) {}

PubKeyImpl::~PubKeyImpl()
{
    HcfObjDestroy(this->pubKey_);
    this->pubKey_ = nullptr;
}

int64_t PubKeyImpl::GetPubKeyObj()
{
    return reinterpret_cast<int64_t>(this->pubKey_);
}

OptKeySpec PubKeyImpl::GetAsyKeySpec(AsyKeySpecEnum itemType)
{
    TH_THROW(std::runtime_error, "GetAsyKeySpec not implemented");
}

DataBlob PubKeyImpl::GetEncodedDer(string_view format)
{
    TH_THROW(std::runtime_error, "GetEncodedDer not implemented");
}

string PubKeyImpl::GetEncodedPem(string_view format)
{
    TH_THROW(std::runtime_error, "GetEncodedPem not implemented");
}

int64_t PubKeyImpl::GetKeyObj()
{
    return reinterpret_cast<int64_t>(&this->pubKey_->base);
}

DataBlob PubKeyImpl::GetEncoded()
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "pubKey obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->pubKey_->base.getEncoded(&this->pubKey_->base, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncoded failed.");
        return {};
    }
    array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string PubKeyImpl::GetFormat()
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "pubKey obj is nullptr!");
        return "";
    }
    const char *format = this->pubKey_->base.getFormat(&this->pubKey_->base);
    return (format == nullptr) ? "" : string(format);
}

string PubKeyImpl::GetAlgName()
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "pubKey obj is nullptr!");
        return "";
    }
    const char *algName = this->pubKey_->base.getAlgorithm(&this->pubKey_->base);
    return (algName == nullptr) ? "" : string(algName);
}
} // namespace ANI::CryptoFramework
