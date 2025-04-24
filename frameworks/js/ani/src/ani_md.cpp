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

#include "ani_md.h"

using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;
using namespace ANI::CryptoFramework;

namespace ANI::CryptoFramework {
MdImpl::MdImpl() {}

MdImpl::MdImpl(HcfMd *md) : md_(md) {}

MdImpl::~MdImpl()
{
    HcfObjDestroy(this->md_);
    this->md_ = nullptr;
}

void MdImpl::UpdateSync(DataBlob const& input)
{
    if (this->md_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "md obj is nullptr!");
        return;
    }
    HcfBlob inBlob = { .data = input.data.data(), .len = input.data.size() };
    HcfResult res = this->md_->update(this->md_, &inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "md doFinal failed!");
        return;
    }
}

DataBlob MdImpl::DigestSync()
{
    if (this->md_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "md obj is nullptr!");
        return { array<uint8_t>(nullptr, 0) };
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult res = this->md_->doFinal(this->md_, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac doFinal failed!");
        return { array<uint8_t>(nullptr, 0) };
    }
    array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

int32_t MdImpl::GetMdLength()
{
    if (this->md_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "md obj is nullptr!");
        return 0;
    }
    uint32_t length = this->md_->getMdLength(this->md_);
    return static_cast<int32_t>(length);
}

string MdImpl::GetAlgName()
{
    if (this->md_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "md obj is nullptr!");
        return "";
    }
    const char *algName = this->md_->getAlgoName(this->md_);
    return (algName == nullptr) ? "" : string(algName);
}

Md CreateMd(string_view algName)
{
    HcfMd *md = nullptr;
    HcfResult res = HcfMdCreate(algName.c_str(), &md);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create C md obj failed.");
        return make_holder<MdImpl, Md>();
    }
    return make_holder<MdImpl, Md>(md);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateMd(CreateMd);
// NOLINTEND
