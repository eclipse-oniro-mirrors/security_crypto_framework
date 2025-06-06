/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef HCF_CIPHER_SM2_ECDSA_SIGNATURE_OPENSSL_H
#define HCF_CIPHER_SM2_ECDSA_SIGNATURE_OPENSSL_H

#include "sm2_crypto_params.h"
#include "result.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfSm2SpecToDerData(Sm2EcSignatureDataSpec *spec, HcfBlob *output);
HcfResult HcfDerDataToSm2Spec(HcfBlob *input, Sm2EcSignatureDataSpec **returnSpec);

#ifdef __cplusplus
}
#endif
#endif