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

#ifndef JSI_API_H
#define JSI_API_H

#include "jsi/jsi.h"
#include "jsi/jsi_types.h"
#include "sym_key.h"
#include "cipher.h"
#include "key_pair.h"

namespace OHOS {
namespace ACELite {
class CryptoFrameworkLiteModule final : public MemoryHeap {
public:
    CryptoFrameworkLiteModule() {}
    ~CryptoFrameworkLiteModule() {};

    static JSIValue CreateMd(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CreateMac(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CreateRandom(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CreateSymKeyGenerator(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CreateCipher(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CreateAsyKeyGenerator(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CreateKeyAgreement(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static void OnDestroy(void);

private:
    // Md
    static JSIValue Update(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue UpdateSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue Digest(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue DigestSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue Squeeze(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue SqueezeSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GetMdLength(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);

    // Mac
    static JSIValue MacInit(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue MacInitSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue MacUpdate(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue MacUpdateSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue MacDoFinal(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue MacDoFinalSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GetMacLength(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);

    // Random
    static JSIValue GenerateRandom(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GenerateRandomSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue SetSeed(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue EnableHardwareEntropy(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);

    // SymKey
    static JSIValue BuildSymKeyObject(HcfSymKey *keyObj);
    static JSIValue GetSymKeyDataSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GetSymKeySize(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue ClearSymKeyMem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);

    // SymKeyGenerator
    static JSIValue GenerateSymKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GenerateSymKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue ConvertSymKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue ConvertSymKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);

    // Cipher
    static JSIValue CipherInit(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CipherInitSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CipherUpdate(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CipherUpdateSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CipherDoFinal(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue CipherDoFinalSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue SetCipherSpec(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GetCipherSpec(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    // AsyKey
    static JSIValue ConstructKeyPairJsObject(HcfKeyPair *keyPair);
    static JSIValue ConstructPubKeyJsObject(HcfPubKey *pubKey);
    static JSIValue ConstructPriKeyJsObject(HcfPriKey *priKey);
    static JSIValue GenerateKeyPair(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GenerateKeyPairSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue ConvertKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue ConvertKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue ConvertPemKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue ConvertPemKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PubKeyGetEncodedDer(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PubKeyGetEncoded(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PubKeyGetEncodedPem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PubKeyGetAsyKeySpec(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PubKeyGetKeySize(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PubKeyGetKeyData(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PubKeyGetKeyDataSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyGetEncoded(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyGetEncodedDer(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyGetEncodedPem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyGetAsyKeySpec(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyGetKeySize(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyGetPubKey(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyGetPubKeySync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyGetKeyData(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyGetKeyDataSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue PriKeyClearMem(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);

    // KeyAgreement
    static JSIValue GenerateSecret(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);
    static JSIValue GenerateSecretSync(const JSIValue thisVal, const JSIValue *args, uint8_t argsNum);

    static void MdDestroy(void);
    static void MacDestroy(void);
    static void RandomDestroy(void);
    static void SymKeyDestroy(void);
    static void CipherDestroy(void);
    static void AsyKeyGeneratorDestroy(void);
    static void AsyKeyPairDestroy(void);
    static void KeyAgreementDestroy(void);
};

void InitCryptoFrameworkModule(JSIValue exports);

}  // namespace ACELite
}  // namespace OHOS
#endif // JSI_API_H
