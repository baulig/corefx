// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_seckey_ios.h"
#include "pal_utilities.h"

CFDataRef AppleCryptoNative_SecKeyExport(SecKeyRef pKey, CFErrorRef *pErrorOut)
{
    return SecKeyCopyExternalRepresentation(pKey, pErrorOut);
}

SecKeyRef AppleCryptoNative_SecKeyImportEphemeral(
    uint8_t* pbKeyBlob, int32_t cbKeyBlob, int32_t isPrivateKey, CFErrorRef *pErrorOut)
{
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionarySetValue(attrs, kSecAttrKeyClass, isPrivateKey ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic);
   //  CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, 0);

    CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, pbKeyBlob, cbKeyBlob, kCFAllocatorNull);
    SecKeyRef key = SecKeyCreateWithData(data, attrs, pErrorOut);
    CFRelease(data);
    CFRelease(attrs);
    return key;
}

