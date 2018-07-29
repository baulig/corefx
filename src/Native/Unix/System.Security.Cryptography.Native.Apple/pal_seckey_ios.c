// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_seckey_ios.h"
#include "pal_utilities.h"

CFDataRef AppleCryptoNative_SecKeyExport(SecKeyRef pKey, CFErrorRef *pErrorOut)
{
    return SecKeyCopyExternalRepresentation(pKey, pErrorOut);
}
