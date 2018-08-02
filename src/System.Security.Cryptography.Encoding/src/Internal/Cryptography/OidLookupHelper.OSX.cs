// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static class OidLookupHelper
    {
        internal static bool IsValidHashAlgorithm(string name)
        {
            return ToFriendlyName(name) != null;
        }

        private static string ToFriendlyName(string oid)
        {
            string mappedName;
            if (OidLookupTable.OidToFriendlyName.TryGetValue(oid, out mappedName) ||
                OidLookupTable.CompatOids.TryGetValue(oid, out mappedName) ||
                OidLookupTable.UnixExtraFriendlyNameToOid.TryGetValue(oid, out mappedName))
            {
                return mappedName;
            }

            return null;
        }
    }
}
