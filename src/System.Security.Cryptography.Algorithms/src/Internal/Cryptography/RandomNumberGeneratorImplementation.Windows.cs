// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Diagnostics.Private;

namespace System.Security.Cryptography
{
    partial class RandomNumberGeneratorImplementation
    {
        private static unsafe void GetBytes(ref byte pbBuffer, int count)
        {
            Debug.Assert(count > 0);

            fixed (byte* buffer = &pbBuffer)
            {
                Interop.BCrypt.NTSTATUS status = Interop.BCrypt.BCryptGenRandom(IntPtr.Zero, buffer, count, Interop.BCrypt.BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                if (status != Interop.BCrypt.NTSTATUS.STATUS_SUCCESS)
                    throw Interop.BCrypt.CreateCryptographicException(status);
            }
        }
    }
}
