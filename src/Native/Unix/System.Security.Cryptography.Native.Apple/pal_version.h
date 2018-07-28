// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

/* See Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator11.4.sdk/usr/include/AvailabilityMacros.h */

#define REQUIRE_MAC_SDK_VERSION(x) (TARGET_OS_MAC && MAC_OS_X_VERSION_MIN_REQUIRED >= (MAC_OS_X_VERSION_ ## x))
#define REQUIRE_IOS_SDK_VERSION(x) (TARGET_OS_IPHONE && IPHONE_OS_VERSION_MIN_REQUIRED >= (__IPHONE_ ## x))
