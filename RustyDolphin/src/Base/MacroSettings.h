#pragma once

#define ENABLE_IN_RELEASE 0

#ifdef NDEBUG
#if ENABLE_IN_RELEASE
#define FEATURES_ENABLED 1
#else
#define FEATURES_ENABLED 0
#endif
#else
#define FEATURES_ENABLED 1
#endif

#if FEATURES_ENABLED
#define CAPTURE_LIVE
//#define CAPTURE_SAMPLES
//#define CAPTURE_V6
//#define CAPTURE_ICMPV6
#endif
