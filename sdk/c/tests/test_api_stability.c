// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#include "hdds.h"

#if defined(__cplusplus)
#define HDDS_STATIC_ASSERT static_assert
#else
#define HDDS_STATIC_ASSERT _Static_assert
#endif

HDDS_STATIC_ASSERT(HDDS_LOG_OFF == 0,
                   "HDDS_LOG_OFF value is part of the C API");
HDDS_STATIC_ASSERT(HDDS_LOG_ERROR == 1,
                   "HDDS_LOG_ERROR value is part of the C API");
HDDS_STATIC_ASSERT(HDDS_LOG_WARN == 2,
                   "HDDS_LOG_WARN value is part of the C API");
HDDS_STATIC_ASSERT(HDDS_LOG_INFO == 3,
                   "HDDS_LOG_INFO value is part of the C API");
HDDS_STATIC_ASSERT(HDDS_LOG_DEBUG == 4,
                   "HDDS_LOG_DEBUG value is part of the C API");
HDDS_STATIC_ASSERT(HDDS_LOG_TRACE == 5,
                   "HDDS_LOG_TRACE value is part of the C API");

HDDS_STATIC_ASSERT(HDDS_OK == 0, "HDDS_OK value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_INVALID_ARGUMENT == 1,
                   "HDDS_INVALID_ARGUMENT value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_NOT_FOUND == 2,
                   "HDDS_NOT_FOUND value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_OPERATION_FAILED == 3,
                   "HDDS_OPERATION_FAILED value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_OUT_OF_MEMORY == 4,
                   "HDDS_OUT_OF_MEMORY value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_CONFIG_ERROR == 10,
                   "HDDS_CONFIG_ERROR value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_INVALID_DOMAIN_ID == 11,
                   "HDDS_INVALID_DOMAIN_ID value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_INVALID_PARTICIPANT_ID == 12,
                   "HDDS_INVALID_PARTICIPANT_ID value is part of the C ABI");
HDDS_STATIC_ASSERT(
    HDDS_NO_AVAILABLE_PARTICIPANT_ID == 13,
    "HDDS_NO_AVAILABLE_PARTICIPANT_ID value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_INVALID_STATE == 14,
                   "HDDS_INVALID_STATE value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_IO_ERROR == 20,
                   "HDDS_IO_ERROR value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_TRANSPORT_ERROR == 21,
                   "HDDS_TRANSPORT_ERROR value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_REGISTRATION_FAILED == 22,
                   "HDDS_REGISTRATION_FAILED value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_WOULD_BLOCK == 23,
                   "HDDS_WOULD_BLOCK value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_TIMEOUT == 24,
                   "HDDS_TIMEOUT value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_TYPE_MISMATCH == 30,
                   "HDDS_TYPE_MISMATCH value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_SERIALIZATION_ERROR == 31,
                   "HDDS_SERIALIZATION_ERROR value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_BUFFER_TOO_SMALL == 32,
                   "HDDS_BUFFER_TOO_SMALL value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_ENDIAN_MISMATCH == 33,
                   "HDDS_ENDIAN_MISMATCH value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_QOS_INCOMPATIBLE == 40,
                   "HDDS_QOS_INCOMPATIBLE value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_UNSUPPORTED == 41,
                   "HDDS_UNSUPPORTED value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_PERMISSION_DENIED == 50,
                   "HDDS_PERMISSION_DENIED value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_AUTHENTICATION_FAILED == 51,
                   "HDDS_AUTHENTICATION_FAILED value is part of the C ABI");

HDDS_STATIC_ASSERT(HDDS_DSCP_BEST_EFFORT == 0,
                   "HDDS_DSCP_BEST_EFFORT value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_DSCP_AF11 == 10,
                   "HDDS_DSCP_AF11 value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_DSCP_AF21 == 18,
                   "HDDS_DSCP_AF21 value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_DSCP_AF31 == 26,
                   "HDDS_DSCP_AF31 value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_DSCP_AF41 == 34,
                   "HDDS_DSCP_AF41 value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_DSCP_EF == 46,
                   "HDDS_DSCP_EF value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_DSCP_CS6 == 48,
                   "HDDS_DSCP_CS6 value is part of the C ABI");
HDDS_STATIC_ASSERT(HDDS_DSCP_CS7 == 56,
                   "HDDS_DSCP_CS7 value is part of the C ABI");
HDDS_STATIC_ASSERT(sizeof(struct HddsDscpConfig) == 3,
                   "HddsDscpConfig layout is part of the C ABI");

/* The values hddsgen writes into the generated C and C++ code (C
 * <NAME>_EXTENSIBILITY, C++ T::hdds_extensibility): a changed number would
 * label every sample of a generated type with another extensibility's
 * encapsulation identifier. */
HDDS_STATIC_ASSERT(HDDS_EXTENSIBILITY_FINAL == 0,
                   "HDDS_EXTENSIBILITY_FINAL value is part of the C API");
HDDS_STATIC_ASSERT(HDDS_EXTENSIBILITY_APPENDABLE == 1,
                   "HDDS_EXTENSIBILITY_APPENDABLE value is part of the C API");
HDDS_STATIC_ASSERT(HDDS_EXTENSIBILITY_MUTABLE == 2,
                   "HDDS_EXTENSIBILITY_MUTABLE value is part of the C API");

int main(void) { return 0; }
