#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// sedutil 1.20.0's Linux SCSI path put the raw Vendor ID in the
// zero-padded serial field and used its first 20 bytes for PBKDF2.
inline bool decodeLegacyScsiSalt(const uint8_t *inquiry, std::size_t length,
                                 uint8_t (&salt)[20])
{
    constexpr std::size_t standardLength = 36;
    constexpr std::size_t vendorOffset = 8;
    constexpr std::size_t vendorLength = 8;
    // Require a connected direct-access device and a complete standard header.
    if (length != standardLength || inquiry[0] != 0 ||
        inquiry[4] < standardLength - 5) {
        return false;
    }
    std::memcpy(salt, inquiry + vendorOffset, vendorLength);
    std::memset(salt + vendorLength, 0, sizeof(salt) - vendorLength);
    return true;
}
