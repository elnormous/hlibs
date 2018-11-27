//
// Header-only libs
//

#ifndef FNV_HPP
#define FNV_HPP

#include <cstdint>
#include <vector>

namespace fnv1
{
    static const uint32_t FNV_PRIME32 = 16777619u;
    static const uint32_t OFFSET_BASIS32 = 2166136261u;
    static const uint64_t FNV_PRIME64 = 1099511628211u;
    static const uint64_t OFFSET_BASIS64 = 14695981039346656037u;

    inline uint32_t hash32(const std::vector<uint8_t>& data, uint32_t result = OFFSET_BASIS32)
    {
        for (uint8_t b : data)
        {
            result *= FNV_PRIME32;
            result ^= b;
        }
        return result;
    }

    inline uint64_t hash64(const std::vector<uint8_t>& data, uint64_t result = OFFSET_BASIS64)
    {
        for (uint8_t b : data)
        {
            result *= FNV_PRIME64;
            result ^= b;
        }
        return result;
    }
}

#endif // FNV_HPP
