//
// Header-only libs
//

#ifndef FNV_HPP
#define FNV_HPP

#include <cstdint>
#include <vector>

namespace fnv1
{
    static constexpr uint32_t FNV_PRIME32 = 16777619u;
    static constexpr uint32_t OFFSET_BASIS32 = 2166136261u;
    static constexpr uint64_t FNV_PRIME64 = 1099511628211u;
    static constexpr uint64_t OFFSET_BASIS64 = 14695981039346656037u;

    template <class Iterator>
    constexpr uint32_t hash32(Iterator i, Iterator end, uint32_t result = OFFSET_BASIS32) noexcept
    {
        return (i != end) ? hash32(i + 1, end, (result * FNV_PRIME32) ^ *i) : result;
    }

    template <class Iterator>
    constexpr uint64_t hash64(Iterator i, Iterator end, uint64_t result = OFFSET_BASIS64) noexcept
    {
        return (i != end) ? hash64(i + 1, end, (result * FNV_PRIME64) ^ *i) : result;
    }
}

#endif // FNV_HPP
