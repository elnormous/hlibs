//
// Header-only libs
//

#ifndef FNV_HPP
#define FNV_HPP

#include <cstdint>

namespace fnv1
{
    template <typename T> T prime() noexcept;
    template <typename T> T offsetBasis() noexcept;

    template <>
    constexpr uint32_t prime() noexcept { return 16777619u; }

    template <>
    constexpr uint32_t offsetBasis() noexcept { return 2166136261u; }

    template <>
    constexpr uint64_t prime() noexcept { return 1099511628211u; }

    template <>
    constexpr uint64_t offsetBasis() noexcept { return 14695981039346656037u; }

    template <typename Result, typename Iterator>
    constexpr Result hash(Iterator i, Iterator end, Result result = offsetBasis<Result>()) noexcept
    {
        return (i != end) ? hash(i + 1, end, (result * prime<Result>()) ^ *i) : result;
    }
}

#endif // FNV_HPP
