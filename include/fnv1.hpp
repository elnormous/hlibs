//
// Header-only libs
//

#ifndef FNV_HPP
#define FNV_HPP

#include <cstdint>

namespace fnv1
{
    namespace
    {
        template <typename T> constexpr T prime() noexcept;
        template <typename T> constexpr T offsetBasis() noexcept;

        template <>
        constexpr uint32_t prime<uint32_t>() noexcept { return 16777619U; }

        template <>
        constexpr uint32_t offsetBasis<uint32_t>() noexcept { return 2166136261U; }

        template <>
        constexpr uint64_t prime<uint64_t>() noexcept { return 1099511628211U; }

        template <>
        constexpr uint64_t offsetBasis<uint64_t>() noexcept { return 14695981039346656037U; }
    }

    template <typename Result, typename Iterator>
    constexpr Result hash(const Iterator i, const Iterator end,
                          const Result result = offsetBasis<Result>()) noexcept
    {
        return (i != end) ? hash(i + 1, end, (result * prime<Result>()) ^ *i) : result;
    }

    template <typename Result, typename T>
    constexpr Result hash(const T& v) noexcept
    {
        return hash<Result>(std::begin(v), std::end(v));
    }
}

#endif // FNV_HPP
