//
// Header-only libs
//

#ifndef FNV_HPP
#define FNV_HPP

#include <cstdint>

namespace fnv1
{
    inline namespace detail
    {
        template <typename T> constexpr T getPrime() noexcept;
        template <typename T> constexpr T getOffsetBasis() noexcept;

        template <>
        constexpr uint32_t getPrime<uint32_t>() noexcept
        {
            return 16777619U;
        }

        template <>
        constexpr uint32_t getOffsetBasis<uint32_t>() noexcept
        {
            return 2166136261U;
        }

        template <>
        constexpr uint64_t getPrime<uint64_t>() noexcept
        {
            return 1099511628211U;
        }

        template <>
        constexpr uint64_t getOffsetBasis<uint64_t>() noexcept
        {
            return 14695981039346656037U;
        }
    }

    template <typename Result, typename Iterator>
    constexpr Result hash(const Iterator i, const Iterator end,
                          const Result result = getOffsetBasis<Result>()) noexcept
    {
        return (i != end) ? hash(i + 1, end, (result * getPrime<Result>()) ^ *i) : result;
    }

    template <typename Result, typename T>
    constexpr Result hash(const T& v) noexcept
    {
        return hash<Result>(std::begin(v), std::end(v));
    }
}

#endif // FNV_HPP
