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
        template <typename T> struct prime;
        template <typename T> struct offsetBasis;

        template <> struct prime<std::uint32_t>
        {
            static constexpr std::uint32_t value = 16777619U;
        };

        template <> struct offsetBasis<std::uint32_t>
        {
            static constexpr std::uint32_t value = 2166136261U;
        };

        template <> struct prime<std::uint64_t>
        {
            static constexpr std::uint64_t value = 1099511628211ULL;
        };

        template <> struct offsetBasis<std::uint64_t>
        {
            static constexpr std::uint64_t value = 14695981039346656037ULL;
        };
    }

    template <typename Result, typename Iterator>
    constexpr Result hash(const Iterator i, const Iterator end,
                          const Result result = offsetBasis<Result>::value) noexcept
    {
        return (i != end) ? hash(i + 1, end, (result * prime<Result>::value) ^ static_cast<std::uint8_t>(*i)) : result;
    }

    template <typename Result, typename T>
    constexpr Result hash(const T& v) noexcept
    {
        return hash<Result>(std::begin(v), std::end(v));
    }
}

#endif // FNV_HPP
