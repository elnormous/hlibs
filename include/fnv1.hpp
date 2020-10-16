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
        template <typename T> struct Constants;

        template <> struct Constants<std::uint32_t>
        {
            static constexpr std::uint32_t prime = 16777619U;
            static constexpr std::uint32_t offsetBasis = 2166136261U;
        };

        template <> struct Constants<std::uint64_t>
        {
            static constexpr std::uint64_t prime = 1099511628211ULL;
            static constexpr std::uint64_t offsetBasis = 14695981039346656037ULL;
        };
    }

    template <typename Result, typename Iterator>
    constexpr Result hash(const Iterator i, const Iterator end,
                          const Result result = Constants<Result>::offsetBasis) noexcept
    {
        return (i != end) ? hash(i + 1, end, (result * Constants<Result>::prime) ^ static_cast<std::uint8_t>(*i)) : result;
    }

    template <typename Result, typename T>
    constexpr Result hash(const T& v) noexcept
    {
        return hash<Result>(std::begin(v), std::end(v));
    }
}

#endif // FNV_HPP
