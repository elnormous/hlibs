//
// Header-only libs
//

#ifndef MD5_HPP
#define MD5_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>

namespace md5
{
    inline namespace detail
    {
        constexpr std::array<std::uint8_t, 16> s = {
            7, 12, 17, 22,
            5, 9, 14, 20,
            4, 11, 16, 23,
            6, 10, 15, 21
        };

        constexpr std::array<std::uint32_t, 64> k = {
            0xD76AA478U, 0xE8C7B756U, 0x242070DBU, 0xC1BDCEEEU,
            0xF57C0FAFU, 0x4787C62AU, 0xA8304613U, 0xFD469501U,
            0x698098D8U, 0x8B44F7AFU, 0xFFFF5BB1U, 0x895CD7BEU,
            0x6B901122U, 0xFD987193U, 0xA679438EU, 0x49B40821U,
            0xF61E2562U, 0xC040B340U, 0x265E5A51U, 0xE9B6C7AAU,
            0xD62F105DU, 0x02441453U, 0xD8A1E681U, 0xE7D3FBC8U,
            0x21E1CDE6U, 0xC33707D6U, 0xF4D50D87U, 0x455A14EDU,
            0xA9E3E905U, 0xFCEFA3F8U, 0x676F02D9U, 0x8D2A4C8AU,
            0xFFFA3942U, 0x8771F681U, 0x6D9D6122U, 0xFDE5380CU,
            0xA4BEEA44U, 0x4BDECFA9U, 0xF6BB4B60U, 0xBEBFBC70U,
            0x289B7EC6U, 0xEAA127FAU, 0xD4EF3085U, 0x04881D05U,
            0xD9D4D039U, 0xE6DB99E5U, 0x1FA27CF8U, 0xC4AC5665U,
            0xF4292244U, 0x432AFF97U, 0xAB9423A7U, 0xFC93A039U,
            0x655B59C3U, 0x8F0CCC92U, 0xFFEFF47DU, 0x85845DD1U,
            0x6FA87E4FU, 0xFE2CE6E0U, 0xA3014314U, 0x4E0811A1U,
            0xF7537E82U, 0xBD3AF235U, 0x2AD7D2BBU, 0xEB86D391U
        };

        constexpr std::uint32_t rotateLeft(const std::uint32_t value,
                                           const std::uint32_t bits) noexcept
        {
            return (value << bits) | ((value & 0xFFFFFFFFU) >> (32 - bits));
        }

        constexpr std::size_t digestIntCount = 4; // number of 32bit integers per MD5 digest
        constexpr std::size_t digestByteCount = digestIntCount * 4;
        constexpr std::size_t blockIntCount = 16; // number of 32bit integers per MD5 block
        constexpr std::size_t blockByteCount = blockIntCount * 4;
        using Block = std::array<std::uint8_t, blockByteCount>;
        using State = std::array<std::uint32_t, digestIntCount>;

        inline void transform(const Block& block,
                              State& state) noexcept
        {
            std::array<std::uint32_t, 16> w;

            for (std::uint32_t i = 0; i < 16; ++i)
                w[i] = static_cast<std::uint32_t>(block[i * 4]) |
                    (static_cast<std::uint32_t>(block[i * 4 + 1]) << 8) |
                    (static_cast<std::uint32_t>(block[i * 4 + 2]) << 16) |
                    (static_cast<std::uint32_t>(block[i * 4 + 3]) << 24);

            std::uint32_t a = state[0];
            std::uint32_t b = state[1];
            std::uint32_t c = state[2];
            std::uint32_t d = state[3];

            for (std::uint32_t i = 0; i < 64; ++i)
            {
                std::uint32_t f = 0;
                std::uint32_t g = 0;

                if (i < 16)
                {
                    f = (b & c) | (~b & d);
                    g = i;
                }
                else if (i < 32)
                {
                    f = (d & b) | (~d & c);
                    g = (5 * i + 1) % 16;
                }
                else if (i < 48)
                {
                    f = b ^ c ^ d;
                    g = (3 * i + 5) % 16;
                }
                else if (i < 64)
                {
                    f = c ^ (b | ~d);
                    g = (7 * i) % 16;
                }

                f = f + a + k[i] + w[g];
                a = d;
                d = c;
                c = b;
                b = b + rotateLeft(f, s[i / 16 * 4 + i % 4]);
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
        }
    }

    template <class Iterator>
    std::array<std::uint8_t, digestByteCount> hash(const Iterator begin,
                                                   const Iterator end) noexcept
    {
        State state = {
            0x67452301U,
            0xEFCDAB89U,
            0x98BADCFEU,
            0x10325476U
        };

        Block block;
        std::uint32_t dataSize = 0;
        for (auto i = begin; i != end; ++i)
        {
            block[dataSize % blockByteCount] = static_cast<std::uint8_t>(*i);
            if (++dataSize % blockByteCount == 0)
                transform(block, state);
        }

        // pad data left in the buffer
        const std::uint32_t n = dataSize % blockByteCount;
        block[n] = 0x80;
        if (n < blockByteCount - 8)
        {
            std::fill(block.begin() + n + 1, block.end() - 8, 0);
        }
        else
        {
            std::fill(block.begin() + n + 1, block.end(), 0);
            transform(block, state);
            std::fill(block.begin(), block.end() - 8, 0);
        }

        // append the size in bits
        const std::uint64_t totalBits = dataSize * 8;
        block[56] = static_cast<std::uint8_t>(totalBits);
        block[57] = static_cast<std::uint8_t>(totalBits >> 8);
        block[58] = static_cast<std::uint8_t>(totalBits >> 16);
        block[59] = static_cast<std::uint8_t>(totalBits >> 24);
        block[60] = static_cast<std::uint8_t>(totalBits >> 32);
        block[61] = static_cast<std::uint8_t>(totalBits >> 40);
        block[62] = static_cast<std::uint8_t>(totalBits >> 48);
        block[63] = static_cast<std::uint8_t>(totalBits >> 56);
        transform(block, state);

        std::array<std::uint8_t, digestByteCount> result;
        for (std::uint32_t i = 0; i < digestIntCount; ++i)
        {
            result[i * 4 + 0] = static_cast<std::uint8_t>(state[i]);
            result[i * 4 + 1] = static_cast<std::uint8_t>(state[i] >> 8);
            result[i * 4 + 2] = static_cast<std::uint8_t>(state[i] >> 16);
            result[i * 4 + 3] = static_cast<std::uint8_t>(state[i] >> 24);
        }

        return result;
    }

    template <class T>
    std::array<std::uint8_t, digestByteCount> hash(const T& v) noexcept
    {
        return hash(std::begin(v), std::end(v));
    }
}

#endif // MD5_HPP
