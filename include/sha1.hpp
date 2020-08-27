//
// Header-only libs
//

#ifndef SHA1_HPP
#define SHA1_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>

namespace sha1
{
    inline namespace detail
    {
        constexpr std::size_t digestIntCount = 5; // number of 32bit integers per SHA1 digest
        constexpr std::size_t digestByteCount = digestIntCount * 4;
        constexpr std::size_t blockIntCount = 16; // number of 32bit integers per SHA1 block
        constexpr std::size_t blockByteCount = blockIntCount * 4;
        using Block = std::uint8_t[blockByteCount];
        using State = std::uint32_t[digestIntCount];

        constexpr std::uint32_t rotateLeft(const std::uint32_t value,
                                           const std::uint32_t bits) noexcept
        {
            return (value << bits) | ((value & 0xFFFFFFFFU) >> (32 - bits));
        }

        inline void transform(const Block& block,
                              State& state) noexcept
        {
            std::uint32_t w[80];
            for (std::uint32_t i = 0; i < 16; ++i)
                w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                    (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                    (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                    static_cast<std::uint32_t>(block[i * 4 + 3]);

            for (std::uint32_t i = 16; i < 80; ++i)
                w[i] = rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

            std::uint32_t a = state[0];
            std::uint32_t b = state[1];
            std::uint32_t c = state[2];
            std::uint32_t d = state[3];
            std::uint32_t e = state[4];

            std::uint32_t f = 0;
            std::uint32_t k = 0;

            for (std::uint32_t i = 0; i < 80; ++i)
            {
                if (i < 20)
                {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999U;
                }
                else if (i < 40)
                {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1U;
                }
                else if (i < 60)
                {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDCU;
                }
                else if (i < 80)
                {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6U;
                }

                const std::uint32_t temp = rotateLeft(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = rotateLeft(b, 30);
                b = a;
                a = temp;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
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
            0x10325476U,
            0xC3D2E1F0U
        };

        std::vector<std::uint8_t> buffer;
        Block block;
        std::uint32_t dataSize = 0;
        for (auto i = begin; i != end; ++i)
        {
            block[dataSize % blockByteCount] = *i;
            if (++dataSize % blockByteCount == 0)
                transform(block, state);
        }

        // pad data left in the buffer
        std::uint32_t n = dataSize % blockByteCount;
        if (n < blockByteCount - 8)
        {
            block[n++] = 0x80;
            while (n < blockByteCount - 8) block[n++] = 0x00;
        }
        else
        {
            block[n++] = 0x80;
            while (n < blockByteCount) block[n++] = 0x00;
            transform(block, state);
            std::fill(block, block + blockByteCount - 8, 0);
        }

        // append the size in bits
        const std::uint64_t totalBits = dataSize * 8;
        block[63] = static_cast<std::uint8_t>(totalBits);
        block[62] = static_cast<std::uint8_t>(totalBits >> 8);
        block[61] = static_cast<std::uint8_t>(totalBits >> 16);
        block[60] = static_cast<std::uint8_t>(totalBits >> 24);
        block[59] = static_cast<std::uint8_t>(totalBits >> 32);
        block[58] = static_cast<std::uint8_t>(totalBits >> 40);
        block[57] = static_cast<std::uint8_t>(totalBits >> 48);
        block[56] = static_cast<std::uint8_t>(totalBits >> 56);
        transform(block, state);

        std::array<std::uint8_t, digestByteCount> result;
        // reverse all the bytes to big endian
        for (std::uint32_t i = 0; i < digestIntCount; i++)
        {
            result[i * 4 + 0] = static_cast<std::uint8_t>(state[i] >> 24);
            result[i * 4 + 1] = static_cast<std::uint8_t>(state[i] >> 16);
            result[i * 4 + 2] = static_cast<std::uint8_t>(state[i] >> 8);
            result[i * 4 + 3] = static_cast<std::uint8_t>(state[i]);
        }

        return result;
    }

    template <class T>
    std::array<std::uint8_t, digestByteCount> hash(const T& v)
    {
        return hash(std::begin(v), std::end(v));
    }
}

#endif // SHA1_HPP
