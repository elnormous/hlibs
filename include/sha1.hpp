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
    namespace
    {
        constexpr uint32_t rotateLeft(const uint32_t value,
                                      const uint32_t bits) noexcept
        {
            return (value << bits) | ((value & 0xFFFFFFFF) >> (32 - bits));
        }

        constexpr uint32_t digestInts = 5; // number of 32bit integers per SHA1 digest
        constexpr uint32_t blockInts = 16; // number of 32bit integers per SHA1 block
        constexpr uint32_t blockBytes = blockInts * 4;

        inline void transform(const uint8_t block[blockBytes],
                              uint32_t state[digestInts]) noexcept
        {
            uint32_t w[80];
            for (uint32_t i = 0; i < 16; ++i)
                w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                    (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                    (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                    static_cast<uint32_t>(block[i * 4 + 3]);

            for (uint32_t i = 16; i < 80; ++i)
                w[i] = rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

            uint32_t a = state[0];
            uint32_t b = state[1];
            uint32_t c = state[2];
            uint32_t d = state[3];
            uint32_t e = state[4];

            uint32_t f = 0;
            uint32_t k = 0;

            for (uint32_t i = 0; i < 80; ++i)
            {
                if (i < 20)
                {
                    f = (b & c) | (~b & d);
                    k = 0x5A827999;
                }
                else if (i < 40)
                {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if (i < 60)
                {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else if (i < 80)
                {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                const uint32_t temp = rotateLeft(a, 5) + f + e + k + w[i];
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
    inline std::array<uint8_t, digestInts * 4> hash(const Iterator begin,
                                                    const Iterator end) noexcept
    {
        uint32_t state[digestInts] = {
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        };

        std::vector<uint8_t> buffer;
        uint8_t block[blockBytes];
        uint32_t dataSize = 0;
        for (auto i = begin; i != end; ++i)
        {
            block[dataSize] = *i;
            dataSize++;
            if (dataSize == blockBytes)
            {
                transform(block, state);
                dataSize = 0;
            }
        }

        // Pad data left in the buffer
        uint32_t n = dataSize;
        if (dataSize < blockBytes - 8)
        {
            block[n++] = 0x80;
            while (n < blockBytes - 8) block[n++] = 0x00;
        }
        else
        {
            block[n++] = 0x80;
            while (n < blockBytes) block[n++] = 0x00;
            transform(block, state);
            std::fill(block, block + blockBytes - 8, 0);
        }

        // append the size in bits
        const uint64_t totalBits = dataSize * 8;
        block[63] = static_cast<uint8_t>(totalBits);
        block[62] = static_cast<uint8_t>(totalBits >> 8);
        block[61] = static_cast<uint8_t>(totalBits >> 16);
        block[60] = static_cast<uint8_t>(totalBits >> 24);
        block[59] = static_cast<uint8_t>(totalBits >> 32);
        block[58] = static_cast<uint8_t>(totalBits >> 40);
        block[57] = static_cast<uint8_t>(totalBits >> 48);
        block[56] = static_cast<uint8_t>(totalBits >> 56);
        transform(block, state);

        std::array<uint8_t, digestInts * 4> result;
        // reverse all the bytes to big endian
        for (uint32_t i = 0; i < digestInts; i++)
        {
            result[i * 4 + 0] = static_cast<uint8_t>(state[i] >> 24);
            result[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            result[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            result[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }

        return result;
    }

    template <class T>
    inline std::array<uint8_t, digestInts * 4> hash(const T& v)
    {
        return hash(std::begin(v), std::end(v));
    }
}

#endif // SHA1_HPP
