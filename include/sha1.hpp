//
// Header-only libs
//

#ifndef SHA1_HPP
#define SHA1_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace sha1
{
    constexpr uint32_t rotateLeft(const uint32_t value,
                                  const uint32_t bits) noexcept
    {
        return (value << bits) | ((value & 0xFFFFFFFF) >> (32 - bits));
    }

    static constexpr uint32_t DIGEST_INTS = 5; // number of 32bit integers per SHA1 digest
    static constexpr uint32_t BLOCK_INTS = 16; // number of 32bit integers per SHA1 block
    static constexpr uint32_t BLOCK_BYTES = BLOCK_INTS * 4;

    inline void transform(const uint32_t block[DIGEST_INTS],
                          uint32_t state[DIGEST_INTS]) noexcept
    {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = block[i];

        for (int i = 16; i < 80; ++i)
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

    template <class Iterator>
    inline std::array<uint8_t, DIGEST_INTS * 4> hash(const Iterator begin,
                                                     const Iterator end)
    {
        uint32_t state[DIGEST_INTS] = {
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        };

        std::vector<uint8_t> buffer;
        uint32_t block[BLOCK_INTS];
        Iterator i;
        for (i = begin; std::distance(i, end) >= BLOCK_BYTES; i += BLOCK_BYTES)
        {
            buffer.assign(i, i + BLOCK_BYTES);

            for (uint32_t n = 0; n < BLOCK_INTS; n++)
                block[n] = static_cast<uint32_t>(buffer[4 * n + 3] |
                                                 buffer[4 * n + 2] << 8 |
                                                 buffer[4 * n + 1] << 16 |
                                                 buffer[4 * n + 0] << 24);

            transform(block, state);
        }

        // pad data left in the buffer
        buffer.assign(i, end);
        buffer.push_back(0x80);
        const auto origSize = buffer.size();
        while (buffer.size() < BLOCK_BYTES)
            buffer.push_back(0x00);

        for (uint32_t n = 0; n < BLOCK_INTS; n++)
            block[n] = static_cast<uint32_t>(buffer[4 * n + 3]) |
                static_cast<uint32_t>(buffer[4 * n + 2]) << 8 |
                static_cast<uint32_t>(buffer[4 * n + 1]) << 16 |
                static_cast<uint32_t>(buffer[4 * n + 0]) << 24;

        if (origSize > BLOCK_BYTES - 8)
        {
            transform(block, state);
            std::fill(block, block + BLOCK_INTS - 2, 0);
        }

        // append the size in bits
        const uint64_t totalBits = static_cast<uint64_t>(abs(std::distance(begin, end))) * 8;
        block[BLOCK_INTS - 1] = static_cast<uint32_t>(totalBits);
        block[BLOCK_INTS - 2] = static_cast<uint32_t>(totalBits >> 32);
        transform(block, state);

        std::array<uint8_t, DIGEST_INTS * 4> result;
        // reverse all the bytes to big endian
        for (uint32_t n = 0; n < DIGEST_INTS; n++)
        {
            result[n * 4 + 0] = static_cast<uint8_t>(state[n] >> 24);
            result[n * 4 + 1] = static_cast<uint8_t>(state[n] >> 16);
            result[n * 4 + 2] = static_cast<uint8_t>(state[n] >> 8);
            result[n * 4 + 3] = static_cast<uint8_t>(state[n]);
        }

        return result;
    }

    template <class T>
    inline std::array<uint8_t, DIGEST_INTS * 4> hash(const T& v)
    {
        return hash(std::begin(v), std::end(v));
    }
}

#endif // SHA1_HPP
