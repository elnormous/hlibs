//
// Header-only libs
//

#ifndef SHA256_HPP
#define SHA256_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace sha256
{
    constexpr uint32_t rotateRight(const uint32_t value,
                                   const uint32_t bits) noexcept
    {
        return (value >> bits) | ((value & 0xFFFFFFFF) << (32 - bits));
    }

    constexpr uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept
    {
        return (x & y) ^ (~x & z);
    }

    constexpr uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    constexpr uint32_t ep0(uint32_t x) noexcept
    {
        return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
    }

    constexpr uint32_t ep1(uint32_t x) noexcept
    {
        return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
    }

    constexpr uint32_t sig0(uint32_t x) noexcept
    {
        return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
    }

    constexpr uint32_t sig1(uint32_t x) noexcept
    {
        return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
    }

    static const uint32_t k[64] = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    };

    inline void transform(const uint8_t block[64], uint32_t state[8]) noexcept
    {
        uint32_t i, j, m[64];

        for (i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (static_cast<uint32_t>(block[j]) << 24) |
                (static_cast<uint32_t>(block[j + 1]) << 16) |
                (static_cast<uint32_t>(block[j + 2]) << 8) |
                static_cast<uint32_t>(block[j + 3]);
        for ( ; i < 64; ++i)
            m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        for (i = 0; i < 64; ++i)
        {
            uint32_t t1 = h + ep1(e) + ch(e, f, g) + k[i] + m[i];
            uint32_t t2 = ep0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    template <class Iterator>
    inline std::array<uint8_t, 32> hash(const Iterator begin,
                                        const Iterator end) noexcept
    {
        uint8_t data[64];
        uint32_t datalen = 0;
        uint32_t state[8] = {
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19
        };

        for (auto i = begin; i != end; ++i)
        {
            data[datalen] = *i;
            datalen++;
            if (datalen == 64)
            {
                transform(data, state);
                datalen = 0;
            }
        }

        // Pad data left in the buffer
        uint32_t n = datalen;
        if (datalen < 56)
        {
            data[n++] = 0x80;
            while (n < 56)
                data[n++] = 0x00;
        }
        else
        {
            data[n++] = 0x80;
            while (n < 64)
                data[n++] = 0x00;
            transform(data, state);
            std::fill(std::begin(data), std::end(data), 0);
        }

        // append the size in bits
        const uint64_t totalBits = static_cast<uint64_t>(abs(std::distance(begin, end))) * 8;
        data[63] = static_cast<uint8_t>(totalBits);
        data[62] = static_cast<uint8_t>(totalBits >> 8);
        data[61] = static_cast<uint8_t>(totalBits >> 16);
        data[60] = static_cast<uint8_t>(totalBits >> 24);
        data[59] = static_cast<uint8_t>(totalBits >> 32);
        data[58] = static_cast<uint8_t>(totalBits >> 40);
        data[57] = static_cast<uint8_t>(totalBits >> 48);
        data[56] = static_cast<uint8_t>(totalBits >> 56);
        transform(data, state);

        std::array<uint8_t, 32> result;
        // reverse all the bytes to big endian
        for (uint32_t i = 0; i < 4; ++i)
        {
            result[i + 0] = static_cast<uint8_t>(state[0] >> (24 - i * 8));
            result[i + 4] = static_cast<uint8_t>(state[1] >> (24 - i * 8));
            result[i + 8] = static_cast<uint8_t>(state[2] >> (24 - i * 8));
            result[i + 12] = static_cast<uint8_t>(state[3] >> (24 - i * 8));
            result[i + 16] = static_cast<uint8_t>(state[4] >> (24 - i * 8));
            result[i + 20] = static_cast<uint8_t>(state[5] >> (24 - i * 8));
            result[i + 24] = static_cast<uint8_t>(state[6] >> (24 - i * 8));
            result[i + 28] = static_cast<uint8_t>(state[7] >> (24 - i * 8));
        }

        return result;
    }

    template <class T>
    inline std::array<uint8_t, 32> hash(const T& v) noexcept
    {
        return hash(std::begin(v), std::end(v));
    }
}

#endif // SHA256_HPP
