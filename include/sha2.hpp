//
// Header-only libs
//

#ifndef SHA256_HPP
#define SHA256_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>

namespace sha256
{
    inline namespace detail
    {
        constexpr uint32_t k[64] = {
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

        constexpr size_t digestIntCount = 8; // number of 32bit integers per SHA256 digest
        constexpr size_t digestByteCount = digestIntCount * 4;
        constexpr size_t blockIntCount = 16; // number of 32bit integers per SHA256 block
        constexpr size_t blockByteCount = blockIntCount * 4;
        using Block = uint8_t[blockByteCount];
        using State = uint32_t[digestIntCount];

        constexpr uint32_t rotateRight(const uint32_t value,
                                       const uint32_t bits) noexcept
        {
            return (value >> bits) | ((value & 0xFFFFFFFF) << (32 - bits));
        }

        inline void transform(const Block& block,
                              State& state) noexcept
        {
            uint32_t w[64];
            for (uint32_t i = 0; i < 16; ++i)
                w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                    (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                    (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                    static_cast<uint32_t>(block[i * 4 + 3]);

            for (uint32_t i = 16; i < 64; ++i)
            {
                const uint32_t sigma0 = rotateRight(w[i - 15], 7) ^ rotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3);
                const uint32_t sigma1 = rotateRight(w[i - 2], 17) ^ rotateRight(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + sigma0 + w[i - 7] + sigma1;
            }

            uint32_t a = state[0];
            uint32_t b = state[1];
            uint32_t c = state[2];
            uint32_t d = state[3];
            uint32_t e = state[4];
            uint32_t f = state[5];
            uint32_t g = state[6];
            uint32_t h = state[7];

            for (uint32_t i = 0; i < 64; ++i)
            {
                const uint32_t s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
                const uint32_t ch = (e & f) ^ (~e & g);
                const uint32_t temp1 = h + s1 + ch + k[i] + w[i];

                const uint32_t s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
                const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                const uint32_t temp2 = s0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
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
    }

    template <class Iterator>
    inline std::array<uint8_t, digestByteCount> hash(const Iterator begin,
                                                     const Iterator end) noexcept
    {
        State state = {
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19
        };

        Block block;
        uint32_t dataSize = 0;
        for (auto i = begin; i != end; ++i)
        {
            block[dataSize % blockByteCount] = *i;
            if (++dataSize % blockByteCount == 0)
                transform(block, state);
        }

        // pad data left in the buffer
        uint32_t n = dataSize % blockByteCount;
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

        std::array<uint8_t, digestByteCount> result;
        // reverse all the bytes to big endian
        for (uint32_t i = 0; i < digestIntCount; i++)
        {
            result[i * 4 + 0] = static_cast<uint8_t>(state[i] >> 24);
            result[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
            result[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
            result[i * 4 + 3] = static_cast<uint8_t>(state[i]);
        }

        return result;
    }

    template <class T>
    inline std::array<uint8_t, digestByteCount> hash(const T& v) noexcept
    {
        return hash(std::begin(v), std::end(v));
    }
}

#endif // SHA256_HPP
