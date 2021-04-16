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
        constexpr std::array<std::uint32_t, 64> k = {
            0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
            0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
            0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
            0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
            0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
            0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
            0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
            0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
            0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
            0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
            0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
            0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
            0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
            0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
            0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
            0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
        };

        constexpr std::size_t digestIntCount = 8; // number of 32bit integers per SHA256 digest
        constexpr std::size_t digestByteCount = digestIntCount * 4;
        constexpr std::size_t blockIntCount = 16; // number of 32bit integers per SHA256 block
        constexpr std::size_t blockByteCount = blockIntCount * 4;
        using Block = std::array<std::uint8_t, blockByteCount>;
        using State = std::array<std::uint32_t, digestIntCount>;

        [[nodiscard]]
        constexpr std::uint32_t rotateRight(const std::uint32_t value,
                                            const std::uint32_t bits) noexcept
        {
            return (value >> bits) | ((value & 0xFFFFFFFFU) << (32 - bits));
        }

        inline void transform(const Block& block,
                              State& state) noexcept
        {
            std::array<std::uint32_t, 64> w;
            for (std::uint32_t i = 0; i < 16; ++i)
                w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                    (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                    (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                    static_cast<std::uint32_t>(block[i * 4 + 3]);

            for (std::uint32_t i = 16; i < 64; ++i)
            {
                const std::uint32_t sigma0 = rotateRight(w[i - 15], 7) ^ rotateRight(w[i - 15], 18) ^ (w[i - 15] >> 3);
                const std::uint32_t sigma1 = rotateRight(w[i - 2], 17) ^ rotateRight(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + sigma0 + w[i - 7] + sigma1;
            }

            std::uint32_t a = state[0];
            std::uint32_t b = state[1];
            std::uint32_t c = state[2];
            std::uint32_t d = state[3];
            std::uint32_t e = state[4];
            std::uint32_t f = state[5];
            std::uint32_t g = state[6];
            std::uint32_t h = state[7];

            for (std::uint32_t i = 0; i < 64; ++i)
            {
                const std::uint32_t s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
                const std::uint32_t ch = (e & f) ^ (~e & g);
                const std::uint32_t temp1 = h + s1 + ch + k[i] + w[i];

                const std::uint32_t s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
                const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                const std::uint32_t temp2 = s0 + maj;

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
    std::array<std::uint8_t, digestByteCount> hash(const Iterator begin,
                                                   const Iterator end) noexcept
    {
        State state = {
            0x6A09E667U,
            0xBB67AE85U,
            0x3C6EF372U,
            0xA54FF53AU,
            0x510E527FU,
            0x9B05688CU,
            0x1F83D9ABU,
            0x5BE0CD19U
        };

        Block block;
        std::uint32_t dataSize = 0;
        for (auto i = begin; i != end; ++i)
        {
            block[dataSize % blockByteCount] =static_cast<std::uint8_t>(*i);
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
        for (std::uint32_t i = 0; i < digestIntCount; ++i)
        {
            result[i * 4 + 0] = static_cast<std::uint8_t>(state[i] >> 24);
            result[i * 4 + 1] = static_cast<std::uint8_t>(state[i] >> 16);
            result[i * 4 + 2] = static_cast<std::uint8_t>(state[i] >> 8);
            result[i * 4 + 3] = static_cast<std::uint8_t>(state[i]);
        }

        return result;
    }

    template <class T>
    std::array<std::uint8_t, digestByteCount> hash(const T& v) noexcept
    {
        return hash(std::begin(v), std::end(v));
    }
}

#endif // SHA256_HPP
