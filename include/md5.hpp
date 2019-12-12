//
// Header-only libs
//

#ifndef MD5_HPP
#define MD5_HPP

#include <array>
#include <cstdint>

namespace md5
{
    constexpr uint8_t s[16] = {
        7, 12, 17, 22,
        5, 9, 14, 20,
        4, 11, 16, 23,
        6, 10, 15, 21
    };

    constexpr uint32_t k[64] = {
        0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
        0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
        0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
        0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
        0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
        0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
        0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
        0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
        0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
        0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
        0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
        0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
        0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
        0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
        0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
        0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
    };

    constexpr uint32_t rotateLeft(const uint32_t value,
                                  const uint32_t bits) noexcept
    {
        return (value << bits) | ((value & 0xFFFFFFFF) >> (32 - bits));
    }

    constexpr uint32_t f(const uint32_t x,
                         const uint32_t y,
                         const uint32_t z) noexcept
    {
        return (x & y) | (~x & z);
    }

    constexpr uint32_t g(const uint32_t x,
                         const uint32_t y,
                         const uint32_t z) noexcept
    {
        return (x & z) | (y & ~z);
    }

    constexpr uint32_t h(const uint32_t x,
                         const uint32_t y,
                         const uint32_t z) noexcept
    {
        return x ^ y ^ z;
    }

    constexpr uint32_t i(const uint32_t x,
                         const uint32_t y,
                         const uint32_t z) noexcept
    {
        return y ^ (x | ~z);
    }

    constexpr uint32_t ff(const uint32_t a, const uint32_t b,
                          const uint32_t c, const uint32_t d,
                          const uint32_t x, const uint32_t sh,
                          const uint32_t ac) noexcept
    {
        return rotateLeft(a + f(b, c, d) + x + ac, sh) + b;
    }

    constexpr uint32_t gg(const uint32_t a, const uint32_t b,
                          const uint32_t c, const uint32_t d,
                          const uint32_t x, const uint32_t sh,
                          const uint32_t ac) noexcept
    {
        return rotateLeft(a + g(b, c, d) + x + ac, sh) + b;
    }

    constexpr uint32_t hh(const uint32_t a, const uint32_t b,
                          const uint32_t c, const uint32_t d,
                          const uint32_t x, const uint32_t sh,
                          const uint32_t ac) noexcept
    {
        return rotateLeft(a + h(b, c, d) + x + ac, sh) + b;
    }

    constexpr uint32_t ii(const uint32_t a, const uint32_t b,
                          const uint32_t c, const uint32_t d,
                          const uint32_t x, const uint32_t sh,
                          const uint32_t ac) noexcept
    {
        return rotateLeft(a + i(b, c, d) + x + ac, sh) + b;
    }

    constexpr uint32_t digestIntCount = 4; // number of 32bit integers per MD5 digest
    constexpr uint32_t digestByteCount = digestIntCount * 4;
    constexpr uint32_t blockIntCount = 16; // number of 32bit integers per MD5 block
    constexpr uint32_t blockByteCount = blockIntCount * 4;
    using Block = uint8_t[blockByteCount];
    using State = uint32_t[digestIntCount];

    inline void transform(const Block& block,
                          State& state) noexcept
    {
        uint32_t w[16];

        for (uint32_t i = 0; i < 16; ++i)
            w[i] = static_cast<uint32_t>(block[i * 4]) |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(block[i * 4 + 3]) << 24);

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];

        a = ff(a, b, c, d, w[0], s[0], k[0]);
        d = ff(d, a, b, c, w[1], s[1], k[1]);
        c = ff(c, d, a, b, w[2], s[2], k[2]);
        b = ff(b, c, d, a, w[3], s[3], k[3]);
        a = ff(a, b, c, d, w[4], s[0], k[4]);
        d = ff(d, a, b, c, w[5], s[1], k[5]);
        c = ff(c, d, a, b, w[6], s[2], k[6]);
        b = ff(b, c, d, a, w[7], s[3], k[7]);
        a = ff(a, b, c, d, w[8], s[0], k[8]);
        d = ff(d, a, b, c, w[9], s[1], k[9]);
        c = ff(c, d, a, b, w[10], s[2], k[10]);
        b = ff(b, c, d, a, w[11], s[3], k[11]);
        a = ff(a, b, c, d, w[12], s[0], k[12]);
        d = ff(d, a, b, c, w[13], s[1], k[13]);
        c = ff(c, d, a, b, w[14], s[2], k[14]);
        b = ff(b, c, d, a, w[15], s[3], k[15]);

        a = gg(a, b, c, d, w[1], s[4], k[16]);
        d = gg(d, a, b, c, w[6], s[5], k[17]);
        c = gg(c, d, a, b, w[11], s[6], k[18]);
        b = gg(b, c, d, a, w[0], s[7], k[19]);
        a = gg(a, b, c, d, w[5], s[4], k[20]);
        d = gg(d, a, b, c, w[10], s[5],  k[21]);
        c = gg(c, d, a, b, w[15], s[6], k[22]);
        b = gg(b, c, d, a, w[4], s[7], k[23]);
        a = gg(a, b, c, d, w[9], s[4], k[24]);
        d = gg(d, a, b, c, w[14], s[5], k[25]);
        c = gg(c, d, a, b, w[3], s[6], k[26]);
        b = gg(b, c, d, a, w[8], s[7], k[27]);
        a = gg(a, b, c, d, w[13], s[4], k[28]);
        d = gg(d, a, b, c, w[2], s[5], k[29]);
        c = gg(c, d, a, b, w[7], s[6], k[30]);
        b = gg(b, c, d, a, w[12], s[7], k[31]);

        a = hh(a, b, c, d, w[5], s[8], k[32]);
        d = hh(d, a, b, c, w[8], s[9], k[33]);
        c = hh(c, d, a, b, w[11], s[10], k[34]);
        b = hh(b, c, d, a, w[14], s[11], k[35]);
        a = hh(a, b, c, d, w[1], s[8], k[36]);
        d = hh(d, a, b, c, w[4], s[9], k[37]);
        c = hh(c, d, a, b, w[7], s[10], k[38]);
        b = hh(b, c, d, a, w[10], s[11], k[39]);
        a = hh(a, b, c, d, w[13], s[8], k[40]);
        d = hh(d, a, b, c, w[0], s[9], k[41]);
        c = hh(c, d, a, b, w[3], s[10], k[42]);
        b = hh(b, c, d, a, w[6], s[11],  k[43]);
        a = hh(a, b, c, d, w[9], s[8], k[44]);
        d = hh(d, a, b, c, w[12], s[9], k[45]);
        c = hh(c, d, a, b, w[15], s[10], k[46]);
        b = hh(b, c, d, a, w[2], s[11], k[47]);

        a = ii(a, b, c, d, w[0], s[12], k[48]);
        d = ii(d, a, b, c, w[7], s[13], k[49]);
        c = ii(c, d, a, b, w[14], s[14], k[50]);
        b = ii(b, c, d, a, w[5], s[15], k[51]);
        a = ii(a, b, c, d, w[12], s[12], k[52]);
        d = ii(d, a, b, c, w[3], s[13], k[53]);
        c = ii(c, d, a, b, w[10], s[14], k[54]);
        b = ii(b, c, d, a, w[1], s[15], k[55]);
        a = ii(a, b, c, d, w[8], s[12], k[56]);
        d = ii(d, a, b, c, w[15], s[13], k[57]);
        c = ii(c, d, a, b, w[6], s[14], k[58]);
        b = ii(b, c, d, a, w[13], s[15], k[59]);
        a = ii(a, b, c, d, w[4], s[12], k[60]);
        d = ii(d, a, b, c, w[11], s[13], k[61]);
        c = ii(c, d, a, b, w[2], s[14], k[62]);
        b = ii(b, c, d, a, w[9], s[15], k[63]);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    template <class Iterator>
    inline std::array<uint8_t, digestByteCount> generate(const Iterator begin,
                                                         const Iterator end) noexcept
    {
        State state = {
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476
        };

        Block block;
        uint32_t dataSize = 0;
        for (auto i = begin; i != end; ++i)
        {
            block[dataSize] = *i;
            dataSize++;
            if (dataSize == blockByteCount)
            {
                transform(block, state);
                dataSize = 0;
            }
        }

        // pad data left in the buffer
        uint32_t n = dataSize;
        if (dataSize < blockByteCount - 8)
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
        block[56] = static_cast<uint8_t>(totalBits);
        block[57] = static_cast<uint8_t>(totalBits >> 8);
        block[58] = static_cast<uint8_t>(totalBits >> 16);
        block[59] = static_cast<uint8_t>(totalBits >> 24);
        block[60] = static_cast<uint8_t>(totalBits >> 32);
        block[61] = static_cast<uint8_t>(totalBits >> 40);
        block[62] = static_cast<uint8_t>(totalBits >> 48);
        block[63] = static_cast<uint8_t>(totalBits >> 56);
        transform(block, state);

        std::array<uint8_t, digestByteCount> result;
        for (uint32_t i = 0; i < digestIntCount; i++)
        {
            result[i * 4 + 0] = static_cast<uint8_t>(state[i]);
            result[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 8);
            result[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 16);
            result[i * 4 + 3] = static_cast<uint8_t>(state[i] >> 24);
        }

        return result;
    }

    template <class T>
    inline std::array<uint8_t, digestByteCount> generate(const T& v) noexcept
    {
        return generate(std::begin(v), std::end(v));
    }
}

#endif // MD5_HPP
