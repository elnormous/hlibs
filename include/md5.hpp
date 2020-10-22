//
// Header-only libs
//

#ifndef MD5_HPP
#define MD5_HPP

#include <array>
#include <cstdint>

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

        constexpr std::uint32_t f(const std::uint32_t x,
                                  const std::uint32_t y,
                                  const std::uint32_t z) noexcept
        {
            return (x & y) | (~x & z);
        }

        constexpr std::uint32_t g(const std::uint32_t x,
                                  const std::uint32_t y,
                                  const std::uint32_t z) noexcept
        {
            return (x & z) | (y & ~z);
        }

        constexpr std::uint32_t h(const std::uint32_t x,
                                  const std::uint32_t y,
                                  const std::uint32_t z) noexcept
        {
            return x ^ y ^ z;
        }

        constexpr std::uint32_t i(const std::uint32_t x,
                                  const std::uint32_t y,
                                  const std::uint32_t z) noexcept
        {
            return y ^ (x | ~z);
        }

        constexpr std::uint32_t ff(const std::uint32_t a, const std::uint32_t b,
                                   const std::uint32_t c, const std::uint32_t d,
                                   const std::uint32_t x, const std::uint32_t sh,
                                   const std::uint32_t ac) noexcept
        {
            return rotateLeft(a + f(b, c, d) + x + ac, sh) + b;
        }

        constexpr std::uint32_t gg(const std::uint32_t a, const std::uint32_t b,
                                   const std::uint32_t c, const std::uint32_t d,
                                   const std::uint32_t x, const std::uint32_t sh,
                                   const std::uint32_t ac) noexcept
        {
            return rotateLeft(a + g(b, c, d) + x + ac, sh) + b;
        }

        constexpr std::uint32_t hh(const std::uint32_t a, const std::uint32_t b,
                                   const std::uint32_t c, const std::uint32_t d,
                                   const std::uint32_t x, const std::uint32_t sh,
                                   const std::uint32_t ac) noexcept
        {
            return rotateLeft(a + h(b, c, d) + x + ac, sh) + b;
        }

        constexpr std::uint32_t ii(const std::uint32_t a, const std::uint32_t b,
                                   const std::uint32_t c, const std::uint32_t d,
                                   const std::uint32_t x, const std::uint32_t sh,
                                   const std::uint32_t ac) noexcept
        {
            return rotateLeft(a + i(b, c, d) + x + ac, sh) + b;
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
        for (std::uint32_t i = 0; i < digestIntCount; i++)
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
