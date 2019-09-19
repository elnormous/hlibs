//
// Header-only libs
//

#ifndef MD5_HPP
#define MD5_HPP

#include <array>
#include <cstdint>

namespace md5
{
    namespace
    {
        constexpr uint8_t S11 = 7;
        constexpr uint8_t S12 = 12;
        constexpr uint8_t S13 = 17;
        constexpr uint8_t S14 = 22;
        constexpr uint8_t S21 = 5;
        constexpr uint8_t S22 = 9;
        constexpr uint8_t S23 = 14;
        constexpr uint8_t S24 = 20;
        constexpr uint8_t S31 = 4;
        constexpr uint8_t S32 = 11;
        constexpr uint8_t S33 = 16;
        constexpr uint8_t S34 = 23;
        constexpr uint8_t S41 = 6;
        constexpr uint8_t S42 = 10;
        constexpr uint8_t S43 = 15;
        constexpr uint8_t S44 = 21;

        constexpr uint32_t rotateLeft(const uint32_t value,
                                      const uint32_t bits) noexcept
        {
            return (value << bits) | ((value & 0xFFFFFFFF) >> (32 - bits));
        }

        // F, G, H and I are basic MD5 functions
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
                              const uint32_t x, const uint32_t s,
                              const uint32_t ac) noexcept
        {
            return rotateLeft(a + f(b, c, d) + x + ac, s) + b;
        }

        constexpr uint32_t gg(const uint32_t a, const uint32_t b,
                              const uint32_t c, const uint32_t d,
                              const uint32_t x, const uint32_t s,
                              const uint32_t ac) noexcept
        {
            return rotateLeft(a + g(b, c, d) + x + ac, s) + b;
        }

        constexpr uint32_t hh(const uint32_t a, const uint32_t b,
                              const uint32_t c, const uint32_t d,
                              const uint32_t x, const uint32_t s,
                              const uint32_t ac) noexcept
        {
            return rotateLeft(a + h(b, c, d) + x + ac, s) + b;
        }

        constexpr uint32_t ii(const uint32_t a, const uint32_t b,
                              const uint32_t c, const uint32_t d,
                              const uint32_t x, const uint32_t s,
                              const uint32_t ac) noexcept
        {
            return rotateLeft(a + i(b, c, d) + x + ac, s) + b;
        }

        constexpr uint32_t DIGEST_INTS = 4; // number of 32bit integers per MD5 digest
        constexpr uint32_t BLOCK_INTS = 16; // number of 32bit integers per MD5 block
        constexpr uint32_t BLOCK_BYTES = BLOCK_INTS * 4;

        inline void transform(const uint8_t block[BLOCK_BYTES],
                              uint32_t state[DIGEST_INTS]) noexcept
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

            a = ff(a, b, c, d, w[0], S11, 0xD76AA478);
            d = ff(d, a, b, c, w[1], S12, 0xE8C7B756);
            c = ff(c, d, a, b, w[2], S13, 0x242070DB);
            b = ff(b, c, d, a, w[3], S14, 0xC1BDCEEE);
            a = ff(a, b, c, d, w[4], S11, 0xF57C0FAF);
            d = ff(d, a, b, c, w[5], S12, 0x4787C62A);
            c = ff(c, d, a, b, w[6], S13, 0xA8304613);
            b = ff(b, c, d, a, w[7], S14, 0xFD469501);
            a = ff(a, b, c, d, w[8], S11, 0x698098D8);
            d = ff(d, a, b, c, w[9], S12, 0x8B44F7AF);
            c = ff(c, d, a, b, w[10], S13, 0xFFFF5BB1);
            b = ff(b, c, d, a, w[11], S14, 0x895CD7BE);
            a = ff(a, b, c, d, w[12], S11, 0x6B901122);
            d = ff(d, a, b, c, w[13], S12, 0xFD987193);
            c = ff(c, d, a, b, w[14], S13, 0xA679438E);
            b = ff(b, c, d, a, w[15], S14, 0x49B40821);

            a = gg(a, b, c, d, w[1], S21, 0xF61E2562);
            d = gg(d, a, b, c, w[6], S22, 0xC040B340);
            c = gg(c, d, a, b, w[11], S23, 0x265E5A51);
            b = gg(b, c, d, a, w[0], S24, 0xE9B6C7AA);
            a = gg(a, b, c, d, w[5], S21, 0xD62F105D);
            d = gg(d, a, b, c, w[10], S22,  0x2441453);
            c = gg(c, d, a, b, w[15], S23, 0xD8A1E681);
            b = gg(b, c, d, a, w[4], S24, 0xE7D3FBC8);
            a = gg(a, b, c, d, w[9], S21, 0x21E1CDE6);
            d = gg(d, a, b, c, w[14], S22, 0xC33707D6);
            c = gg(c, d, a, b, w[3], S23, 0xF4D50D87);
            b = gg(b, c, d, a, w[8], S24, 0x455A14ED);
            a = gg(a, b, c, d, w[13], S21, 0xA9E3E905);
            d = gg(d, a, b, c, w[2], S22, 0xFCEFA3F8);
            c = gg(c, d, a, b, w[7], S23, 0x676F02D9);
            b = gg(b, c, d, a, w[12], S24, 0x8D2A4C8A);

            a = hh(a, b, c, d, w[5], S31, 0xFFFA3942);
            d = hh(d, a, b, c, w[8], S32, 0x8771F681);
            c = hh(c, d, a, b, w[11], S33, 0x6D9D6122);
            b = hh(b, c, d, a, w[14], S34, 0xFDE5380C);
            a = hh(a, b, c, d, w[1], S31, 0xA4BEEA44);
            d = hh(d, a, b, c, w[4], S32, 0x4BDECFA9);
            c = hh(c, d, a, b, w[7], S33, 0xF6BB4B60);
            b = hh(b, c, d, a, w[10], S34, 0xBEBFBC70);
            a = hh(a, b, c, d, w[13], S31, 0x289B7EC6);
            d = hh(d, a, b, c, w[0], S32, 0xEAA127FA);
            c = hh(c, d, a, b, w[3], S33, 0xD4EF3085);
            b = hh(b, c, d, a, w[6], S34,  0x4881D05);
            a = hh(a, b, c, d, w[9], S31, 0xD9D4D039);
            d = hh(d, a, b, c, w[12], S32, 0xE6DB99E5);
            c = hh(c, d, a, b, w[15], S33, 0x1FA27CF8);
            b = hh(b, c, d, a, w[2], S34, 0xC4AC5665);

            a = ii(a, b, c, d, w[0], S41, 0xF4292244);
            d = ii(d, a, b, c, w[7], S42, 0x432AFF97);
            c = ii(c, d, a, b, w[14], S43, 0xAB9423A7);
            b = ii(b, c, d, a, w[5], S44, 0xFC93A039);
            a = ii(a, b, c, d, w[12], S41, 0x655B59C3);
            d = ii(d, a, b, c, w[3], S42, 0x8F0CCC92);
            c = ii(c, d, a, b, w[10], S43, 0xFFEFF47D);
            b = ii(b, c, d, a, w[1], S44, 0x85845DD1);
            a = ii(a, b, c, d, w[8], S41, 0x6FA87E4F);
            d = ii(d, a, b, c, w[15], S42, 0xFE2CE6E0);
            c = ii(c, d, a, b, w[6], S43, 0xA3014314);
            b = ii(b, c, d, a, w[13], S44, 0x4E0811A1);
            a = ii(a, b, c, d, w[4], S41, 0xF7537E82);
            d = ii(d, a, b, c, w[11], S42, 0xBD3AF235);
            c = ii(c, d, a, b, w[2], S43, 0x2AD7D2BB);
            b = ii(b, c, d, a, w[9], S44, 0xEB86D391);

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
        }
    }

    template <class Iterator>
    inline std::array<uint8_t, DIGEST_INTS * 4> generate(const Iterator begin,
                                                         const Iterator end) noexcept
    {
        uint32_t state[BLOCK_INTS] = {
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476
        };

        uint8_t block[BLOCK_BYTES];
        uint32_t dataSize = 0;
        for (auto i = begin; i != end; ++i)
        {
            block[dataSize] = *i;
            dataSize++;
            if (dataSize == BLOCK_BYTES)
            {
                transform(block, state);
                dataSize = 0;
            }
        }

        // Pad data left in the buffer
        uint32_t n = dataSize;
        if (dataSize < BLOCK_BYTES - 8)
        {
            block[n++] = 0x80;
            while (n < BLOCK_BYTES - 8) block[n++] = 0x00;
        }
        else
        {
            block[n++] = 0x80;
            while (n < BLOCK_BYTES) block[n++] = 0x00;
            transform(block, state);
            std::fill(block, block + BLOCK_BYTES - 8, 0);
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

        std::array<uint8_t, DIGEST_INTS * 4> result;
        for (uint32_t i = 0; i < DIGEST_INTS; i++)
        {
            result[i * 4 + 0] = static_cast<uint8_t>(state[i]);
            result[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 8);
            result[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 16);
            result[i * 4 + 3] = static_cast<uint8_t>(state[i] >> 24);
        }

        return result;
    }

    template <class T>
    inline std::array<uint8_t, DIGEST_INTS * 4> generate(const T& v) noexcept
    {
        return generate(std::begin(v), std::end(v));
    }
}

#endif // MD5_HPP
