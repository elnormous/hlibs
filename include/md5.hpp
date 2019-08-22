//
// Header-only libs
//

#ifndef MD5_HPP
#define MD5_HPP

#include <array>
#include <cstdint>
#include <vector>

namespace md5
{
    static constexpr uint8_t S11 = 7;
    static constexpr uint8_t S12 = 12;
    static constexpr uint8_t S13 = 17;
    static constexpr uint8_t S14 = 22;
    static constexpr uint8_t S21 = 5;
    static constexpr uint8_t S22 = 9;
    static constexpr uint8_t S23 = 14;
    static constexpr uint8_t S24 = 20;
    static constexpr uint8_t S31 = 4;
    static constexpr uint8_t S32 = 11;
    static constexpr uint8_t S33 = 16;
    static constexpr uint8_t S34 = 23;
    static constexpr uint8_t S41 = 6;
    static constexpr uint8_t S42 = 10;
    static constexpr uint8_t S43 = 15;
    static constexpr uint8_t S44 = 21;

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

    inline void transform(uint32_t state[4], const uint8_t block[64]) noexcept
    {
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t x[16];

        for (uint32_t i = 0; i < 16; ++i)
            x[i] = static_cast<uint32_t>(block[i * 4]) |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
                (static_cast<uint32_t>(block[i * 4 + 3]) << 24);

        a = ff(a, b, c, d, x[0], S11, 0xD76AA478);
        d = ff(d, a, b, c, x[1], S12, 0xE8C7B756);
        c = ff(c, d, a, b, x[2], S13, 0x242070DB);
        b = ff(b, c, d, a, x[3], S14, 0xC1BDCEEE);
        a = ff(a, b, c, d, x[4], S11, 0xF57C0FAF);
        d = ff(d, a, b, c, x[5], S12, 0x4787C62A);
        c = ff(c, d, a, b, x[6], S13, 0xA8304613);
        b = ff(b, c, d, a, x[7], S14, 0xFD469501);
        a = ff(a, b, c, d, x[8], S11, 0x698098D8);
        d = ff(d, a, b, c, x[9], S12, 0x8B44F7AF);
        c = ff(c, d, a, b, x[10], S13, 0xFFFF5BB1);
        b = ff(b, c, d, a, x[11], S14, 0x895CD7BE);
        a = ff(a, b, c, d, x[12], S11, 0x6B901122);
        d = ff(d, a, b, c, x[13], S12, 0xFD987193);
        c = ff(c, d, a, b, x[14], S13, 0xA679438E);
        b = ff(b, c, d, a, x[15], S14, 0x49B40821);

        a = gg(a, b, c, d, x[1], S21, 0xF61E2562);
        d = gg(d, a, b, c, x[6], S22, 0xC040B340);
        c = gg(c, d, a, b, x[11], S23, 0x265E5A51);
        b = gg(b, c, d, a, x[0], S24, 0xE9B6C7AA);
        a = gg(a, b, c, d, x[5], S21, 0xD62F105D);
        d = gg(d, a, b, c, x[10], S22,  0x2441453);
        c = gg(c, d, a, b, x[15], S23, 0xD8A1E681);
        b = gg(b, c, d, a, x[4], S24, 0xE7D3FBC8);
        a = gg(a, b, c, d, x[9], S21, 0x21E1CDE6);
        d = gg(d, a, b, c, x[14], S22, 0xC33707D6);
        c = gg(c, d, a, b, x[3], S23, 0xF4D50D87);
        b = gg(b, c, d, a, x[8], S24, 0x455A14ED);
        a = gg(a, b, c, d, x[13], S21, 0xA9E3E905);
        d = gg(d, a, b, c, x[2], S22, 0xFCEFA3F8);
        c = gg(c, d, a, b, x[7], S23, 0x676F02D9);
        b = gg(b, c, d, a, x[12], S24, 0x8D2A4C8A);

        a = hh(a, b, c, d, x[5], S31, 0xFFFA3942);
        d = hh(d, a, b, c, x[8], S32, 0x8771F681);
        c = hh(c, d, a, b, x[11], S33, 0x6D9D6122);
        b = hh(b, c, d, a, x[14], S34, 0xFDE5380C);
        a = hh(a, b, c, d, x[1], S31, 0xA4BEEA44);
        d = hh(d, a, b, c, x[4], S32, 0x4BDECFA9);
        c = hh(c, d, a, b, x[7], S33, 0xF6BB4B60);
        b = hh(b, c, d, a, x[10], S34, 0xBEBFBC70);
        a = hh(a, b, c, d, x[13], S31, 0x289B7EC6);
        d = hh(d, a, b, c, x[0], S32, 0xEAA127FA);
        c = hh(c, d, a, b, x[3], S33, 0xD4EF3085);
        b = hh(b, c, d, a, x[6], S34,  0x4881D05);
        a = hh(a, b, c, d, x[9], S31, 0xD9D4D039);
        d = hh(d, a, b, c, x[12], S32, 0xE6DB99E5);
        c = hh(c, d, a, b, x[15], S33, 0x1FA27CF8);
        b = hh(b, c, d, a, x[2], S34, 0xC4AC5665);

        a = ii(a, b, c, d, x[0], S41, 0xF4292244);
        d = ii(d, a, b, c, x[7], S42, 0x432AFF97);
        c = ii(c, d, a, b, x[14], S43, 0xAB9423A7);
        b = ii(b, c, d, a, x[5], S44, 0xFC93A039);
        a = ii(a, b, c, d, x[12], S41, 0x655B59C3);
        d = ii(d, a, b, c, x[3], S42, 0x8F0CCC92);
        c = ii(c, d, a, b, x[10], S43, 0xFFEFF47D);
        b = ii(b, c, d, a, x[1], S44, 0x85845DD1);
        a = ii(a, b, c, d, x[8], S41, 0x6FA87E4F);
        d = ii(d, a, b, c, x[15], S42, 0xFE2CE6E0);
        c = ii(c, d, a, b, x[6], S43, 0xA3014314);
        b = ii(b, c, d, a, x[13], S44, 0x4E0811A1);
        a = ii(a, b, c, d, x[4], S41, 0xF7537E82);
        d = ii(d, a, b, c, x[11], S42, 0xBD3AF235);
        c = ii(c, d, a, b, x[2], S43, 0x2AD7D2BB);
        b = ii(b, c, d, a, x[9], S44, 0xEB86D391);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    template <class Iterator>
    inline std::array<uint8_t, 16> generate(const Iterator begin,
                                            const Iterator end)
    {
        uint32_t state[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};

        std::vector<uint8_t> m(begin, end);
        const size_t length = m.size() * 8;
        m.push_back(0x80);

        while (m.size() % 64 != 56)
            m.push_back(0x00);

        m.push_back(length & 0xFF);
        m.push_back((length >> 8) & 0xFF);
        m.push_back((length >> 16) & 0xFF);
        m.push_back((length >> 24) & 0xFF);
        m.push_back((length >> 32) & 0xFF);
        m.push_back((length >> 40) & 0xFF);
        m.push_back((length >> 48) & 0xFF);
        m.push_back((length >> 56) & 0xFF);

        for (uint32_t i = 0; i + 63 < m.size(); i += 64)
            transform(state, &m[i]);

        std::array<uint8_t, 16> result;
        for (uint32_t i = 0; i < 4; ++i)
        {
            result[i * 4] = state[i] & 0xFF;
            result[i * 4 + 1] = (state[i] >> 8) & 0xFF;
            result[i * 4 + 2] = (state[i] >> 16) & 0xFF;
            result[i * 4 + 3] = (state[i] >> 24) & 0xFF;
        }

        return result;
    }

    template <class T>
    inline std::array<uint8_t, 16> generate(const T& v)
    {
        return generate(std::begin(v), std::end(v));
    }
}

#endif // MD5_HPP
