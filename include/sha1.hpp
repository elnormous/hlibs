//
// Header-only libs
//

#ifndef SHA1_HPP
#define SHA1_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace sha1
{
    inline uint32_t rotateLeft(uint32_t value, uint32_t bits)
    {
        return (value << bits) | ((value & 0xFFFFFFFF) >> (32 - bits));
    }

    static const uint32_t DIGEST_INTS = 5; // number of 32bit integers per SHA1 digest
    static const uint32_t BLOCK_INTS = 16; // number of 32bit integers per SHA1 block
    static const uint32_t BLOCK_BYTES = BLOCK_INTS * 4;

    inline void transform(uint32_t block[BLOCK_BYTES], uint32_t digest[DIGEST_INTS])
    {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = block[i];

        for (int i = 16; i < 80; ++i)
            w[i] = rotateLeft(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

        uint32_t a = digest[0];
        uint32_t b = digest[1];
        uint32_t c = digest[2];
        uint32_t d = digest[3];
        uint32_t e = digest[4];

        uint32_t f = 0;
        uint32_t k = 0;

        for (int i = 0; i < 80; ++i)
        {
            if (0 <= i && i < 20)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (20 <= i && i < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (40 <= i && i < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else if (60 <= i && i < 80)
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = rotateLeft(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotateLeft(b, 30);
            b = a;
            a = temp;
        }

        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
    }

    inline std::vector<uint8_t> hash(const std::vector<uint8_t>& s)
    {
        uint32_t digest[DIGEST_INTS] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
        std::vector<uint8_t> buffer;
        uint32_t block[BLOCK_INTS];
        int b = 0;
        for (b = 0; b + BLOCK_BYTES <= s.size(); b += BLOCK_BYTES)
        {
            buffer.assign(s.begin() + b, s.begin() + b + BLOCK_BYTES);

            for (uint32_t i = 0; i < BLOCK_INTS; i++)
                block[i] = buffer[4 * i + 3] | buffer[4 * i + 2] << 8 | buffer[4 * i + 1] << 16 | buffer[4 * i + 0] << 24;

            transform(block, digest);
        }

        buffer.assign(s.begin() + b, s.end());
        buffer.push_back(0x80);
        auto origSize = buffer.size();
        while (buffer.size() < BLOCK_BYTES)
            buffer.push_back(0x00);

        for (uint32_t i = 0; i < BLOCK_INTS; i++)
            block[i] = buffer[4 * i + 3] | buffer[4 * i + 2] << 8 | buffer[4 * i + 1] << 16 | buffer[4 * i + 0] << 24;

        if (origSize > BLOCK_BYTES - 8)
        {
            transform(block, digest);
            for (uint32_t i = 0; i < BLOCK_INTS - 2; i++)
                block[i] = 0;
        }

        uint64_t totalBits = s.size() * 8;
        block[BLOCK_INTS - 1] = totalBits & 0xFFFFFFFF;
        block[BLOCK_INTS - 2] = (totalBits >> 32) & 0xFFFFFFFF;
        transform(block, digest);

        std::vector<uint8_t> result;
        for (uint32_t i = 0; i < DIGEST_INTS; i++)
        {
            result.push_back((digest[i] >> 24) & 0xFF);
            result.push_back((digest[i] >> 16) & 0xFF);
            result.push_back((digest[i] >> 8) & 0xFF);
            result.push_back(digest[i] & 0xFF);
        }

        return result;
    }
}

#endif // SHA1_HPP
