//
// Header-only libs
//

#ifndef AES_HPP
#define AES_HPP

namespace aes
{
    namespace
    {
        // substitution-box 16x16 matrix
        static constexpr uint8_t sbox[256] = {
            0X63, 0X7C, 0X77, 0X7B, 0XF2, 0X6B, 0X6F, 0XC5,
            0X30, 0X01, 0X67, 0X2B, 0XFE, 0XD7, 0XAB, 0X76,
            0XCA, 0X82, 0XC9, 0X7D, 0XFA, 0X59, 0X47, 0XF0,
            0XAD, 0XD4, 0XA2, 0XAF, 0X9C, 0XA4, 0X72, 0XC0,
            0XB7, 0XFD, 0X93, 0X26, 0X36, 0X3F, 0XF7, 0XCC,
            0X34, 0XA5, 0XE5, 0XF1, 0X71, 0XD8, 0X31, 0X15,
            0X04, 0XC7, 0X23, 0XC3, 0X18, 0X96, 0X05, 0X9A,
            0X07, 0X12, 0X80, 0XE2, 0XEB, 0X27, 0XB2, 0X75,
            0X09, 0X83, 0X2C, 0X1A, 0X1B, 0X6E, 0X5A, 0XA0,
            0X52, 0X3B, 0XD6, 0XB3, 0X29, 0XE3, 0X2F, 0X84,
            0X53, 0XD1, 0X00, 0XED, 0X20, 0XFC, 0XB1, 0X5B,
            0X6A, 0XCB, 0XBE, 0X39, 0X4A, 0X4C, 0X58, 0XCF,
            0XD0, 0XEF, 0XAA, 0XFB, 0X43, 0X4D, 0X33, 0X85,
            0X45, 0XF9, 0X02, 0X7F, 0X50, 0X3C, 0X9F, 0XA8,
            0X51, 0XA3, 0X40, 0X8F, 0X92, 0X9D, 0X38, 0XF5,
            0XBC, 0XB6, 0XDA, 0X21, 0X10, 0XFF, 0XF3, 0XD2,
            0XCD, 0X0C, 0X13, 0XEC, 0X5F, 0X97, 0X44, 0X17,
            0XC4, 0XA7, 0X7E, 0X3D, 0X64, 0X5D, 0X19, 0X73,
            0X60, 0X81, 0X4F, 0XDC, 0X22, 0X2A, 0X90, 0X88,
            0X46, 0XEE, 0XB8, 0X14, 0XDE, 0X5E, 0X0B, 0XDB,
            0XE0, 0X32, 0X3A, 0X0A, 0X49, 0X06, 0X24, 0X5C,
            0XC2, 0XD3, 0XAC, 0X62, 0X91, 0X95, 0XE4, 0X79,
            0XE7, 0XC8, 0X37, 0X6D, 0X8D, 0XD5, 0X4E, 0XA9,
            0X6C, 0X56, 0XF4, 0XEA, 0X65, 0X7A, 0XAE, 0X08,
            0XBA, 0X78, 0X25, 0X2E, 0X1C, 0XA6, 0XB4, 0XC6,
            0XE8, 0XDD, 0X74, 0X1F, 0X4B, 0XBD, 0X8B, 0X8A,
            0X70, 0X3E, 0XB5, 0X66, 0X48, 0X03, 0XF6, 0X0E,
            0X61, 0X35, 0X57, 0XB9, 0X86, 0XC1, 0X1D, 0X9E,
            0XE1, 0XF8, 0X98, 0X11, 0X69, 0XD9, 0X8E, 0X94,
            0X9B, 0X1E, 0X87, 0XE9, 0XCE, 0X55, 0X28, 0XDF,
            0X8C, 0XA1, 0X89, 0X0D, 0XBF, 0XE6, 0X42, 0X68,
            0X41, 0X99, 0X2D, 0X0F, 0XB0, 0X54, 0XBB, 0X16
        };

        // inverse substitution-box 16x16 matrix
        static constexpr uint8_t inverseSbox[256] = {
            0X52, 0X09, 0X6A, 0XD5, 0X30, 0X36, 0XA5, 0X38,
            0XBF, 0X40, 0XA3, 0X9E, 0X81, 0XF3, 0XD7, 0XFB,
            0X7C, 0XE3, 0X39, 0X82, 0X9B, 0X2F, 0XFF, 0X87,
            0X34, 0X8E, 0X43, 0X44, 0XC4, 0XDE, 0XE9, 0XCB,
            0X54, 0X7B, 0X94, 0X32, 0XA6, 0XC2, 0X23, 0X3D,
            0XEE, 0X4C, 0X95, 0X0B, 0X42, 0XFA, 0XC3, 0X4E,
            0X08, 0X2E, 0XA1, 0X66, 0X28, 0XD9, 0X24, 0XB2,
            0X76, 0X5B, 0XA2, 0X49, 0X6D, 0X8B, 0XD1, 0X25,
            0X72, 0XF8, 0XF6, 0X64, 0X86, 0X68, 0X98, 0X16,
            0XD4, 0XA4, 0X5C, 0XCC, 0X5D, 0X65, 0XB6, 0X92,
            0X6C, 0X70, 0X48, 0X50, 0XFD, 0XED, 0XB9, 0XDA,
            0X5E, 0X15, 0X46, 0X57, 0XA7, 0X8D, 0X9D, 0X84,
            0X90, 0XD8, 0XAB, 0X00, 0X8C, 0XBC, 0XD3, 0X0A,
            0XF7, 0XE4, 0X58, 0X05, 0XB8, 0XB3, 0X45, 0X06,
            0XD0, 0X2C, 0X1E, 0X8F, 0XCA, 0X3F, 0X0F, 0X02,
            0XC1, 0XAF, 0XBD, 0X03, 0X01, 0X13, 0X8A, 0X6B,
            0X3A, 0X91, 0X11, 0X41, 0X4F, 0X67, 0XDC, 0XEA,
            0X97, 0XF2, 0XCF, 0XCE, 0XF0, 0XB4, 0XE6, 0X73,
            0X96, 0XAC, 0X74, 0X22, 0XE7, 0XAD, 0X35, 0X85,
            0XE2, 0XF9, 0X37, 0XE8, 0X1C, 0X75, 0XDF, 0X6E,
            0X47, 0XF1, 0X1A, 0X71, 0X1D, 0X29, 0XC5, 0X89,
            0X6F, 0XB7, 0X62, 0X0E, 0XAA, 0X18, 0XBE, 0X1B,
            0XFC, 0X56, 0X3E, 0X4B, 0XC6, 0XD2, 0X79, 0X20,
            0X9A, 0XDB, 0XC0, 0XFE, 0X78, 0XCD, 0X5A, 0XF4,
            0X1F, 0XDD, 0XA8, 0X33, 0X88, 0X07, 0XC7, 0X31,
            0XB1, 0X12, 0X10, 0X59, 0X27, 0X80, 0XEC, 0X5F,
            0X60, 0X51, 0X7F, 0XA9, 0X19, 0XB5, 0X4A, 0X0D,
            0X2D, 0XE5, 0X7A, 0X9F, 0X93, 0XC9, 0X9C, 0XEF,
            0XA0, 0XE0, 0X3B, 0X4D, 0XAE, 0X2A, 0XF5, 0XB0,
            0XC8, 0XEB, 0XBB, 0X3C, 0X83, 0X53, 0X99, 0X61,
            0X17, 0X2B, 0X04, 0X7E, 0XBA, 0X77, 0XD6, 0X26,
            0XE1, 0X69, 0X14, 0X63, 0X55, 0X21, 0X0C, 0X7D
        };

        // number of rounds (Nr)
        constexpr size_t getRoundCount(size_t keyLength)
        {
            return keyLength / 32 + 6;
        }

        // number of 32-bit words in cipher key (Nk)
        constexpr size_t getKeyWordCount(size_t keyLength) noexcept
        {
            return keyLength / 32;
        }

        constexpr size_t blockWordCount = 4; // number of words in an AES block (Nb)
        constexpr size_t blockByteCount = 4 * blockWordCount;

        struct Word
        {
            uint8_t& operator[](size_t i) { return b[i]; }
            uint8_t operator[](size_t i) const { return b[i]; }

            uint8_t b[4];
        };

        struct Block
        {
            Word& operator[](size_t i) { return w[i]; }
            const Word& operator[](size_t i) const { return w[i]; }

            Word w[blockWordCount];
        };

        using RoundKey = Word[4];
        template <size_t keyLength>
        using RoundKeys = RoundKey[getRoundCount(keyLength) + 1];

        void subBytes(Block& block) noexcept
        {
            for (size_t i = 0; i < 4; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    block[i][j] = sbox[block[i][j]];
        }

        void invSubBytes(Block& block) noexcept
        {
            for (size_t i = 0; i < 4; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    block[i][j] = inverseSbox[block[i][j]];
        }

        void shiftRow(Block& block, const size_t i, const size_t n) noexcept
        {
            for (size_t k = 0; k < n; k++)
            {
                uint8_t t = block[i][0];
                for (size_t j = 0; j < blockWordCount - 1; ++j)
                    block[i][j] = block[i][j + 1];

                block[i][blockWordCount - 1] = t;
            }
        }

        void shiftRows(Block& block) noexcept
        {
            shiftRow(block, 1, 1);
            shiftRow(block, 2, 2);
            shiftRow(block, 3, 3);
        }

        void invShiftRows(Block& block) noexcept
        {
            shiftRow(block, 1, blockWordCount - 1);
            shiftRow(block, 2, blockWordCount - 2);
            shiftRow(block, 3, blockWordCount - 3);
        }

        uint8_t mulBytes(uint8_t a, uint8_t b) noexcept
        {
            uint8_t c = 0;
            for (size_t i = 0; i < 8; ++i)
            {
                if (b & 0x01)
                {
                    uint8_t d = a;
                    for (size_t j = 0; j < i; ++j)
                        d = static_cast<uint8_t>((d << 1) ^ (d & 0x80 ? 0x1B : 0));

                    c = c ^ d;
                }

                b >>= 1;
            }
            return c;
        }

        void mixColumns(Block& block) noexcept
        {
            for (size_t j = 0; j < blockWordCount; ++j)
            {
                const Word s = {
                    block[0][j],
                    block[1][j],
                    block[2][j],
                    block[3][j]
                };

                const Word s1 = {
                    static_cast<uint8_t>(mulBytes(0x02, s[0]) ^ mulBytes(0x03, s[1]) ^ s[2] ^ s[3]),
                    static_cast<uint8_t>(s[0] ^ mulBytes(0x02, s[1]) ^ mulBytes(0x03, s[2]) ^ s[3]),
                    static_cast<uint8_t>(s[0] ^ s[1] ^ mulBytes(0x02, s[2]) ^ mulBytes(0x03, s[3])),
                    static_cast<uint8_t>(mulBytes(0x03, s[0]) ^ s[1] ^ s[2] ^ mulBytes(0x02, s[3]))
                };

                for (size_t i = 0; i < 4; ++i)
                    block[i][j] = s1[i];
          }
        }

        void invMixColumns(Block& block) noexcept
        {
            for (size_t j = 0; j < blockWordCount; ++j)
            {
                const Word s = {
                    block[0][j],
                    block[1][j],
                    block[2][j],
                    block[3][j]
                };

                Word s1;
                s1[0] = mulBytes(0x0e, s[0]) ^ mulBytes(0x0b, s[1]) ^ mulBytes(0x0d, s[2]) ^ mulBytes(0x09, s[3]);
                s1[1] = mulBytes(0x09, s[0]) ^ mulBytes(0x0e, s[1]) ^ mulBytes(0x0b, s[2]) ^ mulBytes(0x0d, s[3]);
                s1[2] = mulBytes(0x0d, s[0]) ^ mulBytes(0x09, s[1]) ^ mulBytes(0x0e, s[2]) ^ mulBytes(0x0b, s[3]);
                s1[3] = mulBytes(0x0b, s[0]) ^ mulBytes(0x0d, s[1]) ^ mulBytes(0x09, s[2]) ^ mulBytes(0x0e, s[3]);

                for (size_t i = 0; i < 4; ++i)
                    block[i][j] = s1[i];
            }
        }

        void xorBlocks(const Block& a, const Block& b, Block& c) noexcept
        {
            for (size_t i = 0; i < 4; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    c[i][j] = a[i][j] ^ b[i][j];
        }

        void addRoundKey(Block& block, const RoundKey& roundKey) noexcept
        {
            for (size_t i = 0; i < 4; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    block[i][j] = block[i][j] ^ roundKey[j][i];
        }

        void subWord(Word& a) noexcept
        {
            for (size_t i = 0; i < 4; ++i)
                a[i] = sbox[a[i]];
        }

        void rotWord(Word& a) noexcept
        {
            const uint8_t c = a[0];
            a[0] = a[1];
            a[1] = a[2];
            a[2] = a[3];
            a[3] = c;
        }

        void xorWords(const Word& a, const Word& b, Word& c) noexcept
        {
            for (size_t i = 0; i < 4; ++i)
                c[i] = a[i] ^ b[i];
        }

        constexpr uint8_t roundConstant(size_t i) noexcept
        {
            return (i == 1) ? 1 : static_cast<uint8_t>(2 * roundConstant(i - 1)) ^ (roundConstant(i - 1) >= 0x80 ? 0x1B : 0);
        }

        template<size_t keyLength, class Key>
        void expandKey(const Key& key, RoundKeys<keyLength>& roundKeys) noexcept
        {
            for (size_t i = 0; i < blockWordCount * (getRoundCount(keyLength) + 1); ++i)
            {
                if (i < getKeyWordCount(keyLength))
                {
                    roundKeys[i / 4][i % 4][0] = key[i * 4 + 0];
                    roundKeys[i / 4][i % 4][1] = key[i * 4 + 1];
                    roundKeys[i / 4][i % 4][2] = key[i * 4 + 2];
                    roundKeys[i / 4][i % 4][3] = key[i * 4 + 3];
                }
                else
                {
                    const size_t previousWordIndex = i - 1;
                    Word temp = roundKeys[previousWordIndex / 4][previousWordIndex % 4];

                    if (i % getKeyWordCount(keyLength) == 0)
                    {
                        rotWord(temp);
                        subWord(temp);
                        Word rCon = {roundConstant(i / getKeyWordCount(keyLength)), 0, 0, 0};
                        xorWords(temp, rCon, temp);
                    }
                    else if (getKeyWordCount(keyLength) > 6 && i % getKeyWordCount(keyLength) == 4)
                        subWord(temp);

                    const size_t beforeKeyIndex = i - getKeyWordCount(keyLength);
                    xorWords(roundKeys[beforeKeyIndex / 4][beforeKeyIndex % 4], temp, roundKeys[i / 4][i % 4]);
                }
            }
        }

        template<size_t keyLength, class Key>
        void encryptBlock(const Block& block, Block& encryptedBlock, const Key& key) noexcept
        {
            RoundKeys<keyLength> roundKeys;
            expandKey<keyLength>(key, roundKeys);

            Block state;
            for (size_t i = 0; i < 4; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    state[i][j] = block[j][i];

            addRoundKey(state, roundKeys[0]);

            for (size_t round = 1; round <= getRoundCount(keyLength) - 1; ++round)
            {
                subBytes(state);
                shiftRows(state);
                mixColumns(state);
                addRoundKey(state, roundKeys[round]);
            }

            subBytes(state);
            shiftRows(state);
            addRoundKey(state, roundKeys[getRoundCount(keyLength)]);

            for (size_t i = 0; i < 4; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    encryptedBlock[j][i] = state[i][j];
        }

        template<size_t keyLength, class Key>
        void decryptBlock(const Block& block, Block& decryptedBlock, const Key& key) noexcept
        {
            RoundKeys<keyLength> roundKeys;
            expandKey<keyLength>(key, roundKeys);

            Block state;
            for (size_t i = 0; i < 4; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    state[i][j] = block[j][i];

            addRoundKey(state, roundKeys[getRoundCount(keyLength)]);

            for (size_t round = getRoundCount(keyLength) - 1; round >= 1; --round)
            {
                invSubBytes(state);
                invShiftRows(state);
                addRoundKey(state, roundKeys[round]);
                invMixColumns(state);
            }

            invSubBytes(state);
            invShiftRows(state);
            addRoundKey(state, roundKeys[0]);

            for (size_t i = 0; i < 4; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    decryptedBlock[j][i] = state[i][j];
        }
    }
}

#endif // AES_HPP
