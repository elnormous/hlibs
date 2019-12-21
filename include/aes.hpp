//
// Header-only libs
//

#ifndef AES_HPP
#define AES_HPP

namespace aes
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
    constexpr size_t getRoundCount(size_t keyLength) noexcept
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
    constexpr size_t wordByteCount = 4;

    class Word final
    {
    public:
        uint8_t& operator[](size_t i) { return b[i]; }
        uint8_t operator[](size_t i) const { return b[i]; }

        Word operator^(const Word& other) const noexcept
        {
            Word result = *this;
            for (size_t i = 0; i < wordByteCount; ++i)
                result[i] ^= other[i];

            return result;
        }

        Word& operator^=(const Word& other) noexcept
        {
            for (size_t i = 0; i < wordByteCount; ++i)
                b[i] ^= other.b[i];

            return *this;
        }

        void sub() noexcept
        {
            for (size_t i = 0; i < wordByteCount; ++i)
                b[i] = sbox[b[i]];
        }

        void rot() noexcept
        {
            const uint8_t c = b[0];
            b[0] = b[1];
            b[1] = b[2];
            b[2] = b[3];
            b[3] = c;
        }

        uint8_t b[wordByteCount];
    };

    using RoundKey = Word[4];
    template <size_t keyLength>
    using RoundKeys = RoundKey[getRoundCount(keyLength) + 1];

    inline uint8_t mulBytes(uint8_t a, uint8_t b) noexcept
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

    constexpr uint8_t roundConstant(size_t i) noexcept
    {
        return (i == 1) ? 1 : static_cast<uint8_t>(2 * roundConstant(i - 1)) ^ (roundConstant(i - 1) >= 0x80 ? 0x1B : 0);
    }

    template <size_t keyLength, class Key>
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
                    temp.rot();
                    temp.sub();
                    Word rCon = {roundConstant(i / getKeyWordCount(keyLength)), 0, 0, 0};
                    temp ^= rCon;
                }
                else if (getKeyWordCount(keyLength) > 6 && i % getKeyWordCount(keyLength) == 4)
                    temp.sub();

                const size_t beforeKeyIndex = i - getKeyWordCount(keyLength);
                roundKeys[i / 4][i % 4] = roundKeys[beforeKeyIndex / 4][beforeKeyIndex % 4] ^ temp;
            }
        }
    }

    class Block final
    {
    public:
        Word& operator[](size_t i) { return w[i]; }
        const Word& operator[](size_t i) const { return w[i]; }

        Block operator^(const Block& other) const noexcept
        {
            Block result = *this;
            for (size_t i = 0; i < blockWordCount; ++i)
                result.w[i] ^= other.w[i];

            return result;
        }

        Block& operator^=(const Block& other) noexcept
        {
            for (size_t i = 0; i < blockWordCount; ++i)
                w[i] ^= other.w[i];

            return *this;
        }

        void subBytes() noexcept
        {
            for (size_t i = 0; i < wordByteCount; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    w[i][j] = sbox[w[i][j]];
        }

        void invSubBytes() noexcept
        {
            for (size_t i = 0; i < wordByteCount; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    w[i][j] = inverseSbox[w[i][j]];
        }

        void shiftRow(const size_t i, const size_t n) noexcept
        {
            for (size_t k = 0; k < n; k++)
            {
                uint8_t t = w[i][0];
                w[i][0] = w[i][1];
                w[i][1] = w[i][2];
                w[i][2] = w[i][3];
                w[i][3] = t;
            }
        }

        void shiftRows() noexcept
        {
            shiftRow(1, 1);
            shiftRow(2, 2);
            shiftRow(3, 3);
        }

        void invShiftRows() noexcept
        {
            shiftRow(1, blockWordCount - 1);
            shiftRow(2, blockWordCount - 2);
            shiftRow(3, blockWordCount - 3);
        }

        void mixColumns() noexcept
        {
            for (size_t j = 0; j < blockWordCount; ++j)
            {
                const Word s = {
                    w[0][j],
                    w[1][j],
                    w[2][j],
                    w[3][j]
                };

                const Word s1 = {
                    static_cast<uint8_t>(mulBytes(0x02, s[0]) ^ mulBytes(0x03, s[1]) ^ s[2] ^ s[3]),
                    static_cast<uint8_t>(s[0] ^ mulBytes(0x02, s[1]) ^ mulBytes(0x03, s[2]) ^ s[3]),
                    static_cast<uint8_t>(s[0] ^ s[1] ^ mulBytes(0x02, s[2]) ^ mulBytes(0x03, s[3])),
                    static_cast<uint8_t>(mulBytes(0x03, s[0]) ^ s[1] ^ s[2] ^ mulBytes(0x02, s[3]))
                };

                for (size_t i = 0; i < wordByteCount; ++i)
                    w[i][j] = s1[i];
          }
        }

        void invMixColumns() noexcept
        {
            for (size_t j = 0; j < blockWordCount; ++j)
            {
                const Word s = {
                    w[0][j],
                    w[1][j],
                    w[2][j],
                    w[3][j]
                };

                Word s1;
                s1[0] = mulBytes(0x0E, s[0]) ^ mulBytes(0x0B, s[1]) ^ mulBytes(0x0D, s[2]) ^ mulBytes(0x09, s[3]);
                s1[1] = mulBytes(0x09, s[0]) ^ mulBytes(0x0E, s[1]) ^ mulBytes(0x0B, s[2]) ^ mulBytes(0x0D, s[3]);
                s1[2] = mulBytes(0x0D, s[0]) ^ mulBytes(0x09, s[1]) ^ mulBytes(0x0E, s[2]) ^ mulBytes(0x0B, s[3]);
                s1[3] = mulBytes(0x0B, s[0]) ^ mulBytes(0x0D, s[1]) ^ mulBytes(0x09, s[2]) ^ mulBytes(0x0E, s[3]);

                for (size_t i = 0; i < wordByteCount; ++i)
                    w[i][j] = s1[i];
            }
        }

        void addRoundKey(const RoundKey& roundKey) noexcept
        {
            for (size_t i = 0; i < blockWordCount; ++i)
                for (size_t j = 0; j < wordByteCount; ++j)
                    w[i][j] ^= roundKey[j][i];
        }

        template <size_t keyLength, class Key>
        void encrypt(const Key& key) noexcept
        {
            RoundKeys<keyLength> roundKeys;
            expandKey<keyLength>(key, roundKeys);

            Block state;
            for (size_t i = 0; i < wordByteCount; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    state[i][j] = w[j][i];

            state.addRoundKey(roundKeys[0]);

            for (size_t round = 1; round <= getRoundCount(keyLength) - 1; ++round)
            {
                state.subBytes();
                state.shiftRows();
                state.mixColumns();
                state.addRoundKey(roundKeys[round]);
            }

            state.subBytes();
            state.shiftRows();
            state.addRoundKey(roundKeys[getRoundCount(keyLength)]);

            for (size_t i = 0; i < wordByteCount; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    w[j][i] = state[i][j];
        }

        template <size_t keyLength, class Key>
        void decrypt(const Key& key) noexcept
        {
            RoundKeys<keyLength> roundKeys;
            expandKey<keyLength>(key, roundKeys);

            Block state;
            for (size_t i = 0; i < wordByteCount; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    state[i][j] = w[j][i];

            state.addRoundKey(roundKeys[getRoundCount(keyLength)]);

            for (size_t round = getRoundCount(keyLength) - 1; round >= 1; --round)
            {
                state.invSubBytes();
                state.invShiftRows();
                state.addRoundKey(roundKeys[round]);
                state.invMixColumns();
            }

            state.invSubBytes();
            state.invShiftRows();
            state.addRoundKey(roundKeys[0]);

            for (size_t i = 0; i < wordByteCount; ++i)
                for (size_t j = 0; j < blockWordCount; ++j)
                    w[j][i] = state[i][j];
        }

        Word w[blockWordCount];
    };

    template <class Iterator>
    std::vector<Block> convertToBlocks(Iterator begin, Iterator end)
    {
        std::vector<Block> result;

        size_t b = 0;
        for (auto i = begin; i != end; ++i, ++b)
        {
            if (result.size() < b / blockByteCount + 1)
                result.resize(b / blockByteCount + 1);

            Block& block = result[b / blockByteCount];
            Word& word = block[(b / wordByteCount) % blockWordCount];
            word[b % wordByteCount] = *i;
        }

        return result;
    }

    template <size_t keyLength, class Iterator, class Key>
    std::vector<uint8_t> encryptEcb(Iterator begin, Iterator end, const Key& key)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<uint8_t> result(blocks.size() * blockByteCount);

        auto resultIterator = result.begin();

        for (Block& block : blocks)
        {
            block.encrypt<keyLength>(key);

            // copy the block to output
            for (const Word w : block.w)
                for (const uint8_t b : w.b)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <size_t keyLength, class Data, class Key>
    std::vector<uint8_t> encryptEcb(const Data& data, const Key& key)
    {
        return encryptEcb<keyLength>(std::begin(data), std::end(data), key);
    }

    template <size_t keyLength, class Iterator, class Key>
    std::vector<uint8_t> decryptEcb(Iterator begin, Iterator end, const Key& key)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<uint8_t> result(blocks.size() * blockByteCount);

        auto resultIterator = result.begin();

        for (Block& block : blocks)
        {
            block.decrypt<keyLength, Key>(key);

            // copy the block to output
            for (const Word w : block.w)
                for (const uint8_t b : w.b)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <size_t keyLength, class Data, class Key>
    std::vector<uint8_t> decryptEcb(const Data& data, const Key& key)
    {
        return decryptEcb<keyLength>(std::begin(data), std::end(data), key);
    }

    template <size_t keyLength, class Iterator, class Key, class InputVector>
    std::vector<uint8_t> encryptCbc(Iterator begin, Iterator end, const Key& key,
                                    const InputVector& inputVector)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<uint8_t> result(blocks.size() * blockByteCount);

        Block dataBlock;

        auto inputVectorIterator = std::begin(inputVector);
        for (Word& w : dataBlock.w)
            for (uint8_t& b : w.b)
                b = *inputVectorIterator++;

        auto resultIterator = result.begin();

        for (const Block& block : blocks)
        {
            dataBlock ^= block;
            dataBlock.encrypt<keyLength>(key);

            // copy the block to output
            for (const Word w : dataBlock.w)
                for (const uint8_t b : w.b)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <size_t keyLength, class Data, class Key, class InputVector>
    std::vector<uint8_t> encryptCbc(const Data& data, const Key& key,
                                    const InputVector& inputVector)
    {
        return encryptCbc<keyLength>(std::begin(data), std::end(data), key, inputVector);
    }

    template <size_t keyLength, class Iterator, class Key, class InputVector>
    std::vector<uint8_t> decryptCbc(Iterator begin, Iterator end, const Key& key,
                                    const InputVector& inputVector)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<uint8_t> result(blocks.size() * blockByteCount);

        Block dataBlock;

        auto inputVectorIterator = std::begin(inputVector);
        for (Word& w : dataBlock.w)
            for (uint8_t& b : w.b)
                b = *inputVectorIterator++;

        auto dataIterator = begin;
        auto resultIterator = result.begin();

        for (Block& block : blocks)
        {
            block.decrypt<keyLength>(key);
            block ^= dataBlock;

            // copy the block to output
            for (const Word w : block.w)
                for (const uint8_t b : w.b)
                    *resultIterator++ = b;

            // copy the data to data block
            for (Word& w : dataBlock.w)
                for (uint8_t& b : w.b)
                    b = *dataIterator++;
        }

        return result;
    }

    template <size_t keyLength, class Data, class Key, class InputVector>
    std::vector<uint8_t> decryptCbc(const Data& data, const Key& key,
                                    const InputVector& inputVector)
    {
        return decryptCbc<keyLength>(std::begin(data), std::end(data), key, inputVector);
    }

    template <size_t keyLength, class Iterator, class Key, class InputVector>
    std::vector<uint8_t> encryptCfb(Iterator begin, Iterator end, const Key& key,
                                    const InputVector& inputVector)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<uint8_t> result(blocks.size() * blockByteCount);

        Block encryptedBlock;

        auto inputVectorIterator = std::begin(inputVector);
        for (Word& w : encryptedBlock.w)
            for (uint8_t& b : w.b)
                b = *inputVectorIterator++;

        auto resultIterator = result.begin();

        for (const Block& block : blocks)
        {
            encryptedBlock.encrypt<keyLength>(key);
            encryptedBlock ^= block;

            // copy the block to output
            for (const Word w : encryptedBlock.w)
                for (const uint8_t b : w.b)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <size_t keyLength, class Data, class Key, class InputVector>
    std::vector<uint8_t> encryptCfb(const Data& data, const Key& key,
                                    const InputVector& inputVector)
    {
        return encryptCfb<keyLength>(std::begin(data), std::end(data), key, inputVector);
    }

    template <size_t keyLength, class Iterator, class Key, class InputVector>
    std::vector<uint8_t> decryptCfb(Iterator begin, Iterator end, const Key& key,
                                    const InputVector& inputVector)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<uint8_t> result(blocks.size() * blockByteCount);

        Block decryptedBlock;

        auto inputVectorIterator = std::begin(inputVector);
        for (Word& w : decryptedBlock.w)
            for (uint8_t& b : w.b)
                b = *inputVectorIterator++;

        auto resultIterator = result.begin();

        for (const Block& block : blocks)
        {
            decryptedBlock.encrypt<keyLength>(key);
            decryptedBlock ^= block;

            // copy the block to output
            for (const Word w : decryptedBlock.w)
                for (const uint8_t b : w.b)
                    *resultIterator++ = b;

            decryptedBlock = block;
        }

        return result;
    }

    template <size_t keyLength, class Data, class Key, class InputVector>
    std::vector<uint8_t> decryptCfb(const Data& data, const Key& key,
                                    const InputVector& inputVector)
    {
        return decryptCfb<keyLength>(std::begin(data), std::end(data), key, inputVector);
    }
}

#endif // AES_HPP
