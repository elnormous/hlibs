//
// Header-only libs
//

#ifndef AES_HPP
#define AES_HPP

#include <array>
#include <cstddef>
#include <vector>

namespace aes
{
    inline namespace detail
    {
        // substitution-box 16x16 matrix
        constexpr std::array<std::uint8_t, 256> sbox = {
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
        constexpr std::array<std::uint8_t, 256> inverseSbox = {
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
        [[nodiscard]] constexpr std::size_t getRoundCount(std::size_t keyLength) noexcept
        {
            return keyLength / 32 + 6;
        }

        // number of 32-bit words in cipher key (Nk)
        [[nodiscard]] constexpr std::size_t getKeyWordCount(std::size_t keyLength) noexcept
        {
            return keyLength / 32;
        }

        constexpr std::size_t blockWordCount = 4; // number of words in an AES block (Nb)
        constexpr std::size_t blockByteCount = 4 * blockWordCount;
        constexpr std::size_t wordByteCount = 4;

        class Word final
        {
        public:
            Word operator^(const Word& other) const noexcept
            {
                Word result = *this;
                for (std::size_t i = 0; i < wordByteCount; ++i)
                    result.bytes[i] ^= other.bytes[i];

                return result;
            }

            Word& operator^=(const Word& other) noexcept
            {
                for (std::size_t i = 0; i < wordByteCount; ++i)
                    bytes[i] ^= other.bytes[i];

                return *this;
            }

            void sub() noexcept
            {
                for (std::size_t i = 0; i < wordByteCount; ++i)
                    bytes[i] = sbox[bytes[i]];
            }

            void rot() noexcept
            {
                const std::uint8_t c = bytes[0];
                bytes[0] = bytes[1];
                bytes[1] = bytes[2];
                bytes[2] = bytes[3];
                bytes[3] = c;
            }

            std::uint8_t bytes[wordByteCount];
        };

        using RoundKey = Word[4];
        template <std::size_t keyLength>
        using RoundKeys = RoundKey[getRoundCount(keyLength) + 1];

        inline std::uint8_t mulBytes(std::uint8_t a, std::uint8_t b) noexcept
        {
            std::uint8_t c = 0;
            for (std::size_t i = 0; i < 8; ++i)
            {
                if (b & 0x01)
                {
                    std::uint8_t d = a;
                    for (std::size_t j = 0; j < i; ++j)
                        d = static_cast<std::uint8_t>((d << 1) ^ (d & 0x80 ? 0x1B : 0));

                    c = c ^ d;
                }

                b >>= 1;
            }
            return c;
        }

        [[nodiscard]] constexpr std::uint8_t getRoundConstant(std::size_t i) noexcept
        {
            return (i == 1) ? 0x01 : static_cast<std::uint8_t>(0x02 * getRoundConstant(i - 1)) ^ (getRoundConstant(i - 1) >= 0x80 ? 0x1B : 0x00);
        }

        template <std::size_t keyLength, class Key>
        void expandKey(const Key& key, RoundKeys<keyLength>& roundKeys) noexcept
        {
            for (std::size_t i = 0; i < blockWordCount * (getRoundCount(keyLength) + 1); ++i)
            {
                if (i < getKeyWordCount(keyLength))
                {
                    roundKeys[i / 4][i % 4].bytes[0] = static_cast<std::uint8_t>(key[i * 4 + 0]);
                    roundKeys[i / 4][i % 4].bytes[1] = static_cast<std::uint8_t>(key[i * 4 + 1]);
                    roundKeys[i / 4][i % 4].bytes[2] = static_cast<std::uint8_t>(key[i * 4 + 2]);
                    roundKeys[i / 4][i % 4].bytes[3] = static_cast<std::uint8_t>(key[i * 4 + 3]);
                }
                else
                {
                    const std::size_t previousWordIndex = i - 1;
                    Word temp = roundKeys[previousWordIndex / 4][previousWordIndex % 4];

                    if (i % getKeyWordCount(keyLength) == 0)
                    {
                        temp.rot();
                        temp.sub();
                        Word rCon = {getRoundConstant(i / getKeyWordCount(keyLength)), 0, 0, 0};
                        temp ^= rCon;
                    }
                    else if (getKeyWordCount(keyLength) > 6 && i % getKeyWordCount(keyLength) == 4)
                        temp.sub();

                    const std::size_t beforeKeyIndex = i - getKeyWordCount(keyLength);
                    roundKeys[i / 4][i % 4] = roundKeys[beforeKeyIndex / 4][beforeKeyIndex % 4] ^ temp;
                }
            }
        }

        class Block final
        {
        public:
            Block operator^(const Block& other) const noexcept
            {
                Block result = *this;
                for (std::size_t i = 0; i < blockWordCount; ++i)
                    result.words[i] ^= other.words[i];

                return result;
            }

            Block& operator^=(const Block& other) noexcept
            {
                for (std::size_t i = 0; i < blockWordCount; ++i)
                    words[i] ^= other.words[i];

                return *this;
            }

            void subBytes() noexcept
            {
                for (std::size_t i = 0; i < wordByteCount; ++i)
                    for (std::size_t j = 0; j < blockWordCount; ++j)
                        words[i].bytes[j] = sbox[words[i].bytes[j]];
            }

            void invSubBytes() noexcept
            {
                for (std::size_t i = 0; i < wordByteCount; ++i)
                    for (std::size_t j = 0; j < blockWordCount; ++j)
                        words[i].bytes[j] = inverseSbox[words[i].bytes[j]];
            }

            void shiftRow(const std::size_t i, const std::size_t n) noexcept
            {
                for (std::size_t k = 0; k < n; k++)
                {
                    std::uint8_t t = words[i].bytes[0];
                    words[i].bytes[0] = words[i].bytes[1];
                    words[i].bytes[1] = words[i].bytes[2];
                    words[i].bytes[2] = words[i].bytes[3];
                    words[i].bytes[3] = t;
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
                for (std::size_t j = 0; j < blockWordCount; ++j)
                {
                    const Word s = {
                        words[0].bytes[j],
                        words[1].bytes[j],
                        words[2].bytes[j],
                        words[3].bytes[j]
                    };

                    const Word s1 = {
                        static_cast<std::uint8_t>(mulBytes(0x02, s.bytes[0]) ^ mulBytes(0x03, s.bytes[1]) ^ s.bytes[2] ^ s.bytes[3]),
                        static_cast<std::uint8_t>(s.bytes[0] ^ mulBytes(0x02, s.bytes[1]) ^ mulBytes(0x03, s.bytes[2]) ^ s.bytes[3]),
                        static_cast<std::uint8_t>(s.bytes[0] ^ s.bytes[1] ^ mulBytes(0x02, s.bytes[2]) ^ mulBytes(0x03, s.bytes[3])),
                        static_cast<std::uint8_t>(mulBytes(0x03, s.bytes[0]) ^ s.bytes[1] ^ s.bytes[2] ^ mulBytes(0x02, s.bytes[3]))
                    };

                    for (std::size_t i = 0; i < wordByteCount; ++i)
                        words[i].bytes[j] = s1.bytes[i];
              }
            }

            void invMixColumns() noexcept
            {
                for (std::size_t j = 0; j < blockWordCount; ++j)
                {
                    const Word s = {
                        words[0].bytes[j],
                        words[1].bytes[j],
                        words[2].bytes[j],
                        words[3].bytes[j]
                    };

                    Word s1;
                    s1.bytes[0] = mulBytes(0x0E, s.bytes[0]) ^ mulBytes(0x0B, s.bytes[1]) ^ mulBytes(0x0D, s.bytes[2]) ^ mulBytes(0x09, s.bytes[3]);
                    s1.bytes[1] = mulBytes(0x09, s.bytes[0]) ^ mulBytes(0x0E, s.bytes[1]) ^ mulBytes(0x0B, s.bytes[2]) ^ mulBytes(0x0D, s.bytes[3]);
                    s1.bytes[2] = mulBytes(0x0D, s.bytes[0]) ^ mulBytes(0x09, s.bytes[1]) ^ mulBytes(0x0E, s.bytes[2]) ^ mulBytes(0x0B, s.bytes[3]);
                    s1.bytes[3] = mulBytes(0x0B, s.bytes[0]) ^ mulBytes(0x0D, s.bytes[1]) ^ mulBytes(0x09, s.bytes[2]) ^ mulBytes(0x0E, s.bytes[3]);

                    for (std::size_t i = 0; i < wordByteCount; ++i)
                        words[i].bytes[j] = s1.bytes[i];
                }
            }

            void addRoundKey(const RoundKey& roundKey) noexcept
            {
                for (std::size_t i = 0; i < blockWordCount; ++i)
                    for (std::size_t j = 0; j < wordByteCount; ++j)
                        words[i].bytes[j] ^= roundKey[j].bytes[i];
            }

            template <std::size_t keyLength, class Key>
            void encrypt(const Key& key) noexcept
            {
                RoundKeys<keyLength> roundKeys;
                expandKey<keyLength>(key, roundKeys);

                Block state;
                for (std::size_t i = 0; i < wordByteCount; ++i)
                    for (std::size_t j = 0; j < blockWordCount; ++j)
                        state.words[i].bytes[j] = words[j].bytes[i];

                state.addRoundKey(roundKeys[0]);

                for (std::size_t round = 1; round <= getRoundCount(keyLength) - 1; ++round)
                {
                    state.subBytes();
                    state.shiftRows();
                    state.mixColumns();
                    state.addRoundKey(roundKeys[round]);
                }

                state.subBytes();
                state.shiftRows();
                state.addRoundKey(roundKeys[getRoundCount(keyLength)]);

                for (std::size_t i = 0; i < wordByteCount; ++i)
                    for (std::size_t j = 0; j < blockWordCount; ++j)
                        words[j].bytes[i] = state.words[i].bytes[j];
            }

            template <std::size_t keyLength, class Key>
            void decrypt(const Key& key) noexcept
            {
                RoundKeys<keyLength> roundKeys;
                expandKey<keyLength>(key, roundKeys);

                Block state;
                for (std::size_t i = 0; i < wordByteCount; ++i)
                    for (std::size_t j = 0; j < blockWordCount; ++j)
                        state.words[i].bytes[j] = words[j].bytes[i];

                state.addRoundKey(roundKeys[getRoundCount(keyLength)]);

                for (std::size_t round = getRoundCount(keyLength) - 1; round >= 1; --round)
                {
                    state.invSubBytes();
                    state.invShiftRows();
                    state.addRoundKey(roundKeys[round]);
                    state.invMixColumns();
                }

                state.invSubBytes();
                state.invShiftRows();
                state.addRoundKey(roundKeys[0]);

                for (std::size_t i = 0; i < wordByteCount; ++i)
                    for (std::size_t j = 0; j < blockWordCount; ++j)
                        words[j].bytes[i] = state.words[i].bytes[j];
            }

            Word words[blockWordCount];
        };

        template <class Iterator>
        std::vector<Block> convertToBlocks(Iterator begin, Iterator end)
        {
            std::vector<Block> result;

            std::size_t byte = 0;
            for (auto i = begin; i != end; ++i)
            {
                if (result.size() < byte / blockByteCount + 1)
                    result.resize(byte / blockByteCount + 1);

                Block& block = result[byte / blockByteCount];
                Word& word = block.words[(byte / wordByteCount) % blockWordCount];
                word.bytes[byte % wordByteCount] = static_cast<std::uint8_t>(*i);
                ++byte;
            }

            return result;
        }
    }

    template <std::size_t keyLength, class Iterator, class Key>
    std::vector<std::uint8_t> encryptEcb(Iterator begin, Iterator end, const Key& key)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        auto resultIterator = result.begin();

        for (auto& block : blocks)
        {
            block.encrypt<keyLength>(key);

            // copy the block to output
            for (const auto w : block.words)
                for (const auto b : w.bytes)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key>
    std::vector<std::uint8_t> encryptEcb(const Data& data, const Key& key)
    {
        return encryptEcb<keyLength>(std::begin(data), std::end(data), key);
    }

    template <std::size_t keyLength, class Iterator, class Key>
    std::vector<std::uint8_t> decryptEcb(Iterator begin, Iterator end, const Key& key)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        auto resultIterator = result.begin();

        for (auto& block : blocks)
        {
            block.decrypt<keyLength, Key>(key);

            // copy the block to output
            for (const auto word : block.words)
                for (const auto byte : word.bytes)
                    *resultIterator++ = byte;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key>
    std::vector<std::uint8_t> decryptEcb(const Data& data, const Key& key)
    {
        return decryptEcb<keyLength>(std::begin(data), std::end(data), key);
    }

    template <std::size_t keyLength, class Iterator, class Key, class InitVector>
    std::vector<std::uint8_t> encryptCbc(Iterator begin, Iterator end, const Key& key,
                                         const InitVector& initVector)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        Block dataBlock;

        auto initVectorIterator = std::begin(initVector);
        for (auto& w : dataBlock.words)
            for (auto& b : w.bytes)
                b = *initVectorIterator++;

        auto resultIterator = result.begin();

        for (const auto& block : blocks)
        {
            dataBlock ^= block;
            dataBlock.encrypt<keyLength>(key);

            // copy the block to output
            for (const auto w : dataBlock.words)
                for (const auto b : w.bytes)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key, class InitVector>
    std::vector<std::uint8_t> encryptCbc(const Data& data, const Key& key,
                                         const InitVector& initVector)
    {
        return encryptCbc<keyLength>(std::begin(data), std::end(data), key, initVector);
    }

    template <std::size_t keyLength, class Iterator, class Key, class InitVector>
    std::vector<std::uint8_t> decryptCbc(Iterator begin, Iterator end, const Key& key,
                                         const InitVector& initVector)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        Block dataBlock;

        auto initVectorIterator = std::begin(initVector);
        for (auto& w : dataBlock.words)
            for (auto& b : w.bytes)
                b = *initVectorIterator++;

        auto dataIterator = begin;
        auto resultIterator = result.begin();

        for (auto& block : blocks)
        {
            block.decrypt<keyLength>(key);
            block ^= dataBlock;

            // copy the block to output
            for (const auto w : block.words)
                for (const auto b : w.bytes)
                    *resultIterator++ = b;

            // copy the data to data block
            for (auto& w : dataBlock.words)
                for (auto& b : w.bytes)
                    b = *dataIterator++;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key, class InitVector>
    std::vector<std::uint8_t> decryptCbc(const Data& data, const Key& key,
                                         const InitVector& initVector)
    {
        return decryptCbc<keyLength>(std::begin(data), std::end(data), key, initVector);
    }

    template <std::size_t keyLength, class Iterator, class Key, class InitVector>
    std::vector<std::uint8_t> encryptCfb(Iterator begin, Iterator end, const Key& key,
                                         const InitVector& initVector)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        Block encryptedBlock;

        auto initVectorIterator = std::begin(initVector);
        for (auto& w : encryptedBlock.words)
            for (auto& b : w.bytes)
                b = static_cast<std::uint8_t>(*initVectorIterator++);

        auto resultIterator = result.begin();

        for (const auto& block : blocks)
        {
            encryptedBlock.encrypt<keyLength>(key);
            encryptedBlock ^= block;

            // copy the block to output
            for (const auto w : encryptedBlock.words)
                for (const auto b : w.bytes)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key, class InitVector>
    std::vector<std::uint8_t> encryptCfb(const Data& data, const Key& key,
                                         const InitVector& initVector)
    {
        return encryptCfb<keyLength>(std::begin(data), std::end(data), key, initVector);
    }

    template <std::size_t keyLength, class Iterator, class Key, class InitVector>
    std::vector<std::uint8_t> decryptCfb(Iterator begin, Iterator end, const Key& key,
                                         const InitVector& initVector)
    {
        std::vector<Block> blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        Block decryptedBlock;

        auto initVectorIterator = std::begin(initVector);
        for (auto& w : decryptedBlock.words)
            for (auto& b : w.bytes)
                b = *initVectorIterator++;

        auto resultIterator = result.begin();

        for (const auto& block : blocks)
        {
            decryptedBlock.encrypt<keyLength>(key);
            decryptedBlock ^= block;

            // copy the block to output
            for (const auto w : decryptedBlock.words)
                for (const auto b : w.bytes)
                    *resultIterator++ = b;

            decryptedBlock = block;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key, class InitVector>
    std::vector<std::uint8_t> decryptCfb(const Data& data, const Key& key,
                                         const InitVector& initVector)
    {
        return decryptCfb<keyLength>(std::begin(data), std::end(data), key, initVector);
    }
}

#endif // AES_HPP
