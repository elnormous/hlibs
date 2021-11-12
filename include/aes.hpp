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
        constexpr std::array<std::uint8_t, 256> sbox{
            0X63U, 0X7CU, 0X77U, 0X7BU, 0XF2U, 0X6BU, 0X6FU, 0XC5U,
            0X30U, 0X01U, 0X67U, 0X2BU, 0XFEU, 0XD7U, 0XABU, 0X76U,
            0XCAU, 0X82U, 0XC9U, 0X7DU, 0XFAU, 0X59U, 0X47U, 0XF0U,
            0XADU, 0XD4U, 0XA2U, 0XAFU, 0X9CU, 0XA4U, 0X72U, 0XC0U,
            0XB7U, 0XFDU, 0X93U, 0X26U, 0X36U, 0X3FU, 0XF7U, 0XCCU,
            0X34U, 0XA5U, 0XE5U, 0XF1U, 0X71U, 0XD8U, 0X31U, 0X15U,
            0X04U, 0XC7U, 0X23U, 0XC3U, 0X18U, 0X96U, 0X05U, 0X9AU,
            0X07U, 0X12U, 0X80U, 0XE2U, 0XEBU, 0X27U, 0XB2U, 0X75U,
            0X09U, 0X83U, 0X2CU, 0X1AU, 0X1BU, 0X6EU, 0X5AU, 0XA0U,
            0X52U, 0X3BU, 0XD6U, 0XB3U, 0X29U, 0XE3U, 0X2FU, 0X84U,
            0X53U, 0XD1U, 0X00U, 0XEDU, 0X20U, 0XFCU, 0XB1U, 0X5BU,
            0X6AU, 0XCBU, 0XBEU, 0X39U, 0X4AU, 0X4CU, 0X58U, 0XCFU,
            0XD0U, 0XEFU, 0XAAU, 0XFBU, 0X43U, 0X4DU, 0X33U, 0X85U,
            0X45U, 0XF9U, 0X02U, 0X7FU, 0X50U, 0X3CU, 0X9FU, 0XA8U,
            0X51U, 0XA3U, 0X40U, 0X8FU, 0X92U, 0X9DU, 0X38U, 0XF5U,
            0XBCU, 0XB6U, 0XDAU, 0X21U, 0X10U, 0XFFU, 0XF3U, 0XD2U,
            0XCDU, 0X0CU, 0X13U, 0XECU, 0X5FU, 0X97U, 0X44U, 0X17U,
            0XC4U, 0XA7U, 0X7EU, 0X3DU, 0X64U, 0X5DU, 0X19U, 0X73U,
            0X60U, 0X81U, 0X4FU, 0XDCU, 0X22U, 0X2AU, 0X90U, 0X88U,
            0X46U, 0XEEU, 0XB8U, 0X14U, 0XDEU, 0X5EU, 0X0BU, 0XDBU,
            0XE0U, 0X32U, 0X3AU, 0X0AU, 0X49U, 0X06U, 0X24U, 0X5CU,
            0XC2U, 0XD3U, 0XACU, 0X62U, 0X91U, 0X95U, 0XE4U, 0X79U,
            0XE7U, 0XC8U, 0X37U, 0X6DU, 0X8DU, 0XD5U, 0X4EU, 0XA9U,
            0X6CU, 0X56U, 0XF4U, 0XEAU, 0X65U, 0X7AU, 0XAEU, 0X08U,
            0XBAU, 0X78U, 0X25U, 0X2EU, 0X1CU, 0XA6U, 0XB4U, 0XC6U,
            0XE8U, 0XDDU, 0X74U, 0X1FU, 0X4BU, 0XBDU, 0X8BU, 0X8AU,
            0X70U, 0X3EU, 0XB5U, 0X66U, 0X48U, 0X03U, 0XF6U, 0X0EU,
            0X61U, 0X35U, 0X57U, 0XB9U, 0X86U, 0XC1U, 0X1DU, 0X9EU,
            0XE1U, 0XF8U, 0X98U, 0X11U, 0X69U, 0XD9U, 0X8EU, 0X94U,
            0X9BU, 0X1EU, 0X87U, 0XE9U, 0XCEU, 0X55U, 0X28U, 0XDFU,
            0X8CU, 0XA1U, 0X89U, 0X0DU, 0XBFU, 0XE6U, 0X42U, 0X68U,
            0X41U, 0X99U, 0X2DU, 0X0FU, 0XB0U, 0X54U, 0XBBU, 0X16U
        };

        // inverse substitution-box 16x16 matrix
        constexpr std::array<std::uint8_t, 256> inverseSbox{
            0X52U, 0X09U, 0X6AU, 0XD5U, 0X30U, 0X36U, 0XA5U, 0X38U,
            0XBFU, 0X40U, 0XA3U, 0X9EU, 0X81U, 0XF3U, 0XD7U, 0XFBU,
            0X7CU, 0XE3U, 0X39U, 0X82U, 0X9BU, 0X2FU, 0XFFU, 0X87U,
            0X34U, 0X8EU, 0X43U, 0X44U, 0XC4U, 0XDEU, 0XE9U, 0XCBU,
            0X54U, 0X7BU, 0X94U, 0X32U, 0XA6U, 0XC2U, 0X23U, 0X3DU,
            0XEEU, 0X4CU, 0X95U, 0X0BU, 0X42U, 0XFAU, 0XC3U, 0X4EU,
            0X08U, 0X2EU, 0XA1U, 0X66U, 0X28U, 0XD9U, 0X24U, 0XB2U,
            0X76U, 0X5BU, 0XA2U, 0X49U, 0X6DU, 0X8BU, 0XD1U, 0X25U,
            0X72U, 0XF8U, 0XF6U, 0X64U, 0X86U, 0X68U, 0X98U, 0X16U,
            0XD4U, 0XA4U, 0X5CU, 0XCCU, 0X5DU, 0X65U, 0XB6U, 0X92U,
            0X6CU, 0X70U, 0X48U, 0X50U, 0XFDU, 0XEDU, 0XB9U, 0XDAU,
            0X5EU, 0X15U, 0X46U, 0X57U, 0XA7U, 0X8DU, 0X9DU, 0X84U,
            0X90U, 0XD8U, 0XABU, 0X00U, 0X8CU, 0XBCU, 0XD3U, 0X0AU,
            0XF7U, 0XE4U, 0X58U, 0X05U, 0XB8U, 0XB3U, 0X45U, 0X06U,
            0XD0U, 0X2CU, 0X1EU, 0X8FU, 0XCAU, 0X3FU, 0X0FU, 0X02U,
            0XC1U, 0XAFU, 0XBDU, 0X03U, 0X01U, 0X13U, 0X8AU, 0X6BU,
            0X3AU, 0X91U, 0X11U, 0X41U, 0X4FU, 0X67U, 0XDCU, 0XEAU,
            0X97U, 0XF2U, 0XCFU, 0XCEU, 0XF0U, 0XB4U, 0XE6U, 0X73U,
            0X96U, 0XACU, 0X74U, 0X22U, 0XE7U, 0XADU, 0X35U, 0X85U,
            0XE2U, 0XF9U, 0X37U, 0XE8U, 0X1CU, 0X75U, 0XDFU, 0X6EU,
            0X47U, 0XF1U, 0X1AU, 0X71U, 0X1DU, 0X29U, 0XC5U, 0X89U,
            0X6FU, 0XB7U, 0X62U, 0X0EU, 0XAAU, 0X18U, 0XBEU, 0X1BU,
            0XFCU, 0X56U, 0X3EU, 0X4BU, 0XC6U, 0XD2U, 0X79U, 0X20U,
            0X9AU, 0XDBU, 0XC0U, 0XFEU, 0X78U, 0XCDU, 0X5AU, 0XF4U,
            0X1FU, 0XDDU, 0XA8U, 0X33U, 0X88U, 0X07U, 0XC7U, 0X31U,
            0XB1U, 0X12U, 0X10U, 0X59U, 0X27U, 0X80U, 0XECU, 0X5FU,
            0X60U, 0X51U, 0X7FU, 0XA9U, 0X19U, 0XB5U, 0X4AU, 0X0DU,
            0X2DU, 0XE5U, 0X7AU, 0X9FU, 0X93U, 0XC9U, 0X9CU, 0XEFU,
            0XA0U, 0XE0U, 0X3BU, 0X4DU, 0XAEU, 0X2AU, 0XF5U, 0XB0U,
            0XC8U, 0XEBU, 0XBBU, 0X3CU, 0X83U, 0X53U, 0X99U, 0X61U,
            0X17U, 0X2BU, 0X04U, 0X7EU, 0XBAU, 0X77U, 0XD6U, 0X26U,
            0XE1U, 0X69U, 0X14U, 0X63U, 0X55U, 0X21U, 0X0CU, 0X7DU
        };

        // number of rounds (Nr)
        template <std::size_t keyLength> constexpr std::size_t roundCount = keyLength / 32U + 6U;

        // number of 32-bit words in cipher key (Nk)
        template <std::size_t keyLength> constexpr std::size_t keyWordCount = keyLength / 32U;

        constexpr std::size_t blockWordCount = 4; // number of words in an AES block (Nb)
        constexpr std::size_t blockByteCount = 4 * blockWordCount;
        constexpr std::size_t wordByteCount = 4;

        using Word = std::array<std::uint8_t, wordByteCount>;
        using Block = std::array<Word, blockWordCount>;

        [[nodiscard]] inline Word operator^(const Word& first, const Word& second) noexcept
        {
            Word result = first;
            for (std::size_t i = 0; i < wordByteCount; ++i)
                result[i] ^= second[i];
            return result;
        }

        inline Word& operator^=(Word& first, const Word& second) noexcept
        {
            for (std::size_t i = 0; i < wordByteCount; ++i)
                first[i] ^= second[i];
            return first;
        }

        inline void sub(Word& word) noexcept
        {
            for (auto& byte : word) byte = sbox[byte];
        }

        inline void intSub(Word& word) noexcept
        {
            for (auto& byte : word) byte = inverseSbox[byte];
        }

        inline void rot(Word& word) noexcept
        {
            const auto c = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = c;
        }

        using RoundKey = std::array<Word, 4>;
        template <std::size_t keyLength>
        using RoundKeys = std::array<RoundKey, roundCount<keyLength> + 1>;

        inline std::uint8_t mulBytes(std::uint8_t a, std::uint8_t b) noexcept
        {
            std::uint8_t c = 0;
            for (std::size_t i = 0; i < 8; ++i)
            {
                if (b & 0x01)
                {
                    std::uint8_t d = a;
                    for (std::size_t j = 0; j < i; ++j)
                        d = static_cast<std::uint8_t>((d << 1) ^ (d & 0x80 ? 0x1B : 0x00));

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
            for (std::size_t i = 0; i < blockWordCount * (roundCount<keyLength> + 1); ++i)
            {
                if (i < keyWordCount<keyLength>)
                {
                    roundKeys[i / 4][i % 4][0] = static_cast<std::uint8_t>(key[i * 4 + 0]);
                    roundKeys[i / 4][i % 4][1] = static_cast<std::uint8_t>(key[i * 4 + 1]);
                    roundKeys[i / 4][i % 4][2] = static_cast<std::uint8_t>(key[i * 4 + 2]);
                    roundKeys[i / 4][i % 4][3] = static_cast<std::uint8_t>(key[i * 4 + 3]);
                }
                else
                {
                    const std::size_t previousWordIndex = i - 1;
                    Word temp = roundKeys[previousWordIndex / 4][previousWordIndex % 4];

                    if (i % keyWordCount<keyLength> == 0)
                    {
                        rot(temp);
                        sub(temp);
                        const Word rCon{getRoundConstant(i / keyWordCount<keyLength>), 0, 0, 0};
                        temp ^= rCon;
                    }
                    else if (keyWordCount<keyLength> > 6 && i % keyWordCount<keyLength> == 4)
                        sub(temp);

                    const std::size_t beforeKeyIndex = i - keyWordCount<keyLength>;
                    roundKeys[i / 4][i % 4] = roundKeys[beforeKeyIndex / 4][beforeKeyIndex % 4] ^ temp;
                }
            }
        }

        [[nodiscard]] inline Block operator^(const Block& first, const Block& second) noexcept
        {
            Block result = first;
            for (std::size_t i = 0; i < blockWordCount; ++i)
                result[i] ^= second[i];

            return result;
        }

        inline Block& operator^=(Block& first, const Block& second) noexcept
        {
            for (std::size_t i = 0; i < blockWordCount; ++i)
                first[i] ^= second[i];

            return first;
        }

        inline void subBytes(Block& block) noexcept
        {
            for (std::size_t i = 0; i < wordByteCount; ++i)
                sub(block[i]);
        }

        inline void invSubBytes(Block& block) noexcept
        {
            for (std::size_t i = 0; i < wordByteCount; ++i)
                intSub(block[i]);
        }

        inline void shiftRow(Block& block, const std::size_t i, const std::size_t n) noexcept
        {
            for (std::size_t k = 0; k < n; k++)
                rot(block[i]);
        }

        inline void shiftRows(Block& block) noexcept
        {
            shiftRow(block, 1, 1);
            shiftRow(block, 2, 2);
            shiftRow(block, 3, 3);
        }

        inline void invShiftRows(Block& block) noexcept
        {
            shiftRow(block, 1, blockWordCount - 1);
            shiftRow(block, 2, blockWordCount - 2);
            shiftRow(block, 3, blockWordCount - 3);
        }

        inline void mixColumns(Block& block) noexcept
        {
            for (std::size_t j = 0; j < blockWordCount; ++j)
            {
                const Word s{
                    block[0][j],
                    block[1][j],
                    block[2][j],
                    block[3][j]
                };

                const Word s1{
                    static_cast<std::uint8_t>(mulBytes(0x02, s[0]) ^ mulBytes(0x03, s[1]) ^ s[2] ^ s[3]),
                    static_cast<std::uint8_t>(s[0] ^ mulBytes(0x02, s[1]) ^ mulBytes(0x03, s[2]) ^ s[3]),
                    static_cast<std::uint8_t>(s[0] ^ s[1] ^ mulBytes(0x02, s[2]) ^ mulBytes(0x03, s[3])),
                    static_cast<std::uint8_t>(mulBytes(0x03, s[0]) ^ s[1] ^ s[2] ^ mulBytes(0x02, s[3]))
                };

                for (std::size_t i = 0; i < wordByteCount; ++i)
                    block[i][j] = s1[i];
          }
        }

        inline void invMixColumns(Block& block) noexcept
        {
            for (std::size_t j = 0; j < blockWordCount; ++j)
            {
                const Word s{
                    block[0][j],
                    block[1][j],
                    block[2][j],
                    block[3][j]
                };

                const Word s1{
                    static_cast<std::uint8_t>(mulBytes(0x0E, s[0]) ^ mulBytes(0x0B, s[1]) ^ mulBytes(0x0D, s[2]) ^ mulBytes(0x09, s[3])),
                    static_cast<std::uint8_t>(mulBytes(0x09, s[0]) ^ mulBytes(0x0E, s[1]) ^ mulBytes(0x0B, s[2]) ^ mulBytes(0x0D, s[3])),
                    static_cast<std::uint8_t>(mulBytes(0x0D, s[0]) ^ mulBytes(0x09, s[1]) ^ mulBytes(0x0E, s[2]) ^ mulBytes(0x0B, s[3])),
                    static_cast<std::uint8_t>(mulBytes(0x0B, s[0]) ^ mulBytes(0x0D, s[1]) ^ mulBytes(0x09, s[2]) ^ mulBytes(0x0E, s[3]))
                };

                for (std::size_t i = 0; i < wordByteCount; ++i)
                    block[i][j] = s1[i];
            }
        }

        inline void addRoundKey(Block& block, const RoundKey& roundKey) noexcept
        {
            for (std::size_t i = 0; i < blockWordCount; ++i)
                for (std::size_t j = 0; j < wordByteCount; ++j)
                    block[i][j] ^= roundKey[j][i];
        }

        template <std::size_t keyLength, class Key>
        void encrypt(Block& block, const Key& key) noexcept
        {
            RoundKeys<keyLength> roundKeys;
            expandKey<keyLength>(key, roundKeys);

            Block state;
            for (std::size_t i = 0; i < wordByteCount; ++i)
                for (std::size_t j = 0; j < blockWordCount; ++j)
                    state[i][j] = block[j][i];

            addRoundKey(state, roundKeys[0]);

            for (std::size_t round = 1; round <= roundCount<keyLength> - 1; ++round)
            {
                subBytes(state);
                shiftRows(state);
                mixColumns(state);
                addRoundKey(state, roundKeys[round]);
            }

            subBytes(state);
            shiftRows(state);
            addRoundKey(state, roundKeys[roundCount<keyLength>]);

            for (std::size_t i = 0; i < wordByteCount; ++i)
                for (std::size_t j = 0; j < blockWordCount; ++j)
                    block[j][i] = state[i][j];
        }

        template <std::size_t keyLength, class Key>
        void decrypt(Block& block, const Key& key) noexcept
        {
            RoundKeys<keyLength> roundKeys;
            expandKey<keyLength>(key, roundKeys);

            Block state;
            for (std::size_t i = 0; i < wordByteCount; ++i)
                for (std::size_t j = 0; j < blockWordCount; ++j)
                    state[i][j] = block[j][i];

            addRoundKey(state, roundKeys[roundCount<keyLength>]);

            for (std::size_t round = roundCount<keyLength> - 1; round >= 1; --round)
            {
                invSubBytes(state);
                invShiftRows(state);
                addRoundKey(state, roundKeys[round]);
                invMixColumns(state);
            }

            invSubBytes(state);
            invShiftRows(state);
            addRoundKey(state, roundKeys[0]);

            for (std::size_t i = 0; i < wordByteCount; ++i)
                for (std::size_t j = 0; j < blockWordCount; ++j)
                    block[j][i] = state[i][j];
        }

        template <class Iterator>
        [[nodiscard]]
        std::vector<Block> convertToBlocks(Iterator begin, Iterator end)
        {
            std::vector<Block> result;

            std::size_t byte = 0;
            for (auto i = begin; i != end; ++i)
            {
                if (result.size() < byte / blockByteCount + 1)
                    result.resize(byte / blockByteCount + 1);

                Block& block = result[byte / blockByteCount];
                Word& word = block[(byte / wordByteCount) % blockWordCount];
                word[byte % wordByteCount] = static_cast<std::uint8_t>(*i);
                ++byte;
            }

            return result;
        }
    }

    template <std::size_t keyLength, class Iterator, class Key>
    [[nodiscard]]
    std::vector<std::uint8_t> encryptEcb(Iterator begin, Iterator end, const Key& key)
    {
        auto blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        auto resultIterator = result.begin();

        for (auto& block : blocks)
        {
            encrypt<keyLength>(block, key);

            // copy the block to output
            for (const auto w : block)
                for (const auto b : w)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key>
    [[nodiscard]]
    std::vector<std::uint8_t> encryptEcb(const Data& data, const Key& key)
    {
        using std::begin, std::end; // add std::begin and std::end to lookup
        return encryptEcb<keyLength>(begin(data), end(data), key);
    }

    template <std::size_t keyLength, class Iterator, class Key>
    [[nodiscard]]
    std::vector<std::uint8_t> decryptEcb(Iterator begin, Iterator end, const Key& key)
    {
        auto blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        auto resultIterator = result.begin();

        for (auto& block : blocks)
        {
            decrypt<keyLength, Key>(block, key);

            // copy the block to output
            for (const auto word : block)
                for (const auto byte : word)
                    *resultIterator++ = byte;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key>
    [[nodiscard]]
    std::vector<std::uint8_t> decryptEcb(const Data& data, const Key& key)
    {
        using std::begin, std::end; // add std::begin and std::end to lookup
        return decryptEcb<keyLength>(begin(data), end(data), key);
    }

    template <std::size_t keyLength, class Iterator, class Key, class InitVector>
    [[nodiscard]]
    std::vector<std::uint8_t> encryptCbc(Iterator begin, Iterator end, const Key& key,
                                         const InitVector& initVector)
    {
        const auto blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        Block dataBlock;

        auto initVectorIterator = std::begin(initVector);
        for (auto& w : dataBlock)
            for (auto& b : w)
                b = *initVectorIterator++;

        auto resultIterator = result.begin();

        for (const auto& block : blocks)
        {
            dataBlock ^= block;
            encrypt<keyLength>(dataBlock, key);

            // copy the block to output
            for (const auto w : dataBlock)
                for (const auto b : w)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key, class InitVector>
    [[nodiscard]]
    std::vector<std::uint8_t> encryptCbc(const Data& data, const Key& key,
                                         const InitVector& initVector)
    {
        using std::begin, std::end; // add std::begin and std::end to lookup
        return encryptCbc<keyLength>(begin(data), end(data), key, initVector);
    }

    template <std::size_t keyLength, class Iterator, class Key, class InitVector>
    [[nodiscard]]
    std::vector<std::uint8_t> decryptCbc(Iterator begin, Iterator end, const Key& key,
                                         const InitVector& initVector)
    {
        auto blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        Block dataBlock;

        auto initVectorIterator = std::begin(initVector);
        for (auto& w : dataBlock)
            for (auto& b : w)
                b = *initVectorIterator++;

        auto dataIterator = begin;
        auto resultIterator = result.begin();

        for (auto& block : blocks)
        {
            decrypt<keyLength>(block, key);
            block ^= dataBlock;

            // copy the block to output
            for (const auto w : block)
                for (const auto b : w)
                    *resultIterator++ = b;

            // copy the data to data block
            for (auto& w : dataBlock)
                for (auto& b : w)
                    b = *dataIterator++;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key, class InitVector>
    [[nodiscard]]
    std::vector<std::uint8_t> decryptCbc(const Data& data, const Key& key,
                                         const InitVector& initVector)
    {
        using std::begin, std::end; // add std::begin and std::end to lookup
        return decryptCbc<keyLength>(begin(data), end(data), key, initVector);
    }

    template <std::size_t keyLength, class Iterator, class Key, class InitVector>
    [[nodiscard]]
    std::vector<std::uint8_t> encryptCfb(Iterator begin, Iterator end, const Key& key,
                                         const InitVector& initVector)
    {
        const auto blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        Block encryptedBlock;

        auto initVectorIterator = std::begin(initVector);
        for (auto& w : encryptedBlock)
            for (auto& b : w)
                b = static_cast<std::uint8_t>(*initVectorIterator++);

        auto resultIterator = result.begin();

        for (const auto& block : blocks)
        {
            encrypt<keyLength>(encryptedBlock, key);
            encryptedBlock ^= block;

            // copy the block to output
            for (const auto w : encryptedBlock)
                for (const auto b : w)
                    *resultIterator++ = b;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key, class InitVector>
    [[nodiscard]]
    std::vector<std::uint8_t> encryptCfb(const Data& data, const Key& key,
                                         const InitVector& initVector)
    {
        return encryptCfb<keyLength>(std::begin(data), std::end(data), key, initVector);
    }

    template <std::size_t keyLength, class Iterator, class Key, class InitVector>
    [[nodiscard]]
    std::vector<std::uint8_t> decryptCfb(Iterator begin, Iterator end, const Key& key,
                                         const InitVector& initVector)
    {
        const auto blocks = convertToBlocks(begin, end);
        std::vector<std::uint8_t> result(blocks.size() * blockByteCount);

        Block decryptedBlock;

        auto initVectorIterator = std::begin(initVector);
        for (auto& w : decryptedBlock)
            for (auto& b : w)
                b = *initVectorIterator++;

        auto resultIterator = result.begin();

        for (const auto& block : blocks)
        {
            encrypt<keyLength>(decryptedBlock, key);
            decryptedBlock ^= block;

            // copy the block to output
            for (const auto w : decryptedBlock)
                for (const auto b : w)
                    *resultIterator++ = b;

            decryptedBlock = block;
        }

        return result;
    }

    template <std::size_t keyLength, class Data, class Key, class InitVector>
    [[nodiscard]]
    std::vector<std::uint8_t> decryptCfb(const Data& data, const Key& key,
                                         const InitVector& initVector)
    {
        using std::begin, std::end; // add std::begin and std::end to lookup
        return decryptCfb<keyLength>(begin(data), end(data), key, initVector);
    }
}

#endif // AES_HPP
