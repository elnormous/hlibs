#include <cstddef>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "crc.hpp"

TEST_CASE("CRC8", "[crc]")
{
    SECTION("Check")
    {
        const struct final
        {
            std::vector<std::uint8_t> data;
            std::uint8_t result;
        } testCases[] = {
            {{}, 0x00},
            {{'0'}, 0x90},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, 0x35},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, 0x20}
        };

        for (const auto& testCase : testCases)
        {
            const auto c = crc::generate<std::uint8_t>(testCase.data);
            REQUIRE(c == testCase.result);
        }
    }

    SECTION("Byte")
    {
        const struct final
        {
            std::vector<std::byte> data;
            std::uint8_t result;
        } testCase = {
            {}, 0x00
        };

        const auto c = crc::generate<std::uint8_t>(testCase.data);
        REQUIRE(c == testCase.result);
    }
}

TEST_CASE("CRC16", "[crc]")
{
    SECTION("Check")
    {
        const struct final
        {
            std::vector<std::uint8_t> data;
            std::uint16_t result;
        } testCases[] = {
            {{}, 0x00},
            {{'0'}, 0x3183},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, 0x681A},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, 0x6B56}
        };

        for (const auto& testCase : testCases)
        {
            const auto c = crc::generate<std::uint16_t>(testCase.data);
            REQUIRE(c == testCase.result);
        }
    }

    SECTION("Byte")
    {
        const struct final
        {
            std::vector<std::byte> data;
            std::uint16_t result;
        } testCase = {
            {}, 0x00
        };

        const auto c = crc::generate<std::uint16_t>(testCase.data);
        REQUIRE(c == testCase.result);
    }
}

TEST_CASE("CRC32", "[crc]")
{
    SECTION("Check")
    {
        const struct final
        {
            std::vector<std::uint8_t> data;
            std::uint32_t result;
        } testCases[] = {
            {{}, 0x00000000U},
            {{'0'}, 0xF4DBDF21U},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, 0x963FBB8EU},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, 0xC8A61CC1}
        };

        for (const auto& testCase : testCases)
        {
            const auto c = crc::generate<std::uint32_t>(testCase.data);
            REQUIRE(c == testCase.result);
        }
    }

    SECTION("Byte")
    {
        const struct final
        {
            std::vector<std::byte> data;
            std::uint32_t result;
        } testCase = {
            {}, 0x00000000U
        };

        const auto c = crc::generate<std::uint32_t>(testCase.data);
        REQUIRE(c == testCase.result);
    }
}
