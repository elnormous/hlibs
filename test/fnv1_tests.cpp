#include <cstddef>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "fnv1.hpp"

TEST_CASE("FNV1 32", "[fnv1]")
{
    SECTION("Hash")
    {
        const struct final
        {
            std::vector<std::uint8_t> data;
            std::uint32_t result;
        } testCases[] = {
            {{}, 0x811C9DC5},
            {{'0'}, 0x050C5D2F},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, 0x84F03A25},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, 0x296A37B7}
        };

        for (const auto& testCase : testCases)
        {
            const auto h = fnv1::hash<std::uint32_t>(testCase.data);
            REQUIRE(h == testCase.result);
        }
    }

    SECTION("Byte")
    {
        const struct final
        {
            std::vector<std::byte> data;
            std::uint32_t result;
        } testCase = {
            {}, 0x811C9DC5
        };

        const auto h = fnv1::hash<std::uint32_t>(testCase.data);
        REQUIRE(h == testCase.result);
    }
}

TEST_CASE("FNV1 64", "[fnv1]")
{
    SECTION("Hash")
    {
        const struct final
        {
            std::vector<std::uint8_t> data;
            uint64_t result;
        } testCases[] = {
            {{}, 0xCBF29CE484222325},
            {{'0'}, 0xAF63BD4C8601B7EF},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, 0xE30D93B97B04FE05},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, 0x98645A51CB3BECF7}
        };

        for (const auto& testCase : testCases)
        {
            const auto h = fnv1::hash<std::uint64_t>(testCase.data);
            REQUIRE(h == testCase.result);
        }
    }

    SECTION("Byte")
    {
        const struct final
        {
            std::vector<std::byte> data;
            uint64_t result;
        } testCase = {
            {}, 0xCBF29CE484222325
        };

        const auto h = fnv1::hash<std::uint64_t>(testCase.data);
        REQUIRE(h == testCase.result);
    }
}
