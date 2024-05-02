#include <cstddef>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "md5.hpp"

namespace
{
    template <class T>
    std::string toString(const T& v)
    {
        constexpr char digits[] = "0123456789abcdef";

        std::string result;
        for (const auto b : v)
        {
            result += digits[(b >> 4) & 0x0F];
            result += digits[b & 0x0F];
        }

        return result;
    }
}

TEST_CASE("MD5", "[md5]")
{
    SECTION("Hash")
    {
        const struct final
        {
            std::vector<std::uint8_t> data;
            std::string result;
        } testCases[] = {
            {{}, "d41d8cd98f00b204e9800998ecf8427e"},
            {{'0'}, "cfcd208495d565ef66e7dff9f98764da"},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, "b373e3ddc3438d7c10c76f3ad9d4c401"},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "9575b2604f8fd72edb743e95bd88b36d"},
            {{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
              'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
              'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
              'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
              'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'}, "46cf18a9b447991b450cad3facf5937e"
            },
            {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            }, "aabd2b2a451504e119a243d8e775fdad"}
        };

        for (const auto& testCase : testCases)
        {
            const auto h = md5::hash(testCase.data);
            const auto str = toString(h);
            REQUIRE(str == testCase.result);
        }
    }

    SECTION("Byte")
    {
        const struct final
        {
            std::vector<std::byte> data;
            std::string result;
        } testCase = {
            {}, "d41d8cd98f00b204e9800998ecf8427e"
        };

        const auto h = md5::hash(testCase.data);
        const auto str = toString(h);
        REQUIRE(str == testCase.result);
    }
}
