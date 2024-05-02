#include <cstddef>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "sha1.hpp"

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

TEST_CASE("SHA1", "[sha1]")
{
    SECTION("Hash")
    {
        const struct final
        {
            std::vector<std::uint8_t> data;
            std::string result;
        } testCases[] = {
            {{}, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
            {{'0'}, "b6589fc6ab0dc82cf12099d1c2d40ab994e8410c"},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, "9514e18b679622b8d59991a6298559cb03099d64"},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "ca593e38a74c94d97c9e0ead291340ae6a824060"},
            {{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
              'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
              'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
              'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
              'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'}, "57b5a033a37d0276ea970639cc3b63cab29442fe"
            },
            {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            }, "ffc6261e487efa8c7442069f71acfc4aa826993d"}
        };

        for (const auto& testCase : testCases)
        {
            const auto h = sha1::hash(testCase.data);
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
            {}, "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        };

        const auto h = sha1::hash(testCase.data);
        const auto str = toString(h);
        REQUIRE(str == testCase.result);
    }
}
