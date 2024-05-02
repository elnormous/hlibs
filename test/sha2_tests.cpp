#include <cstddef>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "sha2.hpp"

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

TEST_CASE("SHA256", "[sha256]")
{
    SECTION("Hash")
    {
        const struct final
        {
            std::vector<std::uint8_t> data;
            std::string result;
        } testCases[] = {
            {{}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {{'0'}, "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, "9692e67b8378a6f6753f97782d458aa757e947eab2fbdf6b5c187b74561eb78f"},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "2d8f37e9c67a0bab28d6cfc4c5d92055c5c69bb131948e198fc62c85d9016008"},
            {{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
              'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
              'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
              'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
              'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'}, "a58bba2cc561bddbc30505632528c8aec0c367b859555462f52fe4476dc4d4bb"
            },
            {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            }, "8667e718294e9e0df1d30600ba3eeb201f764aad2dad72748643e4a285e1d1f7"}
        };

        for (const auto& testCase : testCases)
        {
            const auto h = sha256::hash(testCase.data);
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
            {}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        };

        const auto h = sha256::hash(testCase.data);
        const auto str = toString(h);
        REQUIRE(str == testCase.result);
    }
}
