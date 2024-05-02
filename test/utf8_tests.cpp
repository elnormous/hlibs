#include <cstddef>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "utf8.hpp"

TEST_CASE("UTF8", "[utf8]")
{
    const struct final
    {
        std::vector<char32_t> data;
        std::string result;
    } testCases[] = {
        {{}, {}},
        {{0x01}, "\u0001"},
        {{0x61, 0xC3, 0x2020, 0x10102}, utf8::fromUtf32(std::vector<char32_t>{0x61, 0xC3, 0x2020, 0x10102})}
    };

    SECTION("Encoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto utf8String = utf8::fromUtf32(testCase.data);
            REQUIRE(utf8String == testCase.result);
        }
    }

    SECTION("Decoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto utf32String = utf8::toUtf32(testCase.result);

            REQUIRE(utf32String.length() == testCase.data.size());

            for (std::size_t i = 0; i < testCase.data.size(); ++i)
                REQUIRE(utf32String[i] == testCase.data[i]);
        }
    }
}
