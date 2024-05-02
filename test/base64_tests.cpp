#include <cstddef>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "base64.hpp"

TEST_CASE("Base64", "[base64]")
{
    const struct final
    {
        std::vector<std::uint8_t> data;
        bool padding;
        std::string result;
    } testCases[] = {
        {{}, true, ""},
        {{0xF8}, false, "+A"},
        {{0xFC}, false, "/A"},
        {{'0'}, false, "MA"},
        {{'0'}, true, "MA=="},
        {{'0', '0'}, false, "MDA"},
        {{'0', '0'}, true, "MDA="},
        {{'0', '0', '0'}, true, "MDAw"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, false, "VGVzdCAxMiE"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, true, "VGVzdCAxMiE="}
    };

    SECTION("Encoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto b = base64::encode(testCase.data, testCase.padding);
            REQUIRE(b == testCase.result);
        }
    }

    SECTION("Decoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto b = base64::decode(testCase.result);
            REQUIRE(b == testCase.data);
        }
    }

    SECTION("Invalid Symbol Error")
    {
        std::string data = {'@'};
        REQUIRE_THROWS_AS(base64::decode(data), base64::ParseError);
    }

    SECTION("Not Enough Data Error")
    {
        REQUIRE_THROWS_AS(base64::decode("M"), base64::ParseError);
    }

    SECTION("Byte")
    {
        const struct final
        {
            std::vector<std::byte> data;
            std::string result;
        } testCaseByte = {
            {}, ""
        };

        const auto b = base64::encode(testCaseByte.data);
        REQUIRE(b == testCaseByte.result);
    }
}

TEST_CASE("Base64 URL", "[base64]")
{
    const struct final
    {
        std::vector<std::uint8_t> data;
        bool padding;
        std::string result;
    } testCases[] = {
        {{}, true, ""},
        {{0xF8}, false, "-A"},
        {{0xFC}, false, "_A"},
        {{'0'}, false, "MA"},
        {{'0'}, true, "MA=="},
        {{'0', '0'}, false, "MDA"},
        {{'0', '0'}, true, "MDA="},
        {{'0', '0', '0'}, true, "MDAw"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, false, "VGVzdCAxMiE"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, true, "VGVzdCAxMiE="}
    };

    SECTION("Encoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto b = base64url::encode(testCase.data, testCase.padding);
            REQUIRE(b == testCase.result);
        }
    }

    SECTION("Decoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto b = base64url::decode(testCase.result);
            REQUIRE(b == testCase.data);
        }
    }

    SECTION("Invalid Symbol Error")
    {
        std::string data = {'@'};
        REQUIRE_THROWS_AS(base64url::decode(data), base64url::ParseError);
    }

    SECTION("Not Enough Data Error")
    {
        REQUIRE_THROWS_AS(base64url::decode("M"), base64url::ParseError);
    }

    SECTION("Byte")
    {
        const struct final
        {
            std::vector<std::byte> data;
            std::string result;
        } testCaseByte = {
            {}, ""
        };

        const auto b = base64url::encode(testCaseByte.data);
        REQUIRE(b == testCaseByte.result);
    }
}
