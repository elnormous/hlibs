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
        std::string result;
    } testCases[] = {
        {{}, ""},
        {{'0'}, "MA=="},
        {{'0', '0'}, "MDA="},
        {{'0', '0', '0'}, "MDAw"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "VGVzdCAxMiE="},
        { { 0xFA, 0xFB }, "+vs="},
        { { 0xFA, 0xFB, 0xFC }, "+vv8"},
        { { 0xFA, 0xFB, 0xFC, 0xFD }, "+vv8/Q=="},
        { { 0xFA, 0xFB, 0xFC, 0xFD, 0xFE }, "+vv8/f4="},
        { { 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF }, "+vv8/f7/"},
        { { 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0xFF }, "+vv8/f7//w=="}
    };

    SECTION("Encoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto b = base64::encode(testCase.data);
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

TEST_CASE("Base64 wihtout padding", "[base64]")
{
    const struct final
    {
        std::vector<std::uint8_t> data;
        std::string result;
    } testCases[] = {
        {{0xF8}, "+A"},
        {{0xFC}, "/A"},
        {{'0'}, "MA"},
        {{'0', '0'}, "MDA"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "VGVzdCAxMiE"}
    };

    SECTION("Encoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto b = base64::encode(testCase.data, false);
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
}

TEST_CASE("Base64 errors", "[base64]")
{
    SECTION("Invalid Symbol Error")
    {
        std::string data = {'@'};
        REQUIRE_THROWS_AS(base64::decode(data), base64::ParseError);
    }

    SECTION("Not Enough Data Error")
    {
        REQUIRE_THROWS_AS(base64::decode("M"), base64::ParseError);
    }
}

TEST_CASE("Base64 URL", "[base64]")
{
    const struct final
    {
        std::vector<std::uint8_t> data;
        std::string result;
    } testCases[] = {
        {{}, ""},
        {{'0'}, "MA=="},
        {{'0', '0'}, "MDA="},
        {{'0', '0', '0'}, "MDAw"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "VGVzdCAxMiE="}
    };

    SECTION("Encoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto b = base64url::encode(testCase.data);
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

TEST_CASE("Base64 URL without padding", "[base64]")
{
    const struct final
    {
        std::vector<std::uint8_t> data;
        std::string result;
    } testCases[] = {
        {{0xF8}, "-A"},
        {{0xFC}, "_A"},
        {{'0'}, "MA"},
        {{'0', '0'}, "MDA"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "VGVzdCAxMiE"}
    };

    SECTION("Encoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto b = base64url::encode(testCase.data, false);
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
}

TEST_CASE("Base64 URL errors", "[base64]")
{
    SECTION("Invalid Symbol Error")
    {
        std::string data = {'@'};
        REQUIRE_THROWS_AS(base64url::decode(data), base64url::ParseError);
    }

    SECTION("Not Enough Data Error")
    {
        REQUIRE_THROWS_AS(base64url::decode("M"), base64url::ParseError);
    }
}
