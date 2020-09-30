#include <cstddef>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "aes.hpp"
#include "base64.hpp"
#include "crc.hpp"
#include "fnv1.hpp"
#include "md5.hpp"
#include "sha1.hpp"
#include "sha2.hpp"
#include "utf8.hpp"
#include "uuid.hpp"

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

constexpr std::uint8_t hexToInt(const char hex)
{
    return (hex >= '0' && hex <= '9') ? static_cast<std::uint8_t>(hex - '0') :
        (hex >= 'a' && hex <='f') ? static_cast<std::uint8_t>(hex - 'a' + 10) :
        (hex >= 'A' && hex <='F') ? static_cast<std::uint8_t>(hex - 'A' + 10) :
        throw std::out_of_range("Invalid hex digit");
}

TEST_CASE("AES", "[aes]")
{
    constexpr std::uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    constexpr std::uint8_t initVector[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    SECTION("ECB")
    {
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> testCasesEcb[] = {
            {}, {},
            {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0xF2, 0x90, 0x0, 0xB6, 0x2A, 0x49, 0x9F, 0xD0, 0xA9, 0xF3, 0x9A, 0x6A, 0xDD, 0x2E, 0x77, 0x80}},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, {0x14, 0x8C, 0x38, 0x74, 0x56, 0xF9, 0x88, 0xAE, 0x89, 0xE6, 0x36, 0x48, 0xC2, 0xC1, 0xD2, 0x3B}},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '.'}, {0xA, 0x47, 0x3A, 0xA5, 0xAC, 0x90, 0x6E, 0xA, 0xB4, 0x4E, 0xB8, 0xEE, 0x32, 0x53, 0x18, 0xA2, 0xC2, 0x51, 0x96, 0xD2, 0x7C, 0xA7, 0x9D, 0xB7, 0x73, 0xA1, 0x9, 0x94, 0x7D, 0x7A, 0x4F, 0x45}}
        };

        for (const auto& testCase : testCasesEcb)
        {
            const auto e = aes::encryptEcb<256>(testCase.first, key);
            REQUIRE(e == testCase.second);

            const auto d = aes::decryptEcb<256>(e, key);
            REQUIRE(std::equal(testCase.first.begin(), testCase.first.end(), d.begin()));
        }
    }

    SECTION("CBC")
    {
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> testCasesCbc[] = {
            {{}, {}},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, {0x9A, 0x10, 0x85, 0x12, 0x4D, 0x37, 0xA9, 0xF6, 0xDB, 0xA6, 0x2E, 0x5E, 0x97, 0x79, 0x41, 0x90}},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '.'}, {0x1, 0x3, 0x3E, 0xC1, 0xC3, 0x49, 0x9F, 0x87, 0x78, 0xE3, 0x8F, 0xB0, 0xC8, 0x46, 0xB2, 0x18, 0xDA, 0x47, 0xEB, 0xE9, 0xDF, 0x12, 0x95, 0x5, 0xEE, 0x87, 0x18, 0x81, 0xD3, 0xF4, 0xFF, 0xEA}}
        };

        for (const auto& testCase : testCasesCbc)
        {
            const auto e = aes::encryptCbc<256>(testCase.first, key, initVector);
            REQUIRE(e == testCase.second);

            const auto d = aes::decryptCbc<256>(e, key, initVector);
            REQUIRE(std::equal(testCase.first.begin(), testCase.first.end(), d.begin()));
        }
    }

    SECTION("CFB")
    {
        const std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> testCasesCfb[] = {
            {{}, {}},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, {0xBD, 0xFC, 0x97, 0x69, 0x6C, 0x96, 0x42, 0xFB, 0x53, 0x87, 0x11, 0x7B, 0x5D, 0x8F, 0x57, 0xEE}},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '.'}, {0xBD, 0xFC, 0x97, 0x69, 0x6C, 0x96, 0x42, 0xFB, 0x62, 0xB5, 0x22, 0x4F, 0x68, 0xB9, 0x60, 0xD6, 0xD0, 0x7C, 0xB4, 0x4B, 0xF5, 0xD5, 0xD5, 0xF3, 0x7D, 0x0B, 0xFC, 0xB3, 0xCB, 0xF3, 0x49, 0x94}}
        };

        for (const auto& testCase : testCasesCfb)
        {
            const auto e = aes::encryptCfb<256>(testCase.first, key, initVector);
            REQUIRE(e == testCase.second);

            const auto d = aes::decryptCfb<256>(e, key, initVector);
            REQUIRE(std::equal(testCase.first.begin(), testCase.first.end(), d.begin()));
        }
    }

    SECTION("Byte")
    {
        constexpr std::byte keyByte[] = {
            std::byte(0x00), std::byte(0x01), std::byte(0x02), std::byte(0x03), std::byte(0x04), std::byte(0x05), std::byte(0x06), std::byte(0x07),
            std::byte(0x08), std::byte(0x09), std::byte(0x0A), std::byte(0x0B), std::byte(0x0C), std::byte(0x0D), std::byte(0x0E), std::byte(0x0F),
            std::byte(0x10), std::byte(0x11), std::byte(0x12), std::byte(0x13), std::byte(0x14), std::byte(0x15), std::byte(0x16), std::byte(0x17),
            std::byte(0x18), std::byte(0x19), std::byte(0x1A), std::byte(0x1B), std::byte(0x1C), std::byte(0x1D), std::byte(0x1E), std::byte(0x1F)
        };

        constexpr std::byte initVectorByte[] = {
            std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF),
            std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF), std::byte(0xFF)
        };

        const std::pair<std::vector<std::byte>, std::vector<std::uint8_t>> testCasesByte = {
            {}, {}
        };

        const auto e = aes::encryptCfb<256>(testCasesByte.first, keyByte, initVectorByte);
        REQUIRE(e == testCasesByte.second);
    }
}

TEST_CASE("Base64", "[base64]")
{
    const std::pair<std::vector<std::uint8_t>, std::string> testCases[] = {
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
            const auto b = base64::encode(testCase.first);
            REQUIRE(b == testCase.second);
        }
    }

    SECTION("Decoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto b = base64::decode(testCase.second);
            REQUIRE(b == testCase.first);
        }
    }

    SECTION("Error")
    {
        REQUIRE_THROWS_AS(base64::decode("@"), base64::ParseError);
    }

    SECTION("Byte")
    {
        const std::pair<std::vector<std::byte>, std::string> testCaseByte = {
            {}, ""
        };

        const auto b = base64::encode(testCaseByte.first);
        REQUIRE(b == testCaseByte.second);
    }
}

TEST_CASE("CRC8", "[crc8]")
{
    SECTION("Check")
    {
        const std::pair<std::vector<std::uint8_t>, std::uint8_t> testCases[] = {
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
            const auto c = crc::generate<std::uint8_t>(testCase.first);
            REQUIRE(c == testCase.second);
        }
    }

    SECTION("Byte")
    {
        const std::pair<std::vector<std::byte>, std::uint8_t> testCase = {
            {}, 0x00
        };

        const auto c = crc::generate<std::uint8_t>(testCase.first);
        REQUIRE(c == testCase.second);
    }
}

TEST_CASE("CRC16", "[crc16]")
{
    SECTION("Check")
    {
        const std::pair<std::vector<std::uint8_t>, std::uint16_t> testCases[] = {
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
            const auto c = crc::generate<std::uint16_t>(testCase.first);
            REQUIRE(c == testCase.second);
        }
    }

    SECTION("Byte")
    {
        const std::pair<std::vector<std::byte>, std::uint16_t> testCase = {
            {}, 0x00
        };

        const auto c = crc::generate<std::uint16_t>(testCase.first);
        REQUIRE(c == testCase.second);
    }
}

TEST_CASE("CRC32", "[crc32]")
{
    SECTION("Check")
    {
        const std::pair<std::vector<std::uint8_t>, std::uint32_t> testCases[] = {
            {{}, 0x00000000U},
            {{'0'}, 0xF4DBDF21U},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, 0x963FBB8EU},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, 0xc8a61cc1}
        };

        for (const auto& testCase : testCases)
        {
            const auto c = crc::generate<std::uint32_t>(testCase.first);
            REQUIRE(c == testCase.second);
        }
    }

    SECTION("Byte")
    {
        const std::pair<std::vector<std::byte>, std::uint32_t> testCase = {
            {}, 0x00000000U
        };

        const auto c = crc::generate<std::uint32_t>(testCase.first);
        REQUIRE(c == testCase.second);
    }
}

TEST_CASE("FNV1 32", "[fnv132]")
{
    const std::pair<std::vector<std::uint8_t>, std::uint32_t> testCases[] = {
        {{}, 0x811c9dc5},
        {{'0'}, 0x050c5d2f},
        {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, 0x84f03a25},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, 0x296a37b7}
    };

    for (const auto& testCase : testCases)
    {
        const auto h = fnv1::hash<std::uint32_t>(testCase.first);
        REQUIRE(h == testCase.second);
    }
}

TEST_CASE("FNV1 64", "[fnv164]")
{
    const std::pair<std::vector<std::uint8_t>, std::uint64_t> testCases[] = {
        {{}, 0xcbf29ce484222325},
        {{'0'}, 0xaf63bd4c8601b7ef},
        {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, 0xe30d93b97b04fe05},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, 0x98645a51cb3becf7}
    };

    for (const auto& testCase : testCases)
    {
        const auto h = fnv1::hash<std::uint64_t>(testCase.first);
        REQUIRE(h == testCase.second);
    }
}

TEST_CASE("MD5", "[md5]")
{
    const std::pair<std::vector<std::uint8_t>, std::string> testCases[] = {
        {{}, "d41d8cd98f00b204e9800998ecf8427e"},
        {{'0'}, "cfcd208495d565ef66e7dff9f98764da"},
        {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, "b373e3ddc3438d7c10c76f3ad9d4c401"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "9575b2604f8fd72edb743e95bd88b36d"},
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
        const auto d = md5::generate(testCase.first);
        const auto str = toString(d);
        REQUIRE(str == testCase.second);
    }
}

TEST_CASE("SHA1", "[sha1]")
{
    const std::pair<std::vector<std::uint8_t>, std::string> testCases[] = {
        {{}, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {{'0'}, "b6589fc6ab0dc82cf12099d1c2d40ab994e8410c"},
        {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, "9514e18b679622b8d59991a6298559cb03099d64"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "ca593e38a74c94d97c9e0ead291340ae6a824060"},
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
        const auto h = sha1::hash(testCase.first);
        const auto str = toString(h);
        REQUIRE(str == testCase.second);
    }
}

TEST_CASE("SHA256", "[sha256]")
{
    const std::pair<std::vector<std::uint8_t>, std::string> testCases[] = {
        {{}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {{'0'}, "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"},
        {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
          '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, "9692e67b8378a6f6753f97782d458aa757e947eab2fbdf6b5c187b74561eb78f"},
        {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "2d8f37e9c67a0bab28d6cfc4c5d92055c5c69bb131948e198fc62c85d9016008"},
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
        const auto h = sha256::hash(testCase.first);
        const auto str = toString(h);
        REQUIRE(str == testCase.second);
    }
}

TEST_CASE("UTF8", "[utf8]")
{
    const std::pair<std::vector<char32_t>, std::string> testCases[] = {
        {{}, {}},
        {{0x01}, "\u0001"},
        {{0x61, 0xC3, 0x2020, 0x10102}, utf8::fromUtf32(std::vector<char32_t>{0x61, 0xC3, 0x2020, 0x10102})}
    };

    SECTION("Encoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto utf8String = utf8::fromUtf32(testCase.first);
            REQUIRE(utf8String == testCase.second);
        }
    }

    SECTION("Decoding")
    {
        for (const auto& testCase : testCases)
        {
            const auto utf32String = utf8::toUtf32(testCase.second);

            REQUIRE(utf32String.length() == testCase.first.size());

            for (std::size_t i = 0; i < testCase.first.size(); ++i)
                REQUIRE(utf32String[i] == testCase.first[i]);
        }
    }
}

TEST_CASE("UUID", "[uuid]")
{
    const auto a = uuid::generate<std::array<std::uint8_t, 16>>();

    REQUIRE(a[6] >> 4 == 4);
    REQUIRE((a[8] & 0xC0U) == 0x80U);

    const auto s = uuid::generate<std::string>();
    REQUIRE(s[14] == '4');
    REQUIRE((hexToInt(s[19]) & 0x0CU) == 0x08U);
}
