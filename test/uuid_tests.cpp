#include <cstddef>
#include <string>
#include <vector>
#include "catch2/catch.hpp"
#include "uuid.hpp"

namespace
{
    constexpr std::uint8_t hexToInt(const char hex)
    {
        return (hex >= '0' && hex <= '9') ? static_cast<std::uint8_t>(hex - '0') :
            (hex >= 'a' && hex <='f') ? static_cast<std::uint8_t>(hex - 'a' + 10) :
            (hex >= 'A' && hex <='F') ? static_cast<std::uint8_t>(hex - 'A' + 10) :
            throw std::out_of_range("Invalid hex digit");
    }
}

TEST_CASE("UUID", "[uuid]")
{
    const auto a = uuid::generateArray();

    REQUIRE(a[6] >> 4 == 4);
    REQUIRE((a[8] & 0xC0U) == 0x80U);

    const auto s = uuid::generateString();
    REQUIRE(s.length() == 36);
    REQUIRE(s[14] == '4');
    REQUIRE((hexToInt(s[19]) & 0x0CU) == 0x08U);
}

TEST_CASE("UUID with custom random engine", "[uuid]")
{
    std::minstd_rand mr{0x01};

    const auto a = uuid::generateArray(mr);

    REQUIRE(a[0] == 0x00);
    REQUIRE(a[1] == 0x00);
    REQUIRE(a[2] == 0xBC);
    REQUIRE(a[3] == 0x8F);
    REQUIRE(a[4] == 0x0A);
    REQUIRE(a[5] == 0xE2);
    REQUIRE(a[6] == 0x47);
    REQUIRE(a[7] == 0xE2);
    REQUIRE(a[8] == 0x8C);
    REQUIRE(a[9] == 0xF9);
    REQUIRE(a[10] == 0x1F);
    REQUIRE(a[11] == 0x46);
    REQUIRE(a[12] == 0x72);
    REQUIRE(a[13] == 0x20);
    REQUIRE(a[14] == 0x51);
    REQUIRE(a[15] == 0x7D);

    const auto s = uuid::generateString(mr);
    REQUIRE(s == "7be5f8f1-1847-4123-81ea-ba5132f1f059");
}
