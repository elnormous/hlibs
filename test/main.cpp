#include <iostream>
#include "base64.hpp"
#include "crc.hpp"
#include "fnv1.hpp"
#include "md5.hpp"
#include "sha1.hpp"
#include "utf8.hpp"
#include "uuid.hpp"

static inline std::string toString(const std::vector<uint8_t>& v)
{
    static const char* digits = "0123456789abcdef";

    std::string result;
    for (uint8_t b : v)
    {
        result += digits[(b >> 4) & 0x0F];
        result += digits[b & 0x0F];
    }

    return result;
}

constexpr uint8_t hexToInt(char hex)
{
    return (hex >= '0' && hex <= '9') ? static_cast<uint8_t>(hex - '0') :
        (hex >= 'a' && hex <='f') ? static_cast<uint8_t>(hex - 'a' + 10) :
        (hex >= 'A' && hex <='F') ? static_cast<uint8_t>(hex - 'A' + 10) :
        throw std::out_of_range("Invalid hex digit");
}

int main()
{
    try
    {
        const std::vector<uint8_t> test = {'T', 'e', 's', 't', ' ', '1', '2', '!'};
        const std::string testString = u8"ÀÁÂÃÄÅÆ";

        const std::string hashTest = "ca593e38a74c94d97c9e0ead291340ae6a824060";
        const std::string base64Test = "VGVzdCAxMiE=";
        const std::string md5Test = "9575b2604f8fd72edb743e95bd88b36d";
        constexpr uint32_t fnv132Test = 0x296a37b7;
        constexpr uint64_t fnv164Test = 0x98645a51cb3becf7;
        constexpr uint8_t crc8Test = 0x20;
        constexpr uint32_t crc32Test = 0xc8a61cc1;

        std::vector<uint8_t> h = sha1::hash(test.begin(), test.end());
        std::string hstr = toString(h);

        if (hstr != hashTest)
            throw std::runtime_error("Invalid sha1");

        std::cout << hstr << std::endl;

        std::string b = base64::encode(test.begin(), test.end());

        if (b != base64Test)
            throw std::runtime_error("Invalid base64");

        std::cout << b << std::endl;

        std::vector<uint8_t> b2 = base64::decode(b.begin(), b.end());

        if (b2 != test)
            throw std::runtime_error("Invalid decoded base64");

        std::vector<uint8_t> d = md5::generate(test.begin(), test.end());
        std::string dstr = toString(d);

        if (dstr != md5Test)
            throw std::runtime_error("Invalid md5");

        std::cout << dstr << std::endl;

        uint32_t f32 = fnv1::hash32(test.begin(), test.end());

        if (f32 != fnv132Test)
            throw std::runtime_error("Invalid FNV1 32-bit");

        std::cout << std::hex << f32 << std::endl;

        uint64_t f64 = fnv1::hash64(test.begin(), test.end());

        if (f64 != fnv164Test)
            throw std::runtime_error("Invalid FNV1 64-bit");

        std::cout << std::hex << f64 << std::endl;

        std::vector<uint32_t> utf32String = utf8::toUtf32(testString);
        std::string utf8String = utf8::fromUtf32(utf32String);

        if (utf8String != testString)
            throw std::runtime_error("Invalid UTF-8");

        std::cout << utf8String << std::endl;

        uint8_t c8 = crc8::generate(test.begin(), test.end());

        if (c8 != crc8Test)
            throw std::runtime_error("Invalid CRC8!");

        std::cout << std::hex << static_cast<uint32_t>(c8) << std::endl;

        uint32_t c32 = crc32::generate(test.begin(), test.end());

        if (c32 != crc32Test)
            throw std::runtime_error("Invalid CRC32");

        std::cout << std::hex << c32 << std::endl;

        std::string g = uuid::generateString();
        if (g[14] != '4')
            throw std::runtime_error("Wrong UUID version");

        if ((hexToInt(g[19]) & 0x0C) != 0x8)
            throw std::runtime_error("Wrong UUID variant");

        std::cout << g << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
