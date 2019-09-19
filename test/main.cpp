#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "base64.hpp"
#include "crc.hpp"
#include "fnv1.hpp"
#include "md5.hpp"
#include "sha1.hpp"
#include "sha2.hpp"
#include "utf8.hpp"
#include "uuid.hpp"

namespace
{
    template <class T>
    inline std::string toString(const T& v)
    {
        constexpr char digits[] = "0123456789abcdef";

        std::string result;
        for (uint8_t b : v)
        {
            result += digits[(b >> 4) & 0x0F];
            result += digits[b & 0x0F];
        }

        return result;
    }

    constexpr uint8_t hexToInt(const char hex)
    {
        return (hex >= '0' && hex <= '9') ? static_cast<uint8_t>(hex - '0') :
            (hex >= 'a' && hex <='f') ? static_cast<uint8_t>(hex - 'a' + 10) :
            (hex >= 'A' && hex <='F') ? static_cast<uint8_t>(hex - 'A' + 10) :
            throw std::out_of_range("Invalid hex digit");
    }

    const std::vector<uint8_t> test = {'T', 'e', 's', 't', ' ', '1', '2', '!'};

    void testBase64()
    {
        const auto b = base64::encode(test);

        if (b != "VGVzdCAxMiE=")
            throw std::runtime_error("Invalid base64");

        std::cout << "Base64: " << b << std::endl;

        const auto b2 = base64::decode(b);

        if (b2 != test)
            throw std::runtime_error("Invalid decoded base64");
    }

    void testCrc()
    {
        const auto c8 = crc8::generate(test);

        if (c8 != 0x20)
            throw std::runtime_error("Invalid CRC8!");

        std::cout << "CRC8: " << std::hex << static_cast<uint32_t>(c8) << std::endl;

        const auto c32 = crc32::generate(test);

        if (c32 != 0xc8a61cc1)
            throw std::runtime_error("Invalid CRC32");

        std::cout << "CRC32: " << std::hex << c32 << std::endl;
    }

    void testFnv1()
    {
        const auto f32 = fnv1::hash<uint32_t>(test);

        if (f32 != 0x296a37b7)
            throw std::runtime_error("Invalid FNV1 32-bit");

        std::cout << "FNV32: " << std::hex << f32 << std::endl;

        const auto f64 = fnv1::hash<uint64_t>(test);

        if (f64 != 0x98645a51cb3becf7)
            throw std::runtime_error("Invalid FNV1 64-bit");

        std::cout << "FNV64: " << std::hex << f64 << std::endl;
    }

    void testMd5()
    {
        const auto d = md5::generate(test);
        const auto dstr = toString(d);

        if (dstr != "9575b2604f8fd72edb743e95bd88b36d")
            throw std::runtime_error("Invalid md5");

        std::cout << "MD5: " << dstr << std::endl;
    }

    void testSha1()
    {
        const auto h = sha1::hash(test);
        const auto hstr = toString(h);

        if (hstr != "ca593e38a74c94d97c9e0ead291340ae6a824060")
            throw std::runtime_error("Invalid sha1");

        std::cout << "SHA1: " << hstr << std::endl;
    }

    void testSha256()
    {
        const auto h = sha256::hash(test);
        const auto hstr = toString(h);

        if (hstr != "2d8f37e9c67a0bab28d6cfc4c5d92055c5c69bb131948e198fc62c85d9016008")
            throw std::runtime_error("Invalid sha256");

        std::cout << "SHA256: " << hstr << std::endl;
    }

    void testUtf8()
    {
        const std::string testString = u8"ÀÁÂÃÄÅÆ";

        const auto utf32String = utf8::toUtf32(testString);

        if (utf32String != U"ÀÁÂÃÄÅÆ")
            throw std::runtime_error("Invalid UTF-32");

        const auto utf8String = utf8::fromUtf32(utf32String);

        if (utf8String != testString)
            throw std::runtime_error("Invalid UTF-8");

        std::cout << "UTF8: " << utf8String << std::endl;
    }

    void testUuid()
    {
        const auto g = uuid::generateString();
        if (g[14] != '4')
            throw std::runtime_error("Wrong UUID version");

        if ((hexToInt(g[19]) & 0x0C) != 0x8)
            throw std::runtime_error("Wrong UUID variant");

        std::cout << "UUID: " << g << std::endl;
    }
}

int main()
{
    try
    {
        testBase64();
        testCrc();
        testFnv1();
        testMd5();
        testSha1();
        testSha256();
        testUtf8();
        testUuid();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
