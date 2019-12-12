#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "aes.hpp"
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
    class TestRunner final
    {
    public:
        template <class T, class ...Args>
        void run(T test, Args ...args) noexcept
        {
            try
            {
                test(args...);
            }
            catch (std::exception& e)
            {
                std::cerr << e.what() << '\n';
                result = false;
            }
        }

        inline bool getResult() const noexcept { return result; }

    private:
        bool result = true;
    };

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

    void testBase64()
    {
        const std::vector<uint8_t> test = {'T', 'e', 's', 't', ' ', '1', '2', '!'};

        const auto b = base64::encode(test);

        if (b != "VGVzdCAxMiE=")
            throw std::logic_error("Invalid base64");

        std::cout << "Base64: " << b << '\n';

        const auto b2 = base64::decode(b);

        if (b2 != test)
            throw std::logic_error("Invalid decoded base64");
    }

    void testCrc8()
    {
        const std::pair<std::vector<uint8_t>, uint8_t> testCases[] = {
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
            const auto c8 = crc8::generate(testCase.first);

            if (c8 != testCase.second)
                throw std::logic_error("Invalid CRC8!");

            std::cout << "CRC8: " << std::hex << static_cast<uint32_t>(c8) << '\n';
        }
    }

    void testCrc32()
    {
        const std::pair<std::vector<uint8_t>, uint32_t> testCases[] = {
            {{}, 0x00000000},
            {{'0'}, 0xF4DBDF21},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, 0x963FBB8E},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, 0xc8a61cc1}
        };

        for (const auto& testCase : testCases)
        {
            const auto c32 = crc32::generate(testCase.first);

            if (c32 != testCase.second)
                throw std::logic_error("Invalid CRC32");

            std::cout << "CRC32: " << std::hex << c32 << '\n';
        }
    }

    void testFnv132()
    {
        const std::pair<std::vector<uint8_t>, uint32_t> testCases[] = {
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
            const auto f32 = fnv1::hash<uint32_t>(testCase.first);

            if (f32 != testCase.second)
                throw std::logic_error("Invalid FNV1 32-bit");

            std::cout << "FNV1 32: " << std::hex << f32 << '\n';
        }
    }

    void testFnv164()
    {
        const std::pair<std::vector<uint8_t>, uint64_t> testCases[] = {
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
            const auto f64 = fnv1::hash<uint64_t>(testCase.first);

            if (f64 != testCase.second)
                throw std::logic_error("Invalid FNV1 64-bit");

            std::cout << "FNV1 64: " << std::hex << f64 << '\n';
        }
    }

    void testMd5()
    {
        const std::pair<std::vector<uint8_t>, std::string> testCases[] = {
            {{}, "d41d8cd98f00b204e9800998ecf8427e"},
            {{'0'}, "cfcd208495d565ef66e7dff9f98764da"},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, "b373e3ddc3438d7c10c76f3ad9d4c401"},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "9575b2604f8fd72edb743e95bd88b36d"}
        };

        for (const auto& testCase : testCases)
        {
            const auto d = md5::generate(testCase.first);
            const auto dstr = toString(d);

            if (dstr != testCase.second)
                throw std::logic_error("Invalid md5");

            std::cout << "MD5: " << dstr << '\n';
        }
    }

    void testSha1()
    {
        const std::pair<std::vector<uint8_t>, std::string> testCases[] = {
            {{}, "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
            {{'0'}, "b6589fc6ab0dc82cf12099d1c2d40ab994e8410c"},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, "9514e18b679622b8d59991a6298559cb03099d64"},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "ca593e38a74c94d97c9e0ead291340ae6a824060"}
        };

        for (const auto& testCase : testCases)
        {
            const auto h = sha1::hash(testCase.first);
            const auto hstr = toString(h);

            if (hstr != testCase.second)
                throw std::logic_error("Invalid sha1");

            std::cout << "SHA1: " << hstr << '\n';
        }
    }

    void testSha256()
    {
        const std::pair<std::vector<uint8_t>, std::string> testCases[] = {
            {{}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {{'0'}, "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9"},
            {{'0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
              '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'}, "9692e67b8378a6f6753f97782d458aa757e947eab2fbdf6b5c187b74561eb78f"},
            {{'T', 'e', 's', 't', ' ', '1', '2', '!'}, "2d8f37e9c67a0bab28d6cfc4c5d92055c5c69bb131948e198fc62c85d9016008"}
        };

        for (const auto& testCase : testCases)
        {
            const auto h = sha256::hash(testCase.first);
            const auto hstr = toString(h);

            if (hstr != testCase.second)
                throw std::logic_error("Invalid sha256");

            std::cout << "SHA256: " << hstr << '\n';
        }
    }

    void testUtf8()
    {
        const std::string testString = u8"ÀÁÂÃÄÅÆ";

        const auto utf32String = utf8::toUtf32(testString);

        if (utf32String != U"ÀÁÂÃÄÅÆ")
            throw std::logic_error("Invalid UTF-32");

        const auto utf8String = utf8::fromUtf32(utf32String);

        if (utf8String != testString)
            throw std::logic_error("Invalid UTF-8");

        std::cout << "UTF8: " << utf8String << '\n';
    }

    void testUuid()
    {
        const auto g = uuid::generateString();
        if (g[14] != '4')
            throw std::logic_error("Wrong UUID version");

        if ((hexToInt(g[19]) & 0x0C) != 0x8)
            throw std::logic_error("Wrong UUID variant");

        std::cout << "UUID: " << g << '\n';
    }
}

int main()
{
    TestRunner testRunner;
    testRunner.run(testBase64);
    testRunner.run(testCrc8);
    testRunner.run(testCrc32);
    testRunner.run(testFnv132);
    testRunner.run(testFnv164);
    testRunner.run(testMd5);
    testRunner.run(testSha1);
    testRunner.run(testSha256);
    testRunner.run(testUtf8);
    testRunner.run(testUuid);

    if (testRunner.getResult())
        std::cout << "Success\n";

    return testRunner.getResult() ? EXIT_SUCCESS : EXIT_FAILURE;
}
