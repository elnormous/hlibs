#include <iostream>
#include "base64.hpp"
#include "md5.hpp"
#include "sha1.hpp"

inline std::string toString(const std::vector<uint8_t>& v)
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

int main()
{
    try
    {
        std::vector<uint8_t> test = {'T', 'e', 's', 't', ' ', '1', '2', '!'};

        static const std::string hashTest = "ca593e38a74c94d97c9e0ead291340ae6a824060";
        static const std::string base64Test = "VGVzdCAxMiE=";
        static const std::string md5Test = "9575b2604f8fd72edb743e95bd88b36d";

        std::vector<uint8_t> h = sha1::hash(test);
        std::string hstr = toString(h);

        if (hstr != hashTest)
            throw std::runtime_error("Invalid sha1");

        std::cout << hstr << std::endl;

        std::string b = base64::encode(test);

        if (b != base64Test)
            throw std::runtime_error("Invalid base64");

        std::cout << b << std::endl;

        std::vector<uint8_t> b2 = base64::decode(b);

        if (b2 != test)
            throw std::runtime_error("Invalid decoded base64");

        std::vector<uint8_t> d = md5::digest(test);
        std::string dstr = toString(d);

        if (dstr != md5Test)
            throw std::runtime_error("Invalid md5");

        std::cout << dstr << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
