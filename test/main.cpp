#include <iostream>
#include "base64.hpp"
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
    static const std::vector<uint8_t> hashTest = {0x64, 0x0a, 0xb2, 0xba, 0xe0, 0x7b, 0xed, 0xc4, 0xc1, 0x63, 0xf6, 0x79, 0xa7, 0x46, 0xf7, 0xab, 0x7f, 0xb5, 0xd1, 0xfa};

    std::vector<uint8_t> h = sha1::hash({'T', 'e', 's', 't'});

    if (h != hashTest)
        throw std::runtime_error("Invalid sha1");

    std::cout << toString(h) << std::endl;

    static const std::string base64Test = "ZAqyuuB77cTBY/Z5p0b3q3+10fo=";

    std::string b = base64::encode(h);

    if (b != base64Test)
        throw std::runtime_error("Invalid base64");

    std::cout << b << std::endl;

    return EXIT_SUCCESS;
}
