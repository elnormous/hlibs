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
    std::vector<uint8_t> test = {'T', 'e', 's', 't'};

    static const std::string hashTest = "640ab2bae07bedc4c163f679a746f7ab7fb5d1fa";
    static const std::string base64Test = "ZAqyuuB77cTBY/Z5p0b3q3+10fo=";
    static const std::string md5Test = "0cbc6611f5540bd0809a388dc95a615b";

    std::vector<uint8_t> h = sha1::hash(test);
    std::string hstr = toString(h);

    if (hstr != hashTest)
        throw std::runtime_error("Invalid sha1");

    std::cout << hstr << std::endl;

    std::string b = base64::encode(h);

    if (b != base64Test)
        throw std::runtime_error("Invalid base64");

    std::cout << b << std::endl;

    std::vector<uint8_t> d = md5::digest(test);
    std::string dstr = toString(d);

    if (dstr != md5Test)
        throw std::runtime_error("Invalid md5");

    std::cout << dstr << std::endl;

    return EXIT_SUCCESS;
}
