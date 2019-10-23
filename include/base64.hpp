//
// Header-only libs
//

#ifndef BASE64_HPP
#define BASE64_HPP

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace base64
{
    namespace
    {
        constexpr char chars[] = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        };

        constexpr uint8_t getIndex(const uint8_t c)
        {
            return (c >= 'A' && c <= 'Z') ? c - 'A' :
                (c >= 'a' && c <= 'z') ? 26 + (c - 'a') :
                (c >= '0' && c <= '9') ? 52 + (c - '0') :
                (c == '+') ? 62 : (c == '/') ? 63 :
                throw std::out_of_range("Invalid Base64 digit");
        }
    }

    template <class Iterator>
    inline std::string encode(const Iterator begin, const Iterator end)
    {
        std::string result;
        size_t c = 0;
        uint8_t charArray[3];

        for (Iterator i = begin; i != end; ++i)
        {
            charArray[c++] = *i;
            if (c == 3)
            {
                result += chars[static_cast<uint8_t>((charArray[0] & 0xFC) >> 2)];
                result += chars[static_cast<uint8_t>(((charArray[0] & 0x03) << 4) + ((charArray[1] & 0xF0) >> 4))];
                result += chars[static_cast<uint8_t>(((charArray[1] & 0x0F) << 2) + ((charArray[2] & 0xC0) >> 6))];
                result += chars[static_cast<uint8_t>(charArray[2] & 0x3f)];
                c = 0;
            }
        }

        if (c)
        {
            for (size_t j = c; j < 3; ++j) charArray[j] = '\0';

            result += chars[static_cast<uint8_t>((charArray[0] & 0xFC) >> 2)];
            result += chars[static_cast<uint8_t>(((charArray[0] & 0x03) << 4) + ((charArray[1] & 0xF0) >> 4))];
            result += chars[static_cast<uint8_t>(((charArray[1] & 0x0F) << 2) + ((charArray[2] & 0xC0) >> 6))];

            while (++c < 4) result += '=';
        }

        return result;
    }

    template <class T>
    inline std::string encode(const T& v)
    {
        return encode(std::begin(v), std::end(v));
    }

    template <class Iterator>
    inline std::vector<uint8_t> decode(const Iterator begin, const Iterator end)
    {
        uint32_t c = 0;
        uint8_t charArray[4];
        std::vector<uint8_t> result;

        for (Iterator i = begin; i != end && *i != '='; ++i)
        {
            charArray[c++] = static_cast<uint8_t>(*i);
            if (c == 4)
            {
                for (uint32_t j = 0; j < 4; ++j) charArray[j] = getIndex(charArray[j]);

                result.push_back(static_cast<uint8_t>((charArray[0] << 2) + ((charArray[1] & 0x30) >> 4)));
                result.push_back(static_cast<uint8_t>(((charArray[1] & 0x0F) << 4) + ((charArray[2] & 0x3C) >> 2)));
                result.push_back(static_cast<uint8_t>(((charArray[2] & 0x3) << 6) + charArray[3]));

                c = 0;
            }
        }

        if (c)
        {
            for (uint32_t j = 0; j < c; ++j) charArray[j] = getIndex(charArray[j]);
            for (uint32_t j = c; j < 4; ++j) charArray[j] = 0;

            result.push_back(static_cast<uint8_t>((charArray[0] << 2) + ((charArray[1] & 0x30) >> 4)));
            result.push_back(static_cast<uint8_t>(((charArray[1] & 0x0F) << 4) + ((charArray[2] & 0x3C) >> 2)));
        }

        return result;
    }

    template <class T>
    inline std::vector<uint8_t> decode(const T& s)
    {
        return decode(std::begin(s), std::end(s));
    }
}

#endif // BASE64_HPP
