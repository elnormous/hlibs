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
    class ParseError final: public std::logic_error
    {
    public:
        explicit ParseError(const std::string& str): std::logic_error(str) {}
        explicit ParseError(const char* str): std::logic_error(str) {}
    };

    inline namespace detail
    {
        constexpr char chars[] = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        };

        constexpr std::uint8_t getIndex(const std::uint8_t c)
        {
            return (c >= 'A' && c <= 'Z') ? c - 'A' :
                (c >= 'a' && c <= 'z') ? 26 + (c - 'a') :
                (c >= '0' && c <= '9') ? 52 + (c - '0') :
                (c == '+') ? 62 : (c == '/') ? 63 :
                throw ParseError("Invalid Base64 digit");
        }
    }

    template <class Iterator>
    std::string encode(const Iterator begin, const Iterator end)
    {
        std::string result;
        std::size_t c = 0;
        std::uint8_t charArray[3];

        for (Iterator i = begin; i != end; ++i)
        {
            charArray[c++] = *i;
            if (c == 3)
            {
                result += chars[static_cast<std::uint8_t>((charArray[0] & 0xFC) >> 2)];
                result += chars[static_cast<std::uint8_t>(((charArray[0] & 0x03) << 4) + ((charArray[1] & 0xF0) >> 4))];
                result += chars[static_cast<std::uint8_t>(((charArray[1] & 0x0F) << 2) + ((charArray[2] & 0xC0) >> 6))];
                result += chars[static_cast<std::uint8_t>(charArray[2] & 0x3f)];
                c = 0;
            }
        }

        if (c)
        {
            result += chars[static_cast<std::uint8_t>((charArray[0] & 0xFC) >> 2)];

            if (c == 1)
                result += chars[static_cast<std::uint8_t>((charArray[0] & 0x03) << 4)];
            else
            {
                result += chars[static_cast<std::uint8_t>(((charArray[0] & 0x03) << 4) + ((charArray[1] & 0xF0) >> 4))];

                if (c == 2)
                    result += chars[static_cast<std::uint8_t>((charArray[1] & 0x0F) << 2)];
                else if (c == 3)
                    result += chars[static_cast<std::uint8_t>(((charArray[1] & 0x0F) << 2) + ((charArray[2] & 0xC0) >> 6))];
            }

            while (++c < 4) result += '=';
        }

        return result;
    }

    template <class T>
    std::string encode(const T& v)
    {
        return encode(std::begin(v), std::end(v));
    }

    template <class Iterator>
    std::vector<std::uint8_t> decode(const Iterator begin, const Iterator end)
    {
        std::uint32_t c = 0;
        std::uint8_t charArray[4];
        std::vector<std::uint8_t> result;

        for (Iterator i = begin; i != end && *i != '='; ++i)
        {
            charArray[c++] = getIndex(static_cast<std::uint8_t>(*i));
            if (c == 4)
            {
                result.push_back(static_cast<std::uint8_t>((charArray[0] << 2) + ((charArray[1] & 0x30) >> 4)));
                result.push_back(static_cast<std::uint8_t>(((charArray[1] & 0x0F) << 4) + ((charArray[2] & 0x3C) >> 2)));
                result.push_back(static_cast<std::uint8_t>(((charArray[2] & 0x3) << 6) + charArray[3]));

                c = 0;
            }
        }

        if (c)
        {
            if (c == 1)
                throw ParseError("Invalid Base64");
            else if (c == 2)
                result.push_back(static_cast<std::uint8_t>((charArray[0] << 2) + ((charArray[1] & 0x30) >> 4)));
            else if (c == 3)
            {
                result.push_back(static_cast<std::uint8_t>((charArray[0] << 2) + ((charArray[1] & 0x30) >> 4)));
                result.push_back(static_cast<std::uint8_t>(((charArray[1] & 0x0F) << 4) + ((charArray[2] & 0x3C) >> 2)));
            }
        }

        return result;
    }

    template <class T>
    std::vector<std::uint8_t> decode(const T& s)
    {
        return decode(std::begin(s), std::end(s));
    }
}

#endif // BASE64_HPP
