//
// Header-only libs
//

#ifndef BASE64_HPP
#define BASE64_HPP

#include <array>
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

    template <class Iterator>
    std::string encode(const Iterator begin, const Iterator end)
    {
        constexpr std::array chars = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
        };

        std::string result;
        std::size_t c = 0;
        std::array<std::uint8_t, 3> charArray;

        for (auto i = begin; i != end; ++i)
        {
            charArray[c++] = static_cast<std::uint8_t>(*i);
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
            else if (c == 2)
            {
                result += chars[static_cast<std::uint8_t>(((charArray[0] & 0x03) << 4) + ((charArray[1] & 0xF0) >> 4))];
                result += chars[static_cast<std::uint8_t>((charArray[1] & 0x0F) << 2)];
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
        std::array<std::uint8_t, 4> charArray;
        std::vector<std::uint8_t> result;

        for (auto i = begin; i != end && *i != '='; ++i)
        {
            const auto b = static_cast<std::uint8_t>(*i);

            charArray[c++] = (b >= 'A' && b <= 'Z') ? b - 'A' :
                (b >= 'a' && b <= 'z') ? 26 + (b - 'a') :
                (b >= '0' && b <= '9') ? 52 + (b - '0') :
                (b == '+') ? 62 : (b == '/') ? 63 :
                throw ParseError("Invalid Base64 digit");

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

    inline std::vector<std::uint8_t> decode(const char* s)
    {
        auto end = s;
        while (*end) ++end;
        return decode(s, end);
    }

    template <class Iterator>
    std::string urlEncode(const Iterator begin, const Iterator end)
    {
        constexpr std::array chars = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
        };

        std::string result;
        std::size_t c = 0;
        std::array<std::uint8_t, 3> charArray;

        for (auto i = begin; i != end; ++i)
        {
            charArray[c++] = static_cast<std::uint8_t>(*i);
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
            else if (c == 2)
            {
                result += chars[static_cast<std::uint8_t>(((charArray[0] & 0x03) << 4) + ((charArray[1] & 0xF0) >> 4))];
                result += chars[static_cast<std::uint8_t>((charArray[1] & 0x0F) << 2)];
            }

            while (++c < 4) result += '=';
        }

        return result;
    }

    template <class T>
    std::string urlEncode(const T& v)
    {
        return urlEncode(std::begin(v), std::end(v));
    }

    template <class Iterator>
    std::vector<std::uint8_t> urlDecode(const Iterator begin, const Iterator end)
    {
        std::uint32_t c = 0;
        std::array<std::uint8_t, 4> charArray;
        std::vector<std::uint8_t> result;

        for (auto i = begin; i != end && *i != '='; ++i)
        {
            const auto b = static_cast<std::uint8_t>(*i);

            charArray[c++] = (b >= 'A' && b <= 'Z') ? b - 'A' :
                (b >= 'a' && b <= 'z') ? 26 + (b - 'a') :
                (b >= '0' && b <= '9') ? 52 + (b - '0') :
                (b == '-') ? 62 : (b == '_') ? 63 :
                throw ParseError("Invalid Base64 digit");

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
    std::vector<std::uint8_t> urlDecode(const T& s)
    {
        return urlDecode(std::begin(s), std::end(s));
    }

    inline std::vector<std::uint8_t> urlDecode(const char* s)
    {
        auto end = s;
        while (*end) ++end;
        return urlDecode(s, end);
    }
}

#endif // BASE64_HPP
