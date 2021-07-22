//
// Header-only libs
//

#ifndef UUID_HPP
#define UUID_HPP

#include <array>
#include <cstdint>
#include <random>
#include <string>

namespace uuid
{
    struct Uuid final
    {
        std::uint32_t timeLow;
        std::uint16_t timeMid;
        std::uint16_t timeHiAndVersion;
        std::uint8_t clockSeqHiAndReserved;
        std::uint8_t clockSeqLow;
        std::array<std::uint8_t, 6> node;
    };

    inline Uuid generate()
    {
        static std::random_device rd;
        static std::mt19937_64 mt{rd()};

        const std::uint64_t randomTime = mt();

        const std::uint32_t timeLow = ((randomTime >> 24) & 0x000000FFU) |
            ((randomTime >> 8) & 0x0000FF00U) |
            ((randomTime << 8) & 0x00FF0000U) |
            ((randomTime << 24) & 0xFF000000U);

        const auto timeMid = static_cast<std::uint16_t>(((randomTime >> 40) & 0x00FFU) |
                                                        ((randomTime >> 24) & 0xFF00U));

        const auto timeHiAndVersion = static_cast<std::uint16_t>(((0x04U << 12) & 0xF000U) |
                                                                 ((randomTime >> 56) & 0x00FFU) |
                                                                 ((randomTime >> 40) & 0x0F00U));

        const auto clockSequence = static_cast<std::uint16_t>(mt() & 0x3FFFU); // 14-bit random

        const auto clockSeqHiAndReserved = static_cast<std::uint8_t>(0x80U | // bit 6 and 7
                                                                     ((clockSequence >> 8) & 0x3FU));
        const auto clockSeqLow = static_cast<std::uint8_t>(clockSequence & 0xFFU);

        const auto random = mt();

        return {
            timeLow,
            timeMid,
            timeHiAndVersion,
            clockSeqHiAndReserved,
            clockSeqLow,
            {
                static_cast<std::uint8_t>(random >> 48),
                static_cast<std::uint8_t>(random >> 40),
                static_cast<std::uint8_t>(random >> 32),
                static_cast<std::uint8_t>(random >> 24),
                static_cast<std::uint8_t>(random >> 16),
                static_cast<std::uint8_t>(random >> 0)
            }
        };
    }

    template <class T> T generate();

    template <>
    std::array<std::uint8_t, 16> generate<std::array<std::uint8_t, 16>>()
    {
        const auto uuid = generate();

        return std::array<std::uint8_t, 16>{
            static_cast<std::uint8_t>(uuid.timeLow >> 24),
            static_cast<std::uint8_t>(uuid.timeLow >> 16),
            static_cast<std::uint8_t>(uuid.timeLow >> 8),
            static_cast<std::uint8_t>(uuid.timeLow),

            static_cast<std::uint8_t>(uuid.timeMid >> 8),
            static_cast<std::uint8_t>(uuid.timeMid),

            static_cast<std::uint8_t>(uuid.timeHiAndVersion >> 8),
            static_cast<std::uint8_t>(uuid.timeHiAndVersion),

            uuid.clockSeqHiAndReserved,
            uuid.clockSeqLow,

            uuid.node[0],
            uuid.node[1],
            uuid.node[2],
            uuid.node[3],
            uuid.node[4],
            uuid.node[5]
        };
    }

    template <>
    std::string generate<std::string>()
    {
        constexpr char digits[] = "0123456789abcdef";

        const auto uuid = generate();

        return {
            digits[(uuid.timeLow >> 28) & 0x0FU],
            digits[(uuid.timeLow >> 24) & 0x0FU],
            digits[(uuid.timeLow >> 20) & 0x0FU],
            digits[(uuid.timeLow >> 16) & 0x0FU],
            digits[(uuid.timeLow >> 12) & 0x0FU],
            digits[(uuid.timeLow >> 8) & 0x0FU],
            digits[(uuid.timeLow >> 4) & 0x0FU],
            digits[(uuid.timeLow >> 0) & 0x0FU],
            '-',
            digits[(uuid.timeMid >> 12) & 0x0FU],
            digits[(uuid.timeMid >> 8) & 0x0FU],
            digits[(uuid.timeMid >> 4) & 0x0FU],
            digits[(uuid.timeMid >> 0) & 0x0FU],
            '-',
            digits[(uuid.timeHiAndVersion >> 12) & 0x0FU],
            digits[(uuid.timeHiAndVersion >> 8) & 0x0FU],
            digits[(uuid.timeHiAndVersion >> 4) & 0x0FU],
            digits[(uuid.timeHiAndVersion >> 0) & 0x0FU],
            '-',
            digits[(uuid.clockSeqHiAndReserved >> 4) & 0x0FU],
            digits[(uuid.clockSeqHiAndReserved >> 0) & 0x0FU],
            digits[(uuid.clockSeqLow >> 4) & 0x0FU],
            digits[(uuid.clockSeqLow >> 0) & 0x0FU],
            '-',
            digits[(uuid.node[0] >> 4) & 0x0FU],
            digits[(uuid.node[0] >> 0) & 0x0FU],
            digits[(uuid.node[1] >> 4) & 0x0FU],
            digits[(uuid.node[1] >> 0) & 0x0FU],
            digits[(uuid.node[2] >> 4) & 0x0FU],
            digits[(uuid.node[2] >> 0) & 0x0FU],
            digits[(uuid.node[3] >> 4) & 0x0FU],
            digits[(uuid.node[3] >> 0) & 0x0FU],
            digits[(uuid.node[4] >> 4) & 0x0FU],
            digits[(uuid.node[4] >> 0) & 0x0FU],
            digits[(uuid.node[5] >> 4) & 0x0FU],
            digits[(uuid.node[5] >> 0) & 0x0FU]
        };
    }
}

#endif // UUID_HPP
