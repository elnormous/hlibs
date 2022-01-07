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

    std::mt19937 mt{std::random_device{}()};

    template <class RandomEngine = std::mt19937>
    [[nodiscard]] Uuid generate(RandomEngine& re = mt)
    {
        const auto timeLow = static_cast<std::uint32_t>(re());
        const auto timeHigh = static_cast<std::uint32_t>(re());

        const auto timeMid = static_cast<std::uint16_t>((timeHigh >> 16) & 0xFFFFU);

        const auto timeHiAndVersion = static_cast<std::uint16_t>(((0x04U << 12) & 0xF000U) |
                                                                 (timeHigh & 0xFFFFU));

        const auto clockSequence = static_cast<std::uint32_t>(re());

        const auto clockSeqHiAndReserved = static_cast<std::uint8_t>(0x80U | // bit 6 and 7
                                                                     ((clockSequence >> 24) & 0x3FU));
        const auto clockSeqLow = static_cast<std::uint8_t>((clockSequence >> 16) & 0xFFU);

        const auto node = static_cast<std::uint32_t>(re());

        return {
            timeLow,
            timeMid,
            timeHiAndVersion,
            clockSeqHiAndReserved,
            clockSeqLow,
            {
                static_cast<std::uint8_t>(clockSequence >> 8),
                static_cast<std::uint8_t>(clockSequence >> 0),
                static_cast<std::uint8_t>(node >> 24),
                static_cast<std::uint8_t>(node >> 16),
                static_cast<std::uint8_t>(node >> 8),
                static_cast<std::uint8_t>(node >> 0)
            }
        };
    }

    template <class RandomEngine = std::mt19937>
    [[nodiscard]] std::array<std::uint8_t, 16> generateArray(RandomEngine& re = mt)
    {
        const auto uuid = generate(re);

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

    template <class RandomEngine = std::mt19937>
    [[nodiscard]] std::string generateString(RandomEngine& re = mt)
    {
        constexpr char digits[] = "0123456789abcdef";

        const auto uuid = generate(re);

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
