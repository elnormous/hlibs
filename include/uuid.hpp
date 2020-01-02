//
// Header-only libs
//

#ifndef UUID_HPP
#define UUID_HPP

#include <cstdint>
#include <random>
#include <string>

namespace uuid
{
    struct Uuid final
    {
        uint32_t  timeLow;
        uint16_t  timeMid;
        uint16_t  timeHiAndVersion;
        uint8_t   clockSeqHiAndReserved;
        uint8_t   clockSeqLow;
        uint8_t   node[6];
    };

    inline Uuid generate()
    {
        static std::random_device rd;
        static std::mt19937_64 mt(rd());

        const uint64_t randomTime = mt();

        const uint32_t timeLow = ((randomTime >> 24) & 0x000000FF) |
            ((randomTime >> 8) & 0x0000FF00) |
            ((randomTime << 8) & 0x00FF0000) |
            ((randomTime << 24) & 0xFF000000);

        const uint16_t timeMid = static_cast<uint16_t>(((randomTime >> 40) & 0x00FF) |
                                                       ((randomTime >> 24) & 0xFF00));

        const uint16_t timeHiAndVersion = static_cast<uint16_t>(((0x04 << 12) & 0xF000) |
                                                                ((randomTime >> 56) & 0x00FF) |
                                                                ((randomTime >> 40) & 0x0F00));

        const uint16_t clockSequence = static_cast<uint16_t>(mt() & 0x3FFF); // 14-bit random

        const uint8_t clockSeqHiAndReserved = static_cast<uint8_t>(0x80 | // bit 6 and 7
                                                                   ((clockSequence >> 8) & 0x3F));
        const uint8_t clockSeqLow = static_cast<uint8_t>(clockSequence & 0xFF);

        const uint64_t random = mt();

        return {
            timeLow,
            timeMid,
            timeHiAndVersion,
            clockSeqHiAndReserved,
            clockSeqLow,
            {
                static_cast<uint8_t>(random >> 48),
                static_cast<uint8_t>(random >> 40),
                static_cast<uint8_t>(random >> 32),
                static_cast<uint8_t>(random >> 24),
                static_cast<uint8_t>(random >> 16),
                static_cast<uint8_t>(random >> 0)
            }
        };
    }

    template <class T>
    T generate();

    template <>
    inline std::string generate<std::string>()
    {
        constexpr char digits[] = "0123456789abcdef";

        const Uuid u = generate();

        return {
            digits[(u.timeLow >> 28) & 0x0F],
            digits[(u.timeLow >> 24) & 0x0F],
            digits[(u.timeLow >> 20) & 0x0F],
            digits[(u.timeLow >> 16) & 0x0F],
            digits[(u.timeLow >> 12) & 0x0F],
            digits[(u.timeLow >> 8) & 0x0F],
            digits[(u.timeLow >> 4) & 0x0F],
            digits[(u.timeLow >> 0) & 0x0F],
            '-',
            digits[(u.timeMid >> 12) & 0x0F],
            digits[(u.timeMid >> 8) & 0x0F],
            digits[(u.timeMid >> 4) & 0x0F],
            digits[(u.timeMid >> 0) & 0x0F],
            '-',
            digits[(u.timeHiAndVersion >> 12) & 0x0F],
            digits[(u.timeHiAndVersion >> 8) & 0x0F],
            digits[(u.timeHiAndVersion >> 4) & 0x0F],
            digits[(u.timeHiAndVersion >> 0) & 0x0F],
            '-',
            digits[(u.clockSeqHiAndReserved >> 4) & 0x0F],
            digits[(u.clockSeqHiAndReserved >> 0) & 0x0F],
            digits[(u.clockSeqLow >> 4) & 0x0F],
            digits[(u.clockSeqLow >> 0) & 0x0F],
            '-',
            digits[(u.node[0] >> 4) & 0x0F],
            digits[(u.node[0] >> 0) & 0x0F],
            digits[(u.node[1] >> 4) & 0x0F],
            digits[(u.node[1] >> 0) & 0x0F],
            digits[(u.node[2] >> 4) & 0x0F],
            digits[(u.node[2] >> 0) & 0x0F],
            digits[(u.node[3] >> 4) & 0x0F],
            digits[(u.node[3] >> 0) & 0x0F],
            digits[(u.node[4] >> 4) & 0x0F],
            digits[(u.node[4] >> 0) & 0x0F],
            digits[(u.node[5] >> 4) & 0x0F],
            digits[(u.node[5] >> 0) & 0x0F]
        };
    }
}

#endif // UUID_HPP
