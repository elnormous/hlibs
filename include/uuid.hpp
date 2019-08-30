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
    struct Uuid
    {
        uint32_t  timeLow;
        uint16_t  timeMid;
        uint16_t  timeHiAndVersion;
        uint8_t   clockSeqHiAndReserved;
        uint8_t   clockSeqLow;
        uint8_t   node[6];
    };

    inline Uuid generate() noexcept
    {
        static std::random_device rd;
        static std::mt19937_64 mt(rd());

        Uuid result;

        const uint64_t randomTime = mt();

        result.timeLow = ((randomTime >> 24) & 0x000000FF) |
            ((randomTime >> 8) & 0x0000FF00) |
            ((randomTime << 8) & 0x00FF0000) |
            ((randomTime << 24) & 0xFF000000);

        result.timeMid = static_cast<uint16_t>(((randomTime >> 40) & 0x00FF) |
                                               ((randomTime >> 24) & 0xFF00));

        result.timeHiAndVersion = static_cast<uint16_t>(((0x04 << 12) & 0xF000) |
                                                        ((randomTime >> 56) & 0x00FF) |
                                                        ((randomTime >> 40) & 0x0F00));

        const uint16_t clockSequence = static_cast<uint16_t>(mt() & 0x3FFF); // 14-bit random

        result.clockSeqHiAndReserved = static_cast<uint8_t>(0x80 | // bit 6 and 7
                                                            ((clockSequence >> 8) & 0x3F));
        result.clockSeqLow = static_cast<uint8_t>(clockSequence & 0xFF);

        const uint64_t random = mt();

        result.node[0] = (random >> 48) & 0xFF;
        result.node[1] = (random >> 40) & 0xFF;
        result.node[2] = (random >> 32) & 0xFF;
        result.node[3] = (random >> 24) & 0xFF;
        result.node[4] = (random >> 16) & 0xFF;
        result.node[5] = (random >> 0) & 0xFF;

        return result;
    }

    inline std::string generateString()
    {
        static const char* digits = "0123456789abcdef";

        const Uuid u = generate();

        std::string result = {
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

        return result;
    }
}

#endif // UUID_HPP
