#include "Utils.hpp"
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

std::string hashToString(const std::vector<unsigned char>& hash)
{
    std::stringstream ss;

    for (unsigned char byte : hash)
    {
        ss << std::hex
           << std::setw(2)
           << std::setfill('0')
           << static_cast<int>(byte);
    }

    return ss.str();
}

std::string toHex(const std::vector<uint8_t>& data)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (uint8_t byte : data)
    {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}