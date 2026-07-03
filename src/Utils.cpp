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