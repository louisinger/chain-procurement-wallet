#include "core.hpp"

std::vector<unsigned char> to_vector(std::string const& str)
{
    // don't forget the trailing 0...
    return std::vector<unsigned char>(str.data(), str.data() + str.length() + 1);
}