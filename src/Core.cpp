#include "core.hpp"

std::vector<unsigned char> to_vector(std::string const& str)
{
    return std::vector<unsigned char>(str.data(), str.data() + str.length() + 1);
}

/**
 * Parse a json-encoded string.
 * 
 * @param str a string to parse.
 * @return a Json::Value object.
 */
Json::Value parse(std::string const& str) {
  Json::Reader reader;
  Json::Value json;

  bool parsingSuccess = reader.parse(str.c_str(), json);
  if (!parsingSuccess) {
    std::cerr << "parsing " << str << " failed" << std::endl;
    exit(-1); 
  }

  return json;
}

/**
 * Transform a Json object into char array.
 * 
 * @param json a json object to convert.
 * @return the string representation of the Json object.
 */
char* to_char_array(Json::Value const& json) {
  Json::StreamWriterBuilder builder;
  int string_size = -1;

  builder["indentation"] = " "; // If you want whitespace-less output
  const std::string json_str = Json::writeString(builder, json);
  string_size = json_str.length();

  char* output = new char[string_size + 1];
  strcpy(output, json_str.c_str());

  return output;
}