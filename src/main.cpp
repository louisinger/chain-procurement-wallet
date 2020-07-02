#include "core.hpp"

int main(int argc, char* argv[]) {
  Json::Value argjson;
  Json::Reader reader;
  std::string to_digest;
  std::string s_result;
  char * result;
  unsigned char bytes[32];
  int res = 0;
  int toHexRes = 0;

  memset(bytes, 0, sizeof(bytes));
  bool parsingSuccess = reader.parse(((std::string)argv[1]).c_str(), argjson);
  if (!parsingSuccess) {
    std::cerr << "json parsing failed" << std::endl;
    exit(-1);
  }
  
  to_digest = argjson.get("to_digest", NULL).asString();

  std::cout << to_digest << std::endl;

  res = wally_sha256((unsigned char *)to_digest.c_str(), to_digest.length(), bytes, sizeof(bytes));
  toHexRes = wally_hex_from_bytes(bytes, sizeof(bytes), &result);

  s_result = (std::string) result;

  if (res != WALLY_OK || toHexRes != WALLY_OK) {
    std::cerr << "sha256 with jsoncpp failed " << res << std::endl;
    exit(res);
  }

  std::cout << s_result << std::endl;


  return 0;
}