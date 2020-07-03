#include "core.hpp"

int main(int argc, char* argv[]) {
  Json::Value argjson;
  std::string to_digest;
  std::string s_result;
  char * result;
  unsigned char bytes[32];
  int res = 0;
  int toHexRes = 0;

  memset(bytes, 0, sizeof(bytes));
  argjson = parse((std::string)argv[1]);
  std::cout << to_char_array(argjson) << std::endl;
  to_digest = argjson.get("to_digest", "").asString();

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