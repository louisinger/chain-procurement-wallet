#include "wallet.hpp"
#include "transaction.hpp"

int main(int argc, char* argv[]) {
  // Json::Value argjson;
  // argjson = parse((std::string)argv[1]);
  // std::cout << "argument:" << std::endl << to_char_array(argjson) << std::endl;

  // char* jsonSeedStr;
  // char* jsonAddrStr;
  // Json::Value jsonSeed;
  // Json::Value jsonAddr;

  // const char* mnemonic = argjson["mnemonic"].asCString();
  // int depth = argjson["depth"].asInt();

  // jsonSeedStr = mnemonicToSeed(mnemonic, NULL);
  // std::cout << "mnemonicToSeed" << std::endl << jsonSeedStr << std::endl;
  // jsonSeed = parse(jsonSeedStr);

  // const char* seedHex = jsonSeed["seed"].asCString();

  // jsonAddrStr = getNewAddress(seedHex, depth);
  // std::cout << std::endl << "getNewAddress" << std::endl << jsonAddrStr << std::endl;

  char* txHex = argv[1];
  char* key = argv[2];

  char* res = signTransaction(key, txHex);

  std::cout << res << std::endl;

  return 0;
}