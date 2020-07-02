#include <iostream>
#include <stdio.h>
#include <string.h>

#include <wally.hpp>

int main(int argc, char* argv[]) {
  unsigned char bytes[32];
  int i = 0;

  unsigned char* arg = (unsigned char*) argv[1];
  int argLen = strlen(argv[1]);

  memset(bytes, 0, sizeof(bytes));
  // printf("arg1 = %s\n", argv[1]);
  int res = wally_sha256(arg, argLen, bytes, sizeof(bytes));
  
  if (res != WALLY_OK) {
    std::cerr << "sha256 failed " << res << std::endl; 
    exit(res);
  }

  for (i = 0; i<(sizeof(bytes)/sizeof(bytes[0])); i++) {
	  std::cout << std::hex << static_cast<unsigned>(bytes[i]);
  }
  std::cout << std::endl;

  return 0;
}