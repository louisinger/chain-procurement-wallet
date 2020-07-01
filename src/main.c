#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>

#include <wally_crypto.h>
#include <wally_elements.h>

int main(int argc, char* argv[]) {
  unsigned char bytes[32];
  int i = 0;
  
  memset(bytes, 0, sizeof(bytes));
  // printf("arg1 = %s\n", argv[1]);
  int res = wally_sha256(argv[1], strlen(argv[1]), bytes, sizeof(bytes));
  
  if (res != WALLY_OK) {
    fprintf(stderr, "sha256 failed %d", res);
    exit(res);
  }

  for (i = 0; i<(sizeof(bytes)/sizeof(bytes[0])); i++) {
	  printf("%x", bytes[i]);
  }

  printf("\n");
}