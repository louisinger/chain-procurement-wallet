#ifndef WALLET_H
#define WALLET_H

#include "core.hpp"

char* mnemonicToSeed (const char* mnemonic, const char* passphrase);
char* getNewAddress (const char* seed, int depth);

#endif