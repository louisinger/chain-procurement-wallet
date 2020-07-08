#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "core.hpp"

char* tokenFromEntropy (const char* entropy);
char* assetFromEntropy (const char* entropy);
char* signTransaction (const char* privKey, const char* txHex);

#endif