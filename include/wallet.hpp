#ifndef WALLET_H
#define WALLET_H

unsigned char* generateNewSeed (unsigned char* entropy);
unsigned char* generateMasterKeys (unsigned char* seed);
unsigned char* getNewAddress (unsigned char* masterKey);

unsigned char* reissueToken (unsigned char* tokenHex);

#endif