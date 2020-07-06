#include "wallet.hpp"

char* mnemonicToSeed (const char* mnemonic, const char* passphrase) {
  size_t LEN = BIP39_SEED_LEN_512;

  int mnemonicValidated;
  int mnemonicSeeded;
  int convertToHex;
  unsigned char seed[LEN];
  char* seedHex;
  Json::Value ret;

  mnemonicValidated = bip39_mnemonic_validate(NULL, mnemonic);
  if (mnemonicValidated != WALLY_OK) {
    std::cerr << "mnemonicToSeed: invalid mnemonic error. " << std::endl;
    exit(mnemonicValidated);
  }

  memset(seed, 0, sizeof(seed));

  mnemonicSeeded = bip39_mnemonic_to_seed(mnemonic, passphrase, seed, LEN, &LEN); 
  if (mnemonicSeeded != WALLY_OK) {
    std::cerr << "mnemonicToSeed: the mnemonic can be switch to seed." << std::endl;
    exit(mnemonicSeeded);
  }

  convertToHex = wally_hex_from_bytes(seed, sizeof(seed), &seedHex);
  if (convertToHex != WALLY_OK) {
    std::cerr << "mnemonicToSeed: can't convert seed to hex." << std::endl;
    exit(convertToHex);
  }

  ret["mnemonic"] = mnemonic;
  ret["seed"] = seedHex;
  return to_char_array(ret);
}

char* getNewAddress (const char* seed, int depth) {
  size_t SEED_LEN = BIP39_SEED_LEN_512;
  size_t SCRIPT_LEN = WALLY_SCRIPTPUBKEY_P2PKH_LEN;
  uint32_t version = BIP32_VER_TEST_PRIVATE;

  int convertSeedToBytes;
  int masterKeyFromSeed ;
  int derivedKeyFromMaster;
  int addressFromDerivedKey;
  int blindingKeyFromSeed;
  int blindingKeyToPrivKey;
  int blindingKeyToPublicKey;
  int serializeMasterKey;
  int addrToScriptPubKey;
  int createConfidentialAddr;

  unsigned char seedBytes[SEED_LEN];
  unsigned char blindingKey[HMAC_SHA512_LEN];
  unsigned char masterKeyBytes[BIP32_SERIALIZED_LEN];
  unsigned char scriptPubKey[SCRIPT_LEN];
  unsigned char ecPrivateKey[EC_PRIVATE_KEY_LEN];
  unsigned char ecPublicKey[EC_PUBLIC_KEY_LEN];
  ext_key* masterKey;
  ext_key* derivedKey;
  char* address;
  char* confidentialAddress;

  Json::Value ret;

  memset(seedBytes, 0, sizeof(seedBytes));
  memset(blindingKey, 0, sizeof(blindingKey));
  memset(masterKeyBytes, 0, sizeof(masterKeyBytes));
  memset(scriptPubKey, 0, sizeof(scriptPubKey));
  memset(ecPrivateKey, 0, sizeof(ecPrivateKey));
  memset(ecPublicKey, 0, sizeof(ecPublicKey));

  if (depth >= BIP32_INITIAL_HARDENED_CHILD) {
    std::cerr << "getNewAddress: depth too high" << std::endl;
    exit(-1);
  }

  convertSeedToBytes = wally_hex_to_bytes(seed, seedBytes, SEED_LEN, &SEED_LEN);
  if (convertSeedToBytes != WALLY_OK) {
    std::cerr << "getNewAddress: can't convert seed hex to bytes." << std::endl;
    exit(convertSeedToBytes);
  }

  masterKeyFromSeed = bip32_key_from_seed_alloc(seedBytes, BIP32_ENTROPY_LEN_512, version, 0, &masterKey);
  if (masterKeyFromSeed != WALLY_OK) {
    std::cerr << "getNewAddress: can't derivate the seed to master key." << std::endl;
    exit(masterKeyFromSeed);
  }

  derivedKeyFromMaster = bip32_key_from_parent_alloc(masterKey, depth, BIP32_FLAG_KEY_PRIVATE, &derivedKey);
  if (derivedKeyFromMaster != WALLY_OK) {
    std::cerr << "getNewAddress: error during key derivation." << std::endl;
    exit(derivedKeyFromMaster);
  }

  addressFromDerivedKey = wally_bip32_key_to_address(derivedKey, WALLY_ADDRESS_TYPE_P2PKH, WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST, &address);
  if (addressFromDerivedKey != WALLY_OK) {
    std::cerr << "getNewAddress: error during key to address function." << std::endl;
    exit(addressFromDerivedKey);
  }

  addrToScriptPubKey = wally_address_to_scriptpubkey(address, WALLY_NETWORK_LIQUID_REGTEST, scriptPubKey, SCRIPT_LEN, &SCRIPT_LEN);
  if (addrToScriptPubKey != WALLY_OK) {
    std::cerr << "getNewAddress: error during script pub key creation." << std::endl;
    exit(addrToScriptPubKey);
  }

  blindingKeyFromSeed = wally_asset_blinding_key_from_seed(seedBytes, SEED_LEN, blindingKey, HMAC_SHA512_LEN);
  if (blindingKeyFromSeed != WALLY_OK) {
    std::cerr << "getNewAddress: error during blinding key generation." << std::endl;
    exit(blindingKeyFromSeed);
  }

  serializeMasterKey = bip32_key_serialize(masterKey, BIP32_FLAG_KEY_PRIVATE, masterKeyBytes, BIP32_SERIALIZED_LEN);
  if (serializeMasterKey != WALLY_OK) {
    std::cerr << "getNewAddress: error to serialize the master key." << std::endl;
    exit(serializeMasterKey);
  }

  blindingKeyToPrivKey = wally_asset_blinding_key_to_ec_private_key(blindingKey, sizeof(blindingKey), scriptPubKey, sizeof(scriptPubKey), ecPrivateKey, sizeof(ecPrivateKey));
  if (blindingKeyToPrivKey != WALLY_OK) {
    std::cerr << "getNewAddress: error to get new ec private key." << blindingKeyToPrivKey << std::endl;
    exit(blindingKeyToPrivKey);
  }

  blindingKeyToPublicKey = wally_ec_public_key_from_private_key(ecPrivateKey, sizeof(ecPrivateKey), ecPublicKey, sizeof(ecPublicKey));
  if (blindingKeyToPublicKey != WALLY_OK) {
    std::cerr << "getNewAddress: error to get new ec public key." << std::endl;
    exit(blindingKeyToPublicKey);
  }

  createConfidentialAddr = wally_confidential_addr_from_addr(address, WALLY_CA_PREFIX_LIQUID_REGTEST, ecPublicKey, sizeof(ecPublicKey), &confidentialAddress);
  if (createConfidentialAddr != WALLY_OK) {
    std::cerr << "getNewAddress: error during confidential addr concatenation with public key." << createConfidentialAddr << std::endl;
    exit(createConfidentialAddr);
  }

  bip32_key_free(derivedKey);
  bip32_key_free(masterKey);

  ret["address"] = address;
  ret["confidentialAddress"] = confidentialAddress;

  return to_char_array(ret);
}


