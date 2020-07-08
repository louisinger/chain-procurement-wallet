#include "transaction.hpp"

/**
 * Generate random bytes.
 */
int generateBytes (unsigned char* bytes, size_t len) {
  for (int i=0; i<len; i++) {
    bytes[i] = (unsigned char) rand();
  }

  return 1;
}

// char* blindOutputs (const char* txHex, int valuesIn[]) {
//   wally_tx* tx;
//   wally_tx_from_hex(txHex, WALLY_TX_FLAG_USE_ELEMENTS, &tx);
//   int num_outputs = tx->num_outputs;
//   int satoshis = 0;
//   unsigned char assetBlindingFactors[num_outputs * 32];
//   unsigned char valueBlindingFactors[num_outputs * 32];
//   unsigned char finalValueBlindingFactor[32];
//   // compute the sum of values in the input (in satoshis).
//   for (int j=0; j<tx->num_inputs; j++) {
//     satoshis += valuesIn[j];
//   }
//   // init arrays
//   memset(assetBlindingFactors, 0, sizeof(assetBlindingFactors));
//   memset(valueBlindingFactors, 0, sizeof(valueBlindingFactors));
//   // generate blinding factors
//   generateBytes(assetBlindingFactors, sizeof(assetBlindingFactors));
//   generateBytes(valueBlindingFactors, sizeof(valueBlindingFactors) - 32);


//   for (int i=0; i<tx->num_outputs; i++) {

//   }
// }

/**
 * Sign a transaction using a private extended key.
 * :param privKey: an HD extended key (base58 encoded).
 * :param txHex: the hex-encoded transaction to sign.
 */
char* signTransaction (const char* privKey, const char* txHex) {
  unsigned char privKeyBytes[EC_PRIVATE_KEY_LEN];
  unsigned char pubKeyBytes[EC_PUBLIC_KEY_LEN];
  ext_key* key;
  wally_tx* tx;
  wally_tx_input* input;
  unsigned char sighash[SHA256_LEN];
  unsigned char signature[EC_SIGNATURE_LEN];
  size_t SCRIPT_LEN = WALLY_SCRIPTSIG_P2PKH_MAX_LEN;
  unsigned char scriptSig[SCRIPT_LEN];
  char* txSignedHex;

  Json::Value ret;

  bip32_key_from_base58_alloc(privKey, &key);
  memcpy(privKeyBytes, key->priv_key + 1, EC_PRIVATE_KEY_LEN);

  wally_ec_public_key_from_private_key(privKeyBytes, EC_PRIVATE_KEY_LEN, pubKeyBytes, EC_PUBLIC_KEY_LEN);

  wally_tx_from_hex(txHex, WALLY_TX_FLAG_USE_ELEMENTS, &tx);
  
  for (int i = 0; i<(tx->num_inputs); i++) {
    input = &tx->inputs[i];
    memset(sighash, 0, sizeof(sighash));
    memset(signature, 0, sizeof(signature));
    memset(scriptSig, 0, sizeof(scriptSig));

    wally_tx_get_elements_signature_hash(tx, i, input->script, input->script_len, NULL, 0, WALLY_SIGHASH_ALL, 0, sighash, sizeof(sighash));
    wally_ec_sig_from_bytes(privKeyBytes, sizeof(privKeyBytes), sighash, sizeof(sighash), EC_FLAG_ECDSA, signature, EC_SIGNATURE_LEN);
    wally_scriptsig_p2pkh_from_sig(pubKeyBytes, sizeof(pubKeyBytes), signature, sizeof(signature), WALLY_SIGHASH_ALL, scriptSig, sizeof(scriptSig), &SCRIPT_LEN);

    
    wally_tx_set_input_script(tx, i, scriptSig, sizeof(scriptSig));
  }


  int toHex = wally_tx_to_hex(tx, 0, &txSignedHex);
  ret["tx"] = txSignedHex;

  wally_free_string(txSignedHex);
  bip32_key_free(key);
  wally_tx_free(tx);

  return to_char_array(ret);
}

/**
 * Calculate the reissuance token for a given entropy.
 * :param entropy: the entropy use to generate the token.
 */
char* tokenFromEntropy (const char* entropy) {
  size_t LEN = SHA256_LEN;
  unsigned char token[LEN];
  char* tokenHex;
  unsigned char entropyBytes[LEN];
  
  int convertEntropyHexToBytes;
  int calculateToken;
  int convertTokenToHex;

  Json::Value ret;

  convertEntropyHexToBytes = wally_hex_to_bytes(entropy, entropyBytes, LEN, &LEN);
  if (convertEntropyHexToBytes != WALLY_OK) {
    exit(convertEntropyHexToBytes);
  }

  calculateToken = wally_tx_elements_issuance_calculate_reissuance_token(entropyBytes, LEN, WALLY_TX_FLAG_BLINDED_INITIAL_ISSUANCE, token, sizeof(token));
  if (calculateToken != WALLY_OK) {
    exit(calculateToken);
  }

  convertTokenToHex = wally_hex_from_bytes(token, sizeof(token), &tokenHex);
  if (convertTokenToHex != WALLY_OK) {
    exit(convertTokenToHex);
  }

  ret["entropy"] = entropy;
  ret["token"] = tokenHex;

  return to_char_array(ret);
} 

/**
 * Calculate the asset hex from the entropy.
 * :param entropy: the entropy used for generate the asset hex.
 */
char* assetFromEntropy (const char* entropy) {
  size_t LEN = SHA256_LEN;
  unsigned char token[LEN];
  char* tokenHex;
  unsigned char entropyBytes[LEN];
  
  int convertEntropyHexToBytes;
  int calculateAsset;
  int convertTokenToHex;

  Json::Value ret;

  convertEntropyHexToBytes = wally_hex_to_bytes(entropy, entropyBytes, LEN, &LEN);
  if (convertEntropyHexToBytes != WALLY_OK) {
    exit(convertEntropyHexToBytes);
  }

  calculateAsset = wally_tx_elements_issuance_calculate_asset(entropyBytes, LEN, token, sizeof(token));
  if (calculateAsset != WALLY_OK) {
    exit(calculateAsset);
  }

  convertTokenToHex = wally_hex_from_bytes(token, sizeof(token), &tokenHex);
  if (convertTokenToHex != WALLY_OK) {
    exit(convertTokenToHex);
  }

  ret["entropy"] = entropy;
  ret["token"] = tokenHex;

  return to_char_array(ret);
} 

/**
 * Create the reissuanceTx. Work in progress.
 */
char* reissuanceTx (char* dataHex, char* assetHex) {
  size_t DATA_LEN = strlen(dataHex) / 2;
  size_t SCRIPT_LEN = WALLY_SCRIPTPUBKEY_OP_RETURN_MAX_LEN;
  size_t ASSET_LEN = WALLY_TX_ASSET_CT_ASSET_LEN;

  unsigned char data[DATA_LEN];
  unsigned char script[SCRIPT_LEN]; 
  unsigned char asset[ASSET_LEN];
  wally_tx_output* assetOutput;
  wally_tx_input* issuanceInput;
  wally_tx* tx;

  wally_tx_init_alloc(2, 0, 0, 0, &tx);

  wally_hex_to_bytes(dataHex, data, DATA_LEN, &DATA_LEN);
  wally_hex_to_bytes(assetHex, asset, ASSET_LEN, &ASSET_LEN);
  wally_scriptpubkey_op_return_from_bytes(data, DATA_LEN, 0, script, SCRIPT_LEN, &SCRIPT_LEN);

  wally_tx_add_raw_output(tx, 0, script, SCRIPT_LEN, 0);
  

  // wally_tx_add_output(tx, output0);



  wally_tx_free(tx);
}