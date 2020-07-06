#ifndef LIBWALLY_CORE_WALLY_HPP
#define LIBWALLY_CORE_WALLY_HPP

#include <iostream>
#include <stdio.h>

#include "json/json.h"

#include <type_traits>
#include <string>
#include <vector>
#include <wally_elements.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip38.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_script.h>
#include <wally_transaction.h>

std::vector<unsigned char> to_vector(std::string const& str);
Json::Value parse(std::string const& str);
char* to_char_array(Json::Value const& json);

#endif
