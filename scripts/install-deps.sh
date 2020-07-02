#!/bin/sh
sudo apt-get -y install git
cd $HOME
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest

echo "set the cmake toolchain:"


EMSDK_ENV_PATH="$PWD/emsdk_env.sh"
echo "emsdk has been installed there: $HOME/emsdk\nPlease run the following command to activate emsdk: \nsource $EMSDK_ENV_PATH && CMAKE_TOOLCHAIN_FILE=$PWD/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake"

echo "--- END OF intall_deps.sh SCRIPT ---"
