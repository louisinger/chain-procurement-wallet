#!/bin/sh
PWD=$(pwd)
echo "move inside the /dist folder"
cd ./dist
echo "cmake ChainProcurementWallet"
cmake ..
echo "cmake build"
cmake --build .

cd $PWD
