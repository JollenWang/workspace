#!/bin/sh

cd ~/workspace/project/image+
./image+ --create -C ./input/fpga_body0.cfg -s 0x01000000 -p 0xFF -o ./output/fpga_body0.bin
cd -
