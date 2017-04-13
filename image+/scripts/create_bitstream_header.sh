#!/bin/sh

cd ~/workspace/project/image+
./image+ --create -C ./input/fpga_header.cfg -s 0x100 -p 0xFF -o ./output/bitstream_header.bin
cd -
