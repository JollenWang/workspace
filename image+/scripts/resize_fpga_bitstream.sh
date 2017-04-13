#!/bin/sh

cd ~/workspace/project/image+
./image+ --resize -i ./output/fpga.bit -p 0xFF -s 0xFFFFC0 -o ./output/fpga_block0_body.bit
cd -
