#!/bin/sh

cd ~/workspace/project/image+
./image+ --read2file -i ./input/BOOT.BIN -b 0x19740 -s 0xCB44C0 -o ./output/fpga.bit
cd -
