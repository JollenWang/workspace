#!/bin/sh

cd ~/workspace/project/image+
./image+ --combine -i ./output/bitstream_header.bin \
		   -i ./output/fpga_body0.bin \
		   -i ./output/reserved_256B.bin \
		   -i ./output/fpga_body1.bin \
		   -i ./output/reserved_3840B.bin \
		   -o ./output/STREAM.BIN
cd -
