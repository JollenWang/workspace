#!/bin/sh
# used for clean all build objects of ffmpeg for Android.
#

make clean
make distclean
rm -rf ./android ./compat/strtod.o ./compat/strtod.d
