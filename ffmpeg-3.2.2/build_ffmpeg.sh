#!/bin/bash
#
# FFmpeg library build config script
# Created by Jollen Wang
# Date: 2016/12/21
#

NDK=$ANDROID_NDK
SYSROOT=$ANDROID_NDK/platforms/android-9/arch-arm
TOOLCHAIN=$ANDROID_NDK/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64
export NDK
export SYSROOT
export TOOLCHAIN
echo "It's OK."

#TOOLCHAIN_CONFIG="--arch=arm --cpu=arm"
CPU=arm
PREFIX=$(pwd)/android/$CPU
ADDI_CFLAGS="-march=armv5"

function build_one
{
./configure \
--prefix=$PREFIX \
--disable-debug \
--disable-doc \
 \
--disable-ffmpeg \
--disable-ffplay \
--disable-ffprobe \
--disable-ffserver \
 \
--disable-dct \
--disable-dwt \
 \
--disable-encoders \
--enable-encoder=rawvideo \
 \
--disable-decoders \
--enable-decoder=aac \
--enable-decoder=ac3 \
--enable-decoder=h264 \
--enable-decoder=mp3 \
--enable-decoder=mpeg2video \
 \
--disable-muxers \
--enable-muxer=mp4 \
--enable-muxer=rawvideo \
 \
--disable-protocols \
--enable-protocol=file \
--enable-protocol=http \
--enable-protocol=https \
--enable-protocol=rtmp \
 \
--disable-indevs \
--disable-outdevs \
--disable-filters \
 \
--disable-avdevice \
--disable-symver \
 \
--disable-static \
--enable-shared \
--arch=arm \
--cross-prefix=$TOOLCHAIN/bin/arm-linux-androideabi- \
--enable-cross-compile \
--sysroot=$SYSROOT \
--target-os=linux \
--extra-cflags="-Os -fpic $ADDI_CFLAGS" \
--extra-ldflags="$ADDI_LDFLAGS" \
$ADDITIONAL_CONFIGURE_FLAG

make clean
make -j4
make install
}

build_one
