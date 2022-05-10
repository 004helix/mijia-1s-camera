#!/bin/bash

set -x

../buildroot-2018.02.12/output/host/bin/aarch64-buildroot-linux-gnu-gcc \
	-I../output/host/aarch64-buildroot-linux-gnu/sysroot/usr/include \
	-D_LARGEFILE_SOURCE \
	-D_LARGEFILE64_SOURCE \
	-D_FILE_OFFSET_BITS=64 \
	-Wall libcamd.c -o libcamd.so -fPIC -shared -ldl -lpthread -lturbojpeg
