export LD_LIBRARY_PATH=/home/hjc/KeySafe-OpenSSL-1.1.1i/out/lib/
gcc -g -Iinclude -c test_sm4_lut.c 
gcc -g test_sm4_lut.o ./libcrypto.so -o test_sm4_lut