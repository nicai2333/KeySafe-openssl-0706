./config
make clean
make -j12
gcc -o test_sm9 test_sm9.c ./libcrypto.a -Iinclude -lpthread -ldl && ./test_sm9