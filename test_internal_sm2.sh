# ./config
# make clean
make -j32 &&
# export LD_LIBRARY_PATH=/home/scnutest/src_2024/tmp/KeySafe-OpenSSL-1.1.1i
# gcc -o test_internal_sm2 -Iinclude -lpthread -ldl -lcrypto -L.  ./test/libtestutil.a test_internal_sm2.c && ./test_internal_sm2
# gcc -o test_internal_sm2 test_internal_sm2.c ./libcrypto.a -Iinclude -lpthread -ldl
# gcc -o test_internal_sm2 test_internal_sm2.c ./libcrypto.so ./test/libtestutil.a -Iinclude -lpthread -ldl && ./test_internal_sm2
# gcc -o test_internal_sm2 test_internal_sm2.c ./libcrypto.a -Iinclude -lpthread -ldl && ./test_internal_sm2
gcc -o test_internal_sm2 test_internal_sm2.c ./test/libtestutil.a -lpthread -ldl -L. -lcrypto -ldl -pthread -Iinclude -Wl,-rpath=. && ./test_internal_sm2