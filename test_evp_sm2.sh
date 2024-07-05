    ./config
    # make clean
    make -j12
    gcc -o test_evp_sm2 test_evp_sm2.c ./test/libtestutil.a ./libcrypto.a -Iinclude -lpthread -ldl && ./test_evp_sm2