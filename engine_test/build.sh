#!/bin/bash 

gcc -fPIC -o my_engine.o -c my_engine.c && gcc -shared -o my_engine.so  -L/home/ryanclq/code/KeySafe-OpenSSL-1.1.1i/openssl-bin/lib -lcrypto my_engine.o