export LD_LIBRARY_PATH=/home/scnutest/src_2024/tmp/KeySafe-OpenSSL-1.1.1i
# make -j12 && ./apps/openssl speed --multi 2 ecdsap256
make -j12 && ./apps/openssl speed --multi 32 sm2
# make -j12 && ./apps/openssl speed sm2 ecdsap256
# make -j12 && ./apps/openssl speed sm2