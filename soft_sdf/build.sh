# 更新libcryto.map，添加add.txt中的相关接口
# export LD_LIBRARY_PATH=/home/scnutest/src_2024/tmp/KeySafe-OpenSSL-1.1.1i/
# rm kek-1.key && rm ./*.pem && rm libsoft_sdf.so && rm soft_sdftest && \
cd .. && make -j32 && cd - && \
gcc -shared -fPIC -o libsoft_sdf.so soft_sdf.c  ../libcrypto.so  -I../include -lpthread -ldl -Wl,-rpath=.. && \
gcc -o soft_sdftest soft_sdftest.c speed.c ../libcrypto.so -I../include -lpthread -ldl -Wl,-rpath=.. && \
./soft_sdftest  
