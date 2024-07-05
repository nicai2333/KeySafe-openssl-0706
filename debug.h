#ifndef OPENSSL_DEBUG_H
#define OPENSSL_DEBUG_H
#include <stdio.h>
#include <stdint.h>

#define DEBUG 1
#define DEBUG_INFO 0
#define DEBUG_ERROR 2
#define DEBUG_SUCCESS 1

#if DEBUG
    static void debug_hex(const uint8_t *array, size_t length) {
        for (size_t i = 0; i < length; i++) {
            printf("%02x ", array[i]);
        }
        printf("\n");
    }
    
    // flag=0, 表示普通信息
    // flag=1，表示成功信息
    // flag=2，表示失败
    void debug(int flag, const char *format, ...) {
    va_list args;

    // 初始化 va_list 变量
    va_start(args, format);

    // 打印自定义前缀
    switch (flag)
    {
    case DEBUG_INFO:
        printf("[*] ");
        break;
    case DEBUG_ERROR:
        printf("[-] ");
        break;
    case DEBUG_SUCCESS:
        printf("[+] ");
        break;
    default:
        break;
    }

    // 使用 vprintf 实现格式化输出
    vprintf(format, args);

    // 清理 va_list 变量
    va_end(args);
}
#else
    static void print_hex(const uint8_t *array, size_t length){}
    #define debug(...) ;
#endif

#endif