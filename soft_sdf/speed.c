/*
 * @Author: RyanCLQ
 * @Date: 2023-06-08 10:00:58
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-13 11:11:17
 * @Description: 请填写简介
 */
#include "./speed.h"

int run = 0;

void dump_hex(uint8_t * h, int len)
{
    while(len--)
    {   
        printf("%02hhx ",*h++);
        if(len%32==0) printf("\n");
    }
}

// static int usertime = 1;
void alarmed(int sig)
{
    // 注册一个计时器
    signal(SIGALRM, alarmed); 
    run = 0;
}

double app_tminterval(int stop)
{
    double ret = 0;
    struct tms rus;
    clock_t now = times(&rus);
    static clock_t tmstart;

    // if (usertime)
    //     now = rus.tms_utime;

    if (stop == TM_START) {
        tmstart = now;
    } else {
        long int tck = sysconf(_SC_CLK_TCK);
        ret = (now - tmstart) / (double)tck;
    }
    return ret;
}

// s为STOP时，返回间隔时间
double Time_F(int s)
{
    double ret = app_tminterval(s);  // 返回
    if (s == STOP)
        alarm(0);  // 停止闹钟
    return ret;
}

void performance_test_enc(size_t (*func_loop)(size_t), size_t size_arr[], size_t num, int sec){
    unsigned long count;
    double d = 0.0;
    double process_per_sec[num];

    // 注册计时器
    signal(SIGALRM, alarmed); 
    
    // 计时sec秒
    for (size_t i = 0; i < num; i++)
    {
        run = 1;
        alarm(sec);

        Time_F(START);
        count = func_loop(size_arr[i]);
        d = Time_F(STOP);
        process_per_sec[i] = count*size_arr[i]/d/1000;
        // 每sec秒可以执行多少次
        printf("size: %ld, run %ld times in %.2fs\n", size_arr[i], count, d);
				// 每秒钟处理多少字节
				// print...
    }
    printf("process persecond:\n");
    for (size_t i = 0; i < num; i++)
    {
        printf("%ld  byte\t",size_arr[i]);
    }
    printf("\n");
    for (size_t i = 0; i < num; i++)
    {
        printf("%.2f k\t",process_per_sec[i]);
    }
    printf("\n");

}

void performance_test_sv(size_t (*func_loop_sign)(size_t), size_t (*func_loop_verify)(size_t), size_t size_arr[], size_t num, int sec){
    unsigned long count;
    double d = 0.0;
    double sign_per_sec[num];
    double verify_per_sec[num];
    // 注册计时器
    signal(SIGALRM, alarmed); 
    
    // 计时sec秒
    for (size_t i = 0; i < num; i++)
    {
        run = 1;
        alarm(sec);

        Time_F(START);
        count = func_loop_sign(size_arr[i]);
        d = Time_F(STOP);
        sign_per_sec[i] = count/d;
        // 每sec秒可以执行多少次
        printf("size: %ld speed : run %ld times in %.2fs\n", size_arr[i], count, d);
				// 每秒钟处理多少字节
				// print...
    }
    for (size_t i = 0; i < num; i++)
    {
        run = 1;
        alarm(sec);

        Time_F(START);
        count = func_loop_verify(size_arr[i]);
        d = Time_F(STOP);
        verify_per_sec[i] = count/d;
        // 每sec秒可以执行多少次
        printf("size: %ld speed : run %ld times in %.2fs\n", size_arr[i], count, d);
				// 每秒钟处理多少字节
				// print...
    }
    for (size_t i = 0; i < num; i++)
    {
        printf("%ld byte sign persecond:%.2f verify persecond:%.2f\n",size_arr[i],sign_per_sec[i],verify_per_sec[i]);
    }

}



void performance_test(size_t (*func_loop)(size_t), size_t size_arr[], size_t num){
    unsigned long count;
    int sec = 3;
    double d = 0.0;

    // 注册计时器
    signal(SIGALRM, alarmed); 
    
    // 计时sec秒
    for (size_t i = 0; i < num; i++)
    {
        run = 1;
        alarm(sec);

        Time_F(START);
        count = func_loop(size_arr[i]);
        d = Time_F(STOP);

        // 每sec秒可以执行多少次
        printf("size: %ld, run %ld times in %.2fs\n", size_arr[i], count, d);
				// 每秒钟处理多少字节
				// print...
    }

}


