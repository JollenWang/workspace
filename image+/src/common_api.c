/*
 * @file    common_api.c
 * @date    2017-05-09
 * @brief   common function implementation
 * @author  Jollen (wang.xiaokun@intellif.com)
 *
 * Copyright (c) 2017, Shenzhen Intellifusion Technologies Co., Ltd.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <assert.h>

#define MAX_NUMERICAL_PARAM_LEN     10
#define IS_IN_a_TO_f(c) (((c) >= 'a') && ((c) <= 'f'))
#define IS_IN_A_TO_F(c) (((c) >= 'A') && ((c) <= 'F'))
#define IS_IN_0_TO_9(c) (((c) >= '0') && ((c) <= '9'))

static int __find_numerical_start(char *str, int str_len, int *start_pos, int *is_hex)
{
    if (str_len > MAX_NUMERICAL_PARAM_LEN || str_len < 1)
        return -1;

    if (str_len == 1) {
        if (!IS_IN_0_TO_9(str[0]))
            return -1;

        *start_pos = 0;
        *is_hex = 0;
        return 0;
    }

    if (str_len > 1) {
        if (str[0] == '0') {
            if (str[1] == 'x' || str[1] == 'X') {
                *start_pos = 2;
                *is_hex = 1;
            } else {
                *start_pos = 0;
                *is_hex = 0;
            }

            return 0;
        } else {
            if (IS_IN_0_TO_9(str[0])) {
                *start_pos = 0;
                *is_hex = 0;
                return 0;
            }
        }
    }

    return -1;
}

static int __check_validity_data(char *str, int start_pos, int is_hex)
{
    char *p = str + start_pos;

    if (is_hex) {
        while(*p != '\0') {
            if (!(IS_IN_a_TO_f(*p) || IS_IN_A_TO_F(*p) || IS_IN_0_TO_9(*p)))
                return -1;
            p++;
        }
    } else {
        while(*p != '\0') {
            if (!IS_IN_0_TO_9(*p))
                return -1;
            p++;
        }
    }

    return p - (str + start_pos);
}

static unsigned char __char2hex(char c)
{
    if (IS_IN_0_TO_9(c))
        return c - '0';
    if (IS_IN_A_TO_F(c))
        return c - 'A' + 10;
    if (IS_IN_a_TO_f(c))
        return c - 'a' + 10;

    return 0;
}

int str2word(char *str, uint32_t *word)
{
    size_t str_len = strlen(str);
    int i, start_pos, is_hex, valid_len;
    uint64_t value = 0;
    uint8_t multiple;

    if (!str)
        return -1;

    if (__find_numerical_start(str, str_len, &start_pos, &is_hex)) {
        printf("#>find numerical start failed!\n");
        return -1;
    }

    valid_len = __check_validity_data(str, start_pos, is_hex);
    if (valid_len < 0)
        return -1;

    multiple = (is_hex) ? 16 : 10;
    for (i = 0; i < valid_len; i++) {
        value *= multiple;
        value += __char2hex(str[start_pos + i]);
        if (!is_hex) {
            if (value > (uint64_t)0xFFFFFFFF) {
                printf("#>decimal data %s overflow!\n", str);
                return -1;
            }
        }
    }
    *word = (uint32_t)value;

    return 0;
}

char *SIZE_TO_HUMAN_READABLE(uint32_t size)
{
#define S_KB    1024
#define S_MB    (S_KB * 1024)
#define S_GB    (S_MB * 1024)
    static char vb[64];
    uint32_t GB = size / S_GB;
    uint32_t MB = (size % S_GB) / S_MB;
    uint32_t KB = (size % S_MB) / S_KB;
    uint32_t BYTES = (size % S_KB);
    int c = 0;

    memset(vb, 0, sizeof(vb));
    if (GB)
        c += snprintf(vb, sizeof(vb), "%dGB.", GB);
    if (MB)
        c += snprintf(vb + c, sizeof(vb) - c, "%dMB.", MB);
    if (KB)
        c += snprintf(vb + c, sizeof(vb) - c, "%dKB.", KB);
    if (BYTES)
        c += snprintf(vb + c, sizeof(vb) - c, "%dBytes", BYTES);

    return vb;
}

void dump_bytes(const char *prefix, int show_address, uint8_t *buf, int count)
{
    int i;

    printf("[%s]:\n", prefix);
    for (i = 0; i < count; i++) {
        if (show_address) {
            if (!(i % 16))
                printf("[%08X] ", i);
        }
        printf("%02X ", buf[i]);
        if (!((i + 1) % 16))
            printf("\n");
    }
    printf("\n");
}


