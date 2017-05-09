/*
 * @file    common_api.h
 * @date    2017-05-09
 * @brief   common functions api header file
 * @author  Jollen (wang.xiaokun@intellif.com)
 *
 * Copyright (c) 2017, Shenzhen Intellifusion Technologies Co., Ltd.
 */


#ifndef __COMMON_API_H_
#define __COMMON_API_H_

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

char *SIZE_TO_HUMAN_READABLE(uint32_t size);
int str2word(char *str, uint32_t *word);
void dump_bytes(const char *prefix, int show_address, uint8_t *buf, int count);


#ifdef  __cplusplus
}
#endif

#endif //__COMMON_API_H_

