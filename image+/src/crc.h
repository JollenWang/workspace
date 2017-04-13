/********************************************************************************************
* Copyright(C)
* file      : 
* purpose   : 
* author    : Jollen Wang
* version   : 1.0
* date      :
* history   :
********************************************************************************************/

#ifndef __CRC_H_
#define __CRC_H_

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define CRC16_INIT_VAL  0x0uL
#define CRC32_INIT_VAL  0xffffffffuL

#define CRC16_DATA_LEN  0x00000002
#define CRC32_DATA_LEN  0x00000004

uint16_t crc16(uint16_t init_value, void *src_addr, uint32_t byte_count);
uint32_t crc32(uint32_t init_value, void *src_addr, uint32_t byte_count);

#ifdef  __cplusplus
}
#endif

#endif //__CRC_H_
