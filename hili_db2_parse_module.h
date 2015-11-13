#ifndef HILI_DB2_PARSE_MODULE_H
#define HILI_DB2_PARSE_MODULE_H

#include <stdio.h>
#include <stdint.h>
#include "cvmx-config.h"
#include "executive-config.h"
#include "cvmx.h"
#include "cvmx-bootmem.h"
#include "cvmx-tim.h"
#include "cvmx-fpa.h"
#include "cvmx-pow.h"
#include "cvmx-spinlock.h"
#include "cvmx-malloc.h"
#include "cvmx-coremask.h"
#include "hili_common.h"
#include "hili_time.h"
#include "fifo_cache.h"
#include "hili_ssh_parse_module.h"
#include "hili_se_send_2_linux.h"
#include "hili_black_list.h"

/*requires:*/
/*timing, log packet sending*/

typedef struct{
	uint8_t protocol_code; //协议，对于明文协议，加解密模块需要知道转给谁
	uint64_t session_id; //标识一条会话，用于生成日志唯一标识
	uint64_t flow_id; //标识（FTP）文件传输流;
	void *mitm_flow_ptr;
	void *oob_data_info; //带外（out of band）数据信息

	u_char primary_account[64]; //主账号名
	uint32_t function_flags; //各种功能的掩码标志
	uint16_t cli_port;
	uint16_t srv_port;
	uint32_t cli_ip;
	uint32_t srv_ip;
	uint8_t cli_mac[6];
    uint8_t srv_mac[6];
}db2_parse_init_info_t;

typedef struct{
        void    *buf_ptr;
        uint32_t buf_len;
        uint8_t  direction;
}db2_data_exchange_t;

typedef struct
{
    void *fifo_cache_ptr;
    uint8_t direction;

    struct
    {
        uint16_t srv_port;//FTP新建流的服务端端口, 上行时无用
        uint32_t srv_ip;//FTP新建流的服务端地址, 上行时无用
        void *oob_data_info;//FTP新建流用于填写日志的FTP数据结构, 上行时无用
        void *ftp_parse_flowsession_ptr;   //FTP的原始会话指针, 上行时无用
    } ftp_parse_control;
}db2_downdata_exchange_t;

#define IDPI_DRDA_DIRECTION_REQUEST (0)
#define IDPI_DRDA_DIRECTION_RESPONSE (1)

/* global init */
//int idpi_db2_parse_module_init();

/**
 * @brief Start up an drda flow parsing task 
 *
 * @param drda_parse_flow_conf Specify drda-related flow info
 *
 * @return Ptr to drda flow handle, or NULL on failure 
 */
void* hili_db2_parse_flow_init(db2_parse_init_info_t* mitm_parse_init_info_ptr);

/**
 * @brief Parse the next packet 
 *
 * @param drda_flow_ptr Ptr to drda flow handle
 * @param buf App packet buffer
 * @param buf_len Buffer length
 * @param direction 0 for C->S, 1 for S->C
 *
 * @return 0 on success, -1 otherwise 
 */
int hili_db2_parse_processing(void* drda_flow_ptr, db2_data_exchange_t *mitm_data_up_ptr);

/**
 * @brief Release an drda flow parsing task 
 *
 * @param drda_flow_ptr Ptr to drda flow handle
 *
 * @return 0 on success, -1 otherwise 
 */
int hili_db2_parse_kill_flow(void* drda_flow_ptr);


#endif

