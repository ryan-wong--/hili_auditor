#ifndef HILI_DB2_PARSER_CONTENT_H
#define HILI_DB2_PARSER_CONTENT_H

#include "hili_dummy_mitm.h"
#include "fifo_cache.h"
#include "hili_db2_parse_module.h"


#define HILI_DB2_USERNAME_MAX_LENGTH 10
#define HILI_DB2_HEAD_LEN 10
#define HILI_DB2_PARA_HEAD_LEN 4

#define HILI_DB2_DIRECTION_REQUEST 0
#define HILI_DB2_DIRECTION_RESPONSE 1 

#define HILI_DB2_WAIT_FOR_BUFFER 1
#define HILI_DB2_MESSAGE_IS_COMPLETE 0

#define HILI_DB2_PARA_HEAD 9

//#define CONTENT_H_IN_TEST

enum 
{
    HILI_DB2_ERROR = -1, 
    HILI_DB2_COMPLETE = 0,
};

enum 
{
    SQLDTA = 4,
    SECCHK = 3,
    QRYDTA = 2,
    SQLSTT = 1, 
    UNSET = 0,
};

enum 
{
    SESSION_LOG = 1,
    OPERATION_LOG = 2,
    FILE_LOG = 3,
};
enum 
{
    SES_FLOW_SIGN = 1,
	SES_SRC_IP = 2,
	SES_SRC_PORT = 3,
	SES_DST_IP = 4,
	SES_DST_PORT = 5,
	SES_MAIN_ACCOUNT = 6,
	SES_PRO_VER = 7,
	SES_SRV_VER = 8,
	SES_CLE_VER = 9,
	SES_LOGIN_TIME = 10,
	SES_LOGIN_NAME = 11,
	SES_LOGOUT_TIME = 12,
	SES_SUB_PRO = 13,
	SES_SUB_PRO_VER = 14,
	SES_REQ_SIZE = 15,
	SES_REP_SIZE = 16,
	SES_SRC_MAC = 17,
	SES_DST_MAC = 18,
};
enum{
	OPR_FLOW_SIGN = 0X21,
	OPR_SIGN = 0X22,
	OPR_COMMAND = 0X23,
	OPR_REPLY = 0X24,
    
	OPR_START_TIME = 0X25,
	OPR_END_TIME = 0X26,
	OPR_REQ_SIZE = 0X27,
	OPR_REP_SIZE = 0X28,
};
enum{
	PARA_STRING = 0x3f,
	PARA_INT = 0x03,
};
enum{
    SEND_NOT_IMMEDIATELY = 0,
    SEND_IMMEDIATELY = 1,
};
enum{
    COMPLETE_NO_SPILT = 0,
    SPILT_NOT_LAST = 1,
    SPILT_LAST = 2,
};



static uint8_t HILI_DB2_E2A[256] = {
      0,  1,  2,  3,156,  9,134,127,151,141,142, 11, 12, 13, 14, 15,
     16, 17, 18, 19,157,133,  8,135, 24, 25,146,143, 28, 29, 30, 31,
    128,129,130,131,132, 10, 23, 27,136,137,138,139,140,  5,  6,  7,
    144,145, 22,147,148,149,150,  4,152,153,154,155, 20, 21,158, 26,
     32,160,161,162,163,164,165,166,167,168, 91, 46, 60, 40, 43, 33,
     38,169,170,171,172,173,174,175,176,177, 93, 36, 42, 41, 59, 94,
     45, 47,178,179,180,181,182,183,184,185,124, 44, 37, 95, 62, 63,
    186,187,188,189,190,191,192,193,194, 96, 58, 35, 64, 39, 61, 34,
    195, 97, 98, 99,100,101,102,103,104,105,196,197,198,199,200,201,
    202,106,107,108,109,110,111,112,113,114,203,204,205,206,207,208,
    209,126,115,116,117,118,119,120,121,122,210,211,212,213,214,215,
    216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,
    123, 65, 66, 67, 68, 69, 70, 71, 72, 73,232,233,234,235,236,237,
    125, 74, 75, 76, 77, 78, 79, 80, 81, 82,238,239,240,241,242,243,
     92,159, 83, 84, 85, 86, 87, 88, 89, 90,244,245,246,247,248,249,
     48, 49, 50, 51, 52, 53, 54, 55, 56, 57,250,251,252,253,254,255
};

typedef enum
{
    HILI_DB2_TYPE_EXCSAT = 0X1041,//0
    HILI_DB2_TYPE_EXCSATRD = 0X1443,//1
    HILI_DB2_TYPE_ACCSEC = 0X106d,//0
    HILI_DB2_TYPE_ACCSECRD = 0x14ac,//1
    HILI_DB2_TYPE_SECCHK = 0x106e,//0
    HILI_DB2_TYPE_SECCHKRM = 0x1219,//1
    HILI_DB2_TYPE_SVCERRNO = 0x11b4,//1
    HILI_DB2_TYPE_ACCRDB = 0x2001,//0
    HILI_DB2_TYPE_ACCRDBRM = 0x2201,//1
    HILI_DB2_TYPE_RDBNACRM = 0x2204,//1
    HILI_DB2_TYPE_EXCSQLSET = 0x2014,//0
    HILI_DB2_TYPE_SQLSTT = 0x2414,//0
    HILI_DB2_TYPE_SQLATTR = 0x2450,//0
    HILI_DB2_TYPE_PRPSQLSTT = 0x200d,//0
    HILI_DB2_TYPE_SQLCARD = 0x2408,//1
    HILI_DB2_TYPE_SQLDARD = 0x2411,//1
    HILI_DB2_TYPE_DSCSQLSTT = 0x2008,//0
    HILI_DB2_TYPE_OPNQRY = 0x200c,//0
    HILI_DB2_TYPE_OPNQRYRM = 0x2205,//1
    HILI_DB2_TYPE_OPNQFLRM = 0x2212,//1
    HILI_DB2_TYPE_ENDQRYRM = 0x220b,//1
    HILI_DB2_TYPE_QRYDSC = 0x241a,//1
    HILI_DB2_TYPE_QRYDTA = 0x241b,//1
    HILI_DB2_TYPE_CLSQRY = 0x2005,//0
    HILI_DB2_TYPE_RDBCMM = 0x200e,//0
    HILI_DB2_TYPE_ENDUOWRM = 0x220c,//1
    HILI_DB2_TYPE_SQLDTA = 0X2412,
	HILI_DB2_TYPE_MONITORRD = 0x1c00,

}hili_db2_content_type_e;


static char *HILI_DB2_CONTENT_TYPE_ARRAY[] = 
{
    "",
    "DRDA_TYPE_EXCSAT", 
    "DRDA_TYPE_EXCSATRD",
    "DRDA_TYPE_ACCSEC",
    "DRDA_TYPE_ACCSECRD",
    "DRDA_TYPE_SECCHK",
    "DRDA_TYPE_SECCHKRM",
    "DRDA_TYPE_SVCERRNO",
    "DRDA_TYPE_ACCRDB",
    "DRDA_TYPE_ACCRDBRM",
    "DRDA_TYPE_RDBNACRM",
    "DRDA_TYPE_EXCSQLSET",
    "DRDA_TYPE_SQLSTT",
    "DRDA_TYPE_SQLATTR",
    "DRDA_TYPE_PRPSQLSTT",
    "DRDA_TYPE_SQLCARD",
    "DRDA_TYPE_SQLDARD",
    "DRDA_TYPE_DSCSQLSTT",
    "DRDA_TYPE_OPNQRY",
    "DRDA_TYPE_OPNQRYRM",
    "DRDA_TYPE_OPNQFLRM",
    "DRDA_TYPE_ENDQRYRM",
    "DRDA_TYPE_QRYDSC",
    "DRDA_TYPE_QRYDTA",
    "DRDA_TYPE_CLSQRY",
    "DRDA_TYPE_RDBCMM",
    "DRDA_TYPE_ENDUOWRM",
    
};



typedef enum
{
    DRDA_DATA_ETN_NAM = 0X115E,
    DRDA_DATA_MNG_LVL_LST = 0X1404,
    DRDA_DATA_SVR_CLS_NAM = 0X1147,
    DRDA_DATA_SVR_NAM = 0X116D,
    DRDA_DATA_SVR_PRD_RLS_LVL = 0X115A,
    
    DRDA_DATA_SEC_MEC = 0X11A2,
    DRDA_DATA_RLT_DBS_NAM = 0X2110,
    DRDA_DATA_SEC_TKN = 0X11DC,
    
    DRDA_DATA_SEC_CHK_COD = 0X11A4,
    
    DRDA_DATA_PWD = 0X11A1,
    DRDA_DATA_UID_TGT_SYS = 0X11A0,
    
    DRDA_DATA_SEC_COD = 0X1149,
    
    DRDA_DATA_RDB_ACS_MNG_CLS = 0X210F,
    DRDA_DATA_CRL_TKN = 0X2135,
    DRDA_DATA_PRD_SPC_IDF = 0X112E,
    DRDA_DATA_DAT_TYP_DEF_NAM = 0X002F,
    DRDA_DATA_TYP_OVR = 0X0035,
    DRDA_DATA_PRD_SPC_DAT = 0X2104,
    DRDA_DATA_TGT_DEF_VAL_RTN = 0X213B,
    
    DRDA_DATA_RDB_PKG_NAM = 0X2113,
    
    DRDA_DATA_DAT = 0X0000,
    
    /*0X2450-SQLATTR NO PKG CAPTURED*/
    
    DRDA_DATA_QRY_BLK_SIZ = 0X2114,
    DRDA_DATA_MAX_NUM_EXT_BLK = 0X2141,
    
    DRDA_DATA_QRY_PTC_TYP = 0X2102,
    DRDA_DATA_QRY_ATB_UPD = 0X2150,
    DRDA_DATA_QRY_INS_IDF = 0X215B,
    
    DRDA_DATA_UNI_WRK_DSP = 0X2115,
    
}hili_db2_payload_data_type_e;



typedef struct/*record the information of cache and buffer*/
{
    hili_db2_content_type_e content_type;
    void *mitm_flow_ptr;
    uint8_t direction;

    uint16_t client_port;
    uint16_t server_port;
    uint32_t client_ip;
    uint32_t server_ip;
	uint64_t session_id;
    uint64_t flow_id;
    uint8_t cli_mac[6];
	uint8_t srv_mac[6];
    uint64_t magic_number;
    uint16_t pre_len;
    uint16_t tail_len;

    uint8_t log_location[3];/* mark the beginning add of each valid content */
    uint32_t log_length[3];
    uint16_t num_para;		//for para mode
    uint16_t qrydsc_len;
    uint16_t qrydta_len;

    uint16_t drda_pkt_length; /*bytes to read in pkt buffer*/

    uint8_t need_to_log;
	uint8_t primary_account[64]; 
	
	uint32_t function_flags;
    uint32_t request_bytes;
	uint64_t session_handle;
	uint64_t operation_handle;

    idpi_util_fifo_cache_t* request_fifo_cache_ptr;
    idpi_util_fifo_cache_t* response_fifo_cache_ptr;
	

}hili_db2_parser_t;

static inline void *hili_db2_alloc_parser()
{
#ifndef CONTENT_H_IN_TEST
    return hili_common_fpa_alloc(CVM_FPA_512B_POOL);
#endif
#ifdef CONTENT_H_IN_TEST
    return (void *)malloc(2048);
#endif
}

static inline void hili_db2_free_parser(void *ptr)
{
#ifndef CONTENT_H_IN_TEST
    hili_common_fpa_free(ptr, CVM_FPA_512B_POOL, CVM_FPA_512B_POOL_SIZE/CVMX_CACHE_LINE_SIZE);
#endif
#ifdef CONTENT_H_IN_TEST
    free(ptr);
#endif
}

static inline void *hili_db2_alloc_memo()
{
#ifndef CONTENT_H_IN_TEST
    return hili_common_fpa_alloc(CVM_FPA_512B_POOL);
#endif
#ifdef CONTENT_H_IN_TEST
    return (void *)malloc(2048);
#endif
}

static inline void hili_db2_free_memo(void *ptr)
{
#ifndef CONTENT_H_IN_TEST
    hili_common_fpa_free(ptr, CVM_FPA_512B_POOL, CVM_FPA_512B_POOL_SIZE/CVMX_CACHE_LINE_SIZE);
#endif
#ifdef CONTENT_H_IN_TEST
    free(ptr);
#endif
}


extern void* hili_db2_parse_flow_init();
extern int idpi_http_parse_kill_flow(void* drda_flow_ptr);
//extern int hili_db2_parse_processing(hili_db2_parser_t* drda_flow_ptr, void* buf, uint32_t buf_len, uint8_t direction);
void hili_db2_context_init(hili_db2_parser_t *drda_flow_ptr);
//void* hili_db2_parse_flow_init();
int hili_db2_parse_free_backup_cache_block(hili_db2_parser_t* drda_flow_ptr);
int hili_db2_parse_payload(hili_db2_parser_t* drda_flow_ptr, uint64_t offset, uint8_t direction);
int hili_db2_print_header(hili_db2_parser_t *ptr);
int hili_db2_parse_alloc_logbuf(hili_db2_parser_t *ptr);
int hili_db2_parse_print_logbuf(hili_db2_parser_t *ptr);
int hili_db2_parse_send_logbuf(hili_db2_parser_t *ptr, unsigned char is_segmented, unsigned char is_last_segment);
int hili_db2_parse_send_paralogbuf(hili_db2_parser_t *ptr, unsigned char is_segmented, unsigned char is_last_segment);
int hili_db2_parse_create_log(hili_db2_parser_t *ptr);
int hili_db2_parse_free_logbuf(hili_db2_parser_t *ptr);
int hili_db2_parse_log_process(hili_db2_parser_t* drda_flow_ptr, uint64_t offset, int last_direction);
int hili_db2_parse_log_key_data(hili_db2_parser_t* drda_flow_ptr, uint8_t *copy_start_p, uint32_t copy_length, uint8_t cache_block_num);
uint32_t hili_db2_parse_find_last_length(hili_db2_parser_t* drda_flow_ptr, uint32_t buf_len);




#endif
