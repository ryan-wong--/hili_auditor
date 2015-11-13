#ifndef HILI_DB2_PARSER_H
#define HILI_DB2_PARSER_H

#include "hili_dummy_mitm.h"

int hili_db2_parse_processing(void* db2_parse_flow_ptr, dummy_updata_t *mitm_data_up_ptr);

void* hili_db2_parse_flow_init(dummy_mitm_parse_init_info_t *mitm_parse_init_info_ptr);

void hili_db2_parse_kill_flow(void *db2_parse_flow_ptr);


#endif
