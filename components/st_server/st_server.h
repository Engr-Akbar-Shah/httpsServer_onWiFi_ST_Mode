/*
Name : 

Description : 

Author : 

Date : 
*/

#ifndef _ST_SERVER_H
#define _ST_SERVER_H

#include <esp_https_server.h>

httpd_handle_t start_webserver(void);

void register_auto_connect_handler(void);

#endif