/*
Name : st_server.h

Description :
This file implements the core logic for a secure HTTPS server running on an ESP32.
It includes handlers for GET/POST/PUT/DELETE methods, mDNS setup, dynamic URI registration,
and runtime interaction via HTML and JavaScript over TLS.

Author : Akbar Shah

Date : May 7, 2025
*/

#ifndef _ST_SERVER_H
#define _ST_SERVER_H

#include <esp_https_server.h>

httpd_handle_t start_webserver(void);

esp_err_t register_auto_connect_handler(void);

#endif