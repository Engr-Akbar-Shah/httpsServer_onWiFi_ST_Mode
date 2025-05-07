/*
Name : wifi.h

Description : Header file for initializing and connecting the ESP32 to a Wi-Fi network in Station (STA) mode.
              Declares the interface to start the Wi-Fi connection process using the ESP-IDF Wi-Fi and event libraries.

Author : Akbar Shah

Date : May 7, 2025
*/

#ifndef _WIFI_H
#define _WIFI_H

#include "esp_wifi.h"
#include "esp_event.h"

esp_err_t connect_wifi_st(void);

#endif