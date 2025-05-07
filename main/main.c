/*
Name : 

Description : 

Author : 

Date : 
*/

#include "st_server.h"
#include "wifi.h"
#include "esp_check.h"

void app_main(void)
{
    connect_wifi_st();

    register_auto_connect_handler();

    start_webserver();

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(5000));  // 5-second delay
    }
}
