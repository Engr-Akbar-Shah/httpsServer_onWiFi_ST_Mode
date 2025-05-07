/*
Name : main.c

Description :
            Entry point of the ST Server Dev Hub application for ESP32.
            Initializes Wi-Fi, registers event handlers for automatic web server
            start/stop based on network connectivity, and starts the HTTPS web server.

Author : Akbar Shah

Date : 07/05/2025
*/

#include "st_server.h"
#include "wifi.h"
#include "esp_check.h"

void app_main(void)
{
    esp_err_t ret;

    ret = connect_wifi_st();
    if (ret == ESP_OK)
    {
        ESP_LOGI("MAIN", "Wi-Fi connected successfully.");
    }
    else
    {
        ESP_LOGE("MAIN", "Wi-Fi connection failed: %s", esp_err_to_name(ret));
    }

    ret = register_auto_connect_handler();
    if (ret == ESP_OK)
    {
        ESP_LOGI("MAIN", "HTTPS server event handlers registered.");
    }
    else
    {
        ESP_LOGE("MAIN", "Failed to register HTTPS event handlers: %s", esp_err_to_name(ret));
    }

    if (start_webserver() != NULL)
    {
        ESP_LOGI("MAIN", "HTTPS web server started successfully.");
    }
    else
    {
        ESP_LOGE("MAIN", "Failed to start HTTPS web server.");
    }

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(5000)); // Keep main task alive
    }
}
