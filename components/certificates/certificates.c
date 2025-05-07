/*
Name : certificates.c

Description :
            Handles loading of TLS certificate and private key from a dedicated NVS partition ("crts").
            Allocates memory dynamically for the PEM strings and makes them available 
            globally for use in HTTPS server configuration.

Author : Akbar Shah

Date : May 7, 2025
*/

#include <esp_system.h>
#include "nvs_flash.h"
#include <esp_log.h>

#include "certificates.h"

static const char *TAG = "CERTIFICATES";

char *SERVER_CERTIFICATE = NULL;
char *PRIVATE_KEY = NULL;

uint32_t SEVRER_CERTIFICATE_SIZE = 0;
uint32_t PRIVATE_KEY_SIZE = 0;

/*
Function : load_certificates_from_nvs

Description :
            Initializes the "crts" NVS partition, reads TLS server certificate and private key strings,
            allocates memory for them, and loads their content into global pointers for use in HTTPS 
            configuration.

Parameter : None

Return :
        esp_err_t – ESP_OK on success, or appropriate ESP-IDF error code on failure 
        (e.g., memory allocation, NVS errors)

Example Call :
            ESP_ERROR_CHECK(load_certificates_from_nvs());
*/
esp_err_t load_certificates_from_nvs()
{
    esp_err_t err = nvs_flash_init_partition("crts");
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase_partition("crts"));
        ESP_ERROR_CHECK(nvs_flash_init_partition("crts"));
    }

    nvs_handle_t nvs;
    err = nvs_open_from_partition("crts", "storage", NVS_READONLY, &nvs);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
        return err;
    }

    nvs_get_u32(nvs, "serverCertSize", &SEVRER_CERTIFICATE_SIZE);
    nvs_get_u32(nvs, "privateKeySize", &PRIVATE_KEY_SIZE);

    if (SEVRER_CERTIFICATE_SIZE == 0 || PRIVATE_KEY_SIZE == 0)
    {
        ESP_LOGE(TAG, "Certificate sizes not found");
        nvs_close(nvs);
        return err;
    }

    SERVER_CERTIFICATE = malloc(SEVRER_CERTIFICATE_SIZE + 1);
    PRIVATE_KEY = malloc(PRIVATE_KEY_SIZE + 1);

    if (!SERVER_CERTIFICATE || !PRIVATE_KEY)
    {
        ESP_LOGE(TAG, "Memory allocation failed");
        nvs_close(nvs);
        return ESP_FAIL;
    }

    size_t len = SEVRER_CERTIFICATE_SIZE + 1;
    err = nvs_get_str(nvs, "serverCert", SERVER_CERTIFICATE, &len);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to read serverCert: %s", esp_err_to_name(err));
        goto cleanup;
    }

    len = PRIVATE_KEY_SIZE + 1;
    err = nvs_get_str(nvs, "privateKey", PRIVATE_KEY, &len);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to read privateKey: %s", esp_err_to_name(err));
        goto cleanup;
    }

    ESP_LOGI(TAG, "Certificates loaded successfully.");

cleanup:
    nvs_close(nvs);
    return err;
}
