/*
Name : certificates.h

Description :
            Header file for certificate handling in the ESP32 HTTPS server.
            Declares global certificate buffers and the function to load
            TLS server certificate and private key from the NVS partition ("crts").

Author : Akbar Shah

Date : 2025-05-07
*/

#ifndef _CERTIFICATES_H
#define _CERTIFICATES_H

#include <stdint.h>
#include <string.h>

extern char *SERVER_CERTIFICATE;
extern char *PRIVATE_KEY;

extern uint32_t SEVRER_CERTIFICATE_SIZE;
extern uint32_t PRIVATE_KEY_SIZE;

esp_err_t load_certificates_from_nvs(void);

#endif
