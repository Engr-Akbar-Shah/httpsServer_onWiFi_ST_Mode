#ifndef _CERTIFICATES_H
#define _CERTIFICATES_H

#include <stdint.h>
#include <string.h>

extern char *SEVRER_CERTIFICATE;
extern char *PRIVATE_KEY;

extern uint32_t SEVRER_CERTIFICATE_SIZE;
extern uint32_t PRIVATE_KEY_SIZE;

esp_err_t load_certificates_from_nvs(void);

#endif
