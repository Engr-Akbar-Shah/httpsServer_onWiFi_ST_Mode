/*
Name : st_server.c

Description :
This file implements the core logic for a secure HTTPS server running on an ESP32.
It includes handlers for GET/POST/PUT/DELETE methods, mDNS setup, dynamic URI registration,
and runtime interaction via HTML and JavaScript over TLS.

Author : Akbar Shah

Date : May 7, 2025
*/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include <sys/param.h>
#include "esp_event.h"
#include "esp_check.h"
#include <esp_system.h>
#include <esp_log.h>

#include "mdns.h"

#include "certificates.h"
#include "st_server.h"
#include "wifi.h"

#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN (64)

static const char *TAG = "ST_Server";

static const httpd_uri_t info_uri;

extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[] asm("_binary_index_html_end");

/*
Function : set_mdns_name_server

Description : Initializes the mDNS service and sets the hostname and instance name for
              the ESP32 device.

Parameter : None

Return : esp_err_t

Example Call : esp_err_t err = set_mdns_name_server();
*/
void set_mdns_name_server(void)
{
    ESP_ERROR_CHECK(mdns_init());

    ESP_ERROR_CHECK(mdns_hostname_set(CONFIG_SET_MDNS_HOST_NAME));
    ESP_LOGI("mDNS", "mDNS hostname set to: %s.local", CONFIG_SET_MDNS_HOST_NAME);

    ESP_ERROR_CHECK(mdns_instance_name_set(CONFIG_SET_MDNS_HOST_NAME_INSTANCE));
    ESP_LOGI("mDNS", "mDNS instance name set to: %s", CONFIG_SET_MDNS_HOST_NAME_INSTANCE);

    ESP_ERROR_CHECK(mdns_service_add(NULL, "_https", "_tcp", 443, NULL, 0));

    ESP_LOGI("mDNS", "mDNS initialized");
}

/*
Function : event_handler

Description : Handles HTTPS server-related events like TLS error reporting.

Parameter : void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data

Return : None

Example Call : (registered internally using esp_event_handler_register)
*/
static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data)
{
    if (event_base == ESP_HTTPS_SERVER_EVENT)
    {
        if (event_id == HTTPS_SERVER_EVENT_ERROR)
        {
            esp_https_server_last_error_t *last_error = (esp_tls_last_error_t *)event_data;
            ESP_LOGD(TAG, "Error event triggered: last_error = %s, last_tls_err = %d, tls_flag = %d", esp_err_to_name(last_error->last_error), last_error->esp_tls_error_code, last_error->esp_tls_flags);
        }
    }
}

#if CONFIG_ENABLE_HTTPS_USER_CALLBACK
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS

/*
Function : print_peer_cert_info

Description : Logs details of the peer's SSL certificate for debugging purposes.

Parameter : const mbedtls_ssl_context *ssl

Return : None

Example Call : print_peer_cert_info(ssl_ctx);
*/
static void print_peer_cert_info(const mbedtls_ssl_context *ssl)
{
    const mbedtls_x509_crt *cert;
    const size_t buf_size = 1024;
    char *buf = calloc(buf_size, sizeof(char));
    if (buf == NULL)
    {
        ESP_LOGE(TAG, "Out of memory - Callback execution failed!");
        return;
    }

    // Logging the peer certificate info
    cert = mbedtls_ssl_get_peer_cert(ssl);
    if (cert != NULL)
    {
        mbedtls_x509_crt_info((char *)buf, buf_size - 1, "    ", cert);
        ESP_LOGI(TAG, "Peer certificate info:\n%s", buf);
    }
    else
    {
        ESP_LOGW(TAG, "Could not obtain the peer certificate!");
    }

    free(buf);
}
#endif

/*
Function : https_server_user_callback

Description : Handles HTTPS session events like session creation and closure. Logs peer
              certificate info and socket details.

Parameter : esp_https_server_user_cb_arg_t *user_cb

Return : None

Example Call : (assigned to conf.user_cb in start_webserver)
*/
static void https_server_user_callback(esp_https_server_user_cb_arg_t *user_cb)
{
    ESP_LOGI(TAG, "User callback invoked!");
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
    mbedtls_ssl_context *ssl_ctx = NULL;
#endif
    switch (user_cb->user_cb_state)
    {
    case HTTPD_SSL_USER_CB_SESS_CREATE:
        ESP_LOGD(TAG, "At session creation");

        // Logging the socket FD
        int sockfd = -1;
        esp_err_t esp_ret;
        esp_ret = esp_tls_get_conn_sockfd(user_cb->tls, &sockfd);
        if (esp_ret != ESP_OK)
        {
            ESP_LOGE(TAG, "Error in obtaining the sockfd from tls context");
            break;
        }
        ESP_LOGI(TAG, "Socket FD: %d", sockfd);
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
        ssl_ctx = (mbedtls_ssl_context *)esp_tls_get_ssl_context(user_cb->tls);
        if (ssl_ctx == NULL)
        {
            ESP_LOGE(TAG, "Error in obtaining ssl context");
            break;
        }
        // Logging the current ciphersuite
        ESP_LOGI(TAG, "Current Ciphersuite: %s", mbedtls_ssl_get_ciphersuite(ssl_ctx));
#endif
        break;

    case HTTPD_SSL_USER_CB_SESS_CLOSE:
        ESP_LOGD(TAG, "At session close");
#ifdef CONFIG_ESP_TLS_USING_MBEDTLS
        // Logging the peer certificate
        ssl_ctx = (mbedtls_ssl_context *)esp_tls_get_ssl_context(user_cb->tls);
        if (ssl_ctx == NULL)
        {
            ESP_LOGE(TAG, "Error in obtaining ssl context");
            break;
        }
        print_peer_cert_info(ssl_ctx);
#endif
        break;
    default:
        ESP_LOGE(TAG, "Illegal state!");
        return;
    }
}
#endif

/*
Function : uri_decode

Description : Decodes a URL-encoded string into a plain string, replacing encoded
              characters and '+' with spaces.

Parameter : char *out, const char *in, size_t len

Return : None

Example Call : uri_decode(decoded, param, strlen(param));
*/
static void uri_decode(char *out, const char *in, size_t len)
{
    char a, b;
    size_t i, j;
    for (i = 0, j = 0; i < len && in[i]; i++, j++)
    {
        if ((in[i] == '%') &&
            ((a = in[i + 1]) && (b = in[i + 2])) &&
            (isxdigit(a) && isxdigit(b)))
        {
            a = tolower(a);
            b = tolower(b);
            a = (a >= 'a') ? (a - 'a' + 10) : (a - '0');
            b = (b >= 'a') ? (b - 'a' + 10) : (b - '0');
            out[j] = 16 * a + b;
            i += 2;
        }
        else if (in[i] == '+')
        {
            out[j] = ' ';
        }
        else
        {
            out[j] = in[i];
        }
    }
    out[j] = '\0';
}

/*
Function : index_handler

Description : Serves the main HTML page from embedded flash.

Parameter : httpd_req_t *req

Return : esp_err_t

Example Call : Called automatically when "/" endpoint is accessed.
*/
static esp_err_t index_handler(httpd_req_t *req)
{
    const size_t html_len = index_html_end - index_html_start;
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, index_html_start, html_len);
}

/*
Function : submit_handler

Description : Handles GET requests for the /submit endpoint and displays the user's submitted message.

Parameter : httpd_req_t *req

Return : esp_err_t

Example Call : Triggered via GET form submission.
*/
static esp_err_t submit_handler(httpd_req_t *req)
{
    char query[100], param[100] = {0}, decoded[100] = {0};

    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        httpd_query_key_value(query, "message", param, sizeof(param));
        uri_decode(decoded, param, strlen(param));
    }

    char response[512];
    snprintf(response, sizeof(response),
             "<!DOCTYPE html><html><body>"
             "<h1>ST Server Dev Hub</h1>"
             "<form action='/submit' method='GET'>"
             "<input type='text' name='message' placeholder='Type something here...' required />"
             "<br><input type='submit' value='Submit' /></form>"
             "<div class='response-box'>This was your text: <b>%s</b></div>"
             "</body></html>",
             decoded);

    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
}

/*
Function : handle_post

Description : Handles POST requests sent to /api/post and echoes the received data back.

Parameter : httpd_req_t *req

Return : esp_err_t

Example Call : Triggered via Fetch API POST request.
*/
static esp_err_t handle_post(httpd_req_t *req)
{
    char buf[100];
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0)
        return ESP_OK;
    buf[ret] = 0;
    ESP_LOGI("POST", "Received: %s", buf);
    httpd_resp_send(req, buf, ret);
    return ESP_OK;
}

/*
Function : handle_put

Description : Handles PUT requests sent to /api/put and echoes the received data back.

Parameter : httpd_req_t *req

Return : esp_err_t

Example Call : Triggered via Fetch API PUT request.
*/
static esp_err_t handle_put(httpd_req_t *req)
{
    char buf[100];
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0)
        return ESP_OK;
    buf[ret] = 0;
    ESP_LOGI("PUT", "Received: %s", buf);
    httpd_resp_send(req, buf, ret);
    return ESP_OK;
}

/*
Function : handle_delete

Description : Handles DELETE requests sent to /api/delete and echoes the received data back.

Parameter : httpd_req_t *req

Return : esp_err_t

Example Call : Triggered via Fetch API DELETE request.
*/
static esp_err_t handle_delete(httpd_req_t *req)
{
    char buf[100];
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf) - 1));
    if (ret <= 0)
        return ESP_OK;
    buf[ret] = 0;
    ESP_LOGI("DELETE", "Received: %s", buf);
    httpd_resp_send(req, buf, ret);
    return ESP_OK;
}

/*
Function : info_get_handler

Description : Responds to GET requests at /info endpoint with JSON-formatted device info.

Parameter : httpd_req_t *req

Return : esp_err_t

Example Call : Triggered via dynamic URI registration.
*/
static esp_err_t info_get_handler(httpd_req_t *req)
{
    const char *resp_str =
        "{ \"device\": \"ESP32\", \"uuid\": \"ABC123DEF456\", \"mem\": \"520KB RAM\", \"wifi\": \"MySSID\" }";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/*
Function : http_404_error_handler

Description : Custom 404 handler, provides special response for /info and default for others.

Parameter : httpd_req_t *req, httpd_err_code_t err

Return : esp_err_t

Example Call : Automatically called for unmatched URIs.
*/
static esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/info", req->uri) == 0)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/info URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

/*
Function : ctrl_put_handler

Description : Handles URI registration/unregistration at runtime based on PUT data ('0' to unregister, other to register /info).

Parameter : httpd_req_t *req

Return : esp_err_t

Example Call : Triggered via PUT request to /ctrl.
*/
static esp_err_t ctrl_put_handler(httpd_req_t *req)
{
    char buf;
    int ret;

    if ((ret = httpd_req_recv(req, &buf, 1)) <= 0)
    {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT)
        {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    if (buf == '0')
    {
        ESP_LOGI(TAG, "Unregistering /info URI");
        httpd_unregister_uri(req->handle, "/info");
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }
    else
    {
        ESP_LOGI(TAG, "Registering /info URI");
        httpd_register_uri_handler(req->handle, &info_uri);
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }

    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t index_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = index_handler,
    .user_ctx = NULL};

static const httpd_uri_t submit_uri = {
    .uri = "/submit",
    .method = HTTP_GET,
    .handler = submit_handler,
    .user_ctx = NULL};

static const httpd_uri_t post_uri = {
    .uri = "/api/post",
    .method = HTTP_POST,
    .handler = handle_post};

static const httpd_uri_t put_uri = {
    .uri = "/api/put",
    .method = HTTP_PUT,
    .handler = handle_put};

static const httpd_uri_t delete_uri = {
    .uri = "/api/delete",
    .method = HTTP_DELETE,
    .handler = handle_delete};

static const httpd_uri_t ctrl_uri = {
    .uri = "/ctrl",
    .method = HTTP_PUT,
    .handler = ctrl_put_handler,
    .user_ctx = NULL};

static const httpd_uri_t info_uri = {
    .uri = "/info",
    .method = HTTP_GET,
    .handler = info_get_handler,
    .user_ctx = NULL};

/*
Function : stop_webserver

Description : Stops the HTTPS server and frees certificate memory.

Parameter : httpd_handle_t server

Return : esp_err_t

Example Call : stop_webserver(server);
*/
static esp_err_t stop_webserver(httpd_handle_t server)
{
    esp_err_t err = ESP_FAIL;
    if (server)
    {
        err = httpd_ssl_stop(server);
        ESP_LOGI(TAG, "HTTPS server stopped");
    }

    if (SERVER_CERTIFICATE)
    {
        free(SERVER_CERTIFICATE);
        SERVER_CERTIFICATE = NULL;
    }

    if (PRIVATE_KEY)
    {
        free(PRIVATE_KEY);
        PRIVATE_KEY = NULL;
    }
    return err;
}

/*
Function : disconnect_handler

Description : Event handler that stops the webserver when Wi-Fi disconnects.

Parameter : void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data

Return : esp_err_t

Example Call : Registered to WIFI_EVENT_STA_DISCONNECTED
*/
static void disconnect_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server)
    {
        ESP_LOGI(TAG, "Stopping webserver");
        if (stop_webserver(*server) == ESP_OK)
        {
            *server = NULL;
        }
        else
        {
            ESP_LOGE(TAG, "Failed to stop http server");
        }
    }
}

/*
Function : connect_handler

Description : Event handler that starts the webserver on successful IP acquisition.

Parameter : void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data

Return : esp_err_t

Example Call : Registered to IP_EVENT_STA_GOT_IP
*/
static void connect_handler(void *arg, esp_event_base_t event_base,
                            int32_t event_id, void *event_data)
{
    httpd_handle_t *server = (httpd_handle_t *)arg;
    if (*server == NULL)
    {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}

/*
Function : register_auto_connect_handler

Description : Registers event handlers for automatic server start/stop based on Wi-Fi connectivity.

Parameter : None

Return : None

Example Call : register_auto_connect_handler();
*/
esp_err_t register_auto_connect_handler(void)
{
    static httpd_handle_t server = NULL;
    /* Register event handlers to stop the server when Wi-Fi or Ethernet is disconnected,
     * and re-start it upon connection.
     */
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));

    ESP_ERROR_CHECK(esp_event_handler_register(ESP_HTTPS_SERVER_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
    return ESP_OK;
}

/*
Function : start_webserver

Description : Loads certificates, sets up the HTTPS server, registers all URI handlers, and starts the server.

Parameter : None

Return : httpd_handle_t - handle to the HTTPS server

Example Call : server = start_webserver();
*/
httpd_handle_t start_webserver(void)
{
    esp_err_t err = load_certificates_from_nvs();
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to load certificates: %s", esp_err_to_name(err));
        return NULL;
    }

    httpd_handle_t server = NULL;
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();

    conf.servercert = (const uint8_t *)SERVER_CERTIFICATE;
    conf.servercert_len = SEVRER_CERTIFICATE_SIZE + 1;

    conf.prvtkey_pem = (const uint8_t *)PRIVATE_KEY;
    conf.prvtkey_len = PRIVATE_KEY_SIZE + 1;

#if CONFIG_ENABLE_HTTPS_USER_CALLBACK
    conf.user_cb = https_server_user_callback;
#endif

#if CONFIG_DEBUG_MBEDTLS_ERRORS
    esp_log_level_set("mbedtls", ESP_LOG_DEBUG);
    esp_log_level_set("esp-tls", ESP_LOG_DEBUG);
    esp_log_level_set("esp_https_server", ESP_LOG_DEBUG);
    esp_log_level_set("esp-tls-mbedtls", ESP_LOG_DEBUG);
#endif
#if !CONFIG_ENABLE_MBEDTLS_LOGS
    esp_log_level_set("httpd", ESP_LOG_NONE);
    esp_log_level_set("esp-tls-mbedtls", ESP_LOG_NONE);
    esp_log_level_set("esp_https_server", ESP_LOG_NONE);
#endif

    set_mdns_name_server();

    ESP_LOGI(TAG, "Starting server");
    if (httpd_ssl_start(&server, &conf) == ESP_OK)
    {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &index_uri);
        httpd_register_uri_handler(server, &submit_uri);
        httpd_register_uri_handler(server, &post_uri);
        httpd_register_uri_handler(server, &put_uri);
        httpd_register_uri_handler(server, &delete_uri);
        httpd_register_uri_handler(server, &ctrl_uri);

        return server;
    }

    ESP_LOGE(TAG, "Error starting server!");
    return NULL;
}
