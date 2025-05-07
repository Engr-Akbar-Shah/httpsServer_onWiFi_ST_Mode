# ST Server Dev Hub

**Secure ESP32 HTTPS Server with Dynamic Endpoints**
## Overview

This project demonstrates a secure HTTPS web server running on an ESP32 in station mode, with support for interactive web features and a fallback AP mode. It showcases the following capabilities:

Secure HTTPS using a device-specific TLS certificate and private key stored in NVS.

Web interface accessible via mDNS hostname (e.g. https://esp32.local) on the local network.

GET form submission: A simple HTML form that sends a GET request and displays the response.

Dynamic HTTP methods: Buttons that use JavaScript (Fetch API) to send POST, PUT, and DELETE requests without reloading the page.

Dynamic URI registration: Ability to register new URI handlers at runtime via a control endpoint (demonstrated by adding an /info endpoint on the fly to show device info).

Fallback Access Point (AP) mode: If Wi-Fi STA connection fails, the ESP32 can switch to AP mode and host the same web server for direct access.

The goal is to provide a “Dev Hub” for experimenting with HTTP methods on ESP32 over a secure connection, easily accessible by name on a LAN and robust to network connectivity issues.
## Components

This project is organized into multiple ESP-IDF components, each with a specific role:

certificates – Handles loading of the TLS server certificate and private key from NVS. On startup, it opens a dedicated NVS partition (named "crts") and reads the stored PEM certificate and key into memory. These credentials (provisioned per device by a Python script) are then used by the HTTPS server for secure communication.

wifi – Manages the Wi-Fi Station (STA) connection. It initializes the ESP32 Wi-Fi in station mode using the SSID and password provided in the config, and attempts to connect to your router. It implements a retry mechanism (configurable max retries) and posts events on connection or failure. On successful connection (IP acquired), it will trigger the launch of the web server. If the connection cannot be established (e.g., wrong credentials or network unavailable), a flag is set so the system can initiate fallback AP mode.

st_server – Implements the HTTPS web server logic and routes. It configures and starts the ESP-IDF HTTPS server (httpd_ssl), supplying the certificate and key from the certificates component. This component registers the URI handlers for the application:

Main page (/) – Serves the HTML/JavaScript interface (an embedded index.html).

Submit handler (/submit) – Handles GET requests from the form (reads a query parameter and responds with a page showing the message).

API handlers (/api/post, /api/put, /api/delete) – Handle AJAX requests for POST/PUT/DELETE, echoing back the received message (used by the dynamic buttons).

Control handler (/ctrl) – Handles requests to trigger runtime actions (used to register new URIs).

It also initializes mDNS (configuring the hostname as set in the config, e.g. esp32.local) so the device can be reached by name on the network. This component ties everything together: starting/stopping the server on network events and providing an event callback (if enabled) for HTTPS events.

server_ap – Provides fallback Access Point functionality. If the station mode fails to connect to Wi-Fi (after the maximum retry count), this component will set up the ESP32 as a Wi-Fi AP (with a predefined SSID/password or open network as configured) and possibly launch the web server in AP mode. This allows a user to connect directly to the ESP32’s network (typically at default IP 192.168.4.1) and access the web interface for configuration or direct control. Essentially, server_ap ensures the web server is accessible even when normal Wi-Fi is unavailable.

(All components have accompanying source/header files and their own Kconfig options as described below.)
## TLS Certificate Generation and Flashing (generateSaveCerts.py)

Because the server uses HTTPS, each device needs its own certificate and private key. The provided Python script generateSaveCerts.py automates the creation and flashing of these TLS credentials for the ESP32. You should run this script before first flashing/running the device. Its usage is:

python generateSaveCerts.py <OFFSET> <CHIP> <PORT>

For example: python generateSaveCerts.py 0xF000 esp32s3 /dev/ttyUSB0

## What the script does

Reads the device MAC address: It invokes esptool.py to get the unique MAC of the connected ESP32 (via the given serial port).

Generates a self-signed certificate: Using OpenSSL, it creates a new RSA 2048-bit key and a self-signed X.509 certificate valid for ~10 years. The certificate’s subject Common Name (CN) is set to ESP32-<MAC> (embedding the MAC to uniquely identify the device).

Stores files in the project: The generated serverCert_<MAC>.pem (certificate) and privateKey_<MAC>.pem (key) are saved under components/certificates/generated/ for reference.

Prepares NVS data: The script creates an NVS CSV file containing four entries – the certificate (serverCert), the key (privateKey), and their lengths (serverCertSize and privateKeySize). It then uses the ESP-IDF NVS partition tool to convert this CSV into a binary image.

Flashes the credentials to NVS: Finally, it uses esptool.py to write the generated NVS binary to the specified flash offset (e.g. 0xF000, which corresponds to the dedicated crts partition in this project’s partition table).

After running this script, the device’s NVS will contain the TLS materials. (If you ever change the partition offset or size for certificates in the partition table, use the new offset when invoking the script. You can also customize the certificate subject by editing the script – by default it uses the MAC in the CN, but you could change the subj string as needed.)

## mDNS Hostname Support (Managed Component)

To simplify access to the device on a LAN, the project uses Espressif’s mDNS component (included via managed_components/). This was added using the command idf.py add-dependency "espressif/mdns", which fetches the official mDNS library. With mDNS enabled, the ESP32 advertises a hostname on the local network, allowing you to reach it at *.local without knowing its IP address.

By default, the configured hostname is esp32, so the device can be accessed at https://esp32.local once it’s connected to Wi-Fi. The mDNS service is initialized at startup (after Wi-Fi connects), and the project sets an instance name "ESP32 Web Server" for the service. You can change these via Kconfig (see below). mDNS makes development and testing easier – instead of checking the IP from logs or DHCP, you can just use the friendly name in your browser (ensure your computer has mDNS/Bonjour support).

## Configuration Options (Kconfig)

Several build-time configuration options are provided to customize the behavior of the firmware. These can be accessed via idf.py menuconfig under the corresponding menus defined by each component’s Kconfig.projbuild file:

Wi-Fi Configuration: (Menu “WiFi Configuration” in menuconfig)

WiFi SSID and WiFi Password – Set the credentials for the STA connection. By default, they are set to "EmbSysHub" / "Devomech@12121" (placeholders – you should change these to your Wi-Fi network’s SSID and password before flashing).

Maximum Retry – The number of reconnection attempts before considering the Wi-Fi connection failed (default is 5). After this, the device can initiate fallback AP mode.

WPA3 SAE Mode and Auth Mode Threshold – Advanced options for Wi-Fi security. By default, WPA2-PSK is used. You can enable WPA3 or adjust the auth mode threshold if your network requires it (e.g., allow WPA3 or mixed modes).

HTTPS Server Configuration: (Menu “HTTPS Server Configuration”)

Enable user callback with HTTPS Server – If enabled, the server will use the esp_https_server’s user callback feature. This allows the application to get access to the underlying SSL context for each connection (for example, to inspect a client certificate if you were implementing mutual TLS authentication). Enabling this sets the TLS auth mode to “optional” internally. If you don’t need to handle SSL context events, you can leave this disabled.

Enable mbedTLS logs – If enabled, all logs from the mbedTLS library and the ESP-IDF HTTPS server will be output to the console. By default this is off, which means those verbose TLS logs are suppressed (you will only see minimal info or errors). Turn this on if you need to debug TLS handshake issues or want to see details of the secure connection process.

Enable debug mbedTLS errors – If enabled, it sets the log level of various TLS components to DEBUG, providing even more detailed diagnostics from mbedTLS (e.g., entire certificate verification process). This is mainly for deep debugging; typically left disabled. (Note: if TLS logs are disabled in the above option, setting this alone won’t show logs — you’d enable both for full debug output.)

mDNS Hostname – The default mDNS hostname the device will advertise. Default is "esp32". You can change it (for example to "mydevice") if you want the URL to be mydevice.local. This must be a hostname (no spaces, etc.).

mDNS Instance Name – A human-friendly name for the service. Default "ESP32 Web Server". This can be anything (e.g. "My ESP32 Dev Board") and is mainly visible in network browsing tools or bonjour service listings.

AP Mode Configuration: (Menu likely provided by a server_ap component, if present)
If the fallback Access Point mode is utilized, there would be options to configure it, such as:

AP SSID / AP Password – The network name (SSID) and passphrase for the ESP32’s AP. This lets you control how the device’s hotspot will appear. It could default to something like "ESP32_AP" (and either an empty password for open AP or a default password). For security, an AP password is recommended if AP mode is used.

AP Channel – The Wi-Fi channel on which the AP will run (default often 1 or 6).
These settings ensure you know how to connect to the ESP32’s AP if it’s triggered. (If not configured, the code may use hard-coded defaults.)

All these options can be adjusted prior to building the firmware. The defaults are set for a quick start (with example Wi-Fi creds and a generic certificate subject, etc.), but you should review them to match your use case.

## Building and Testing

Follow these steps to build the project and try out the HTTPS server:

Configure Wi-Fi Credentials: Ensure the ESP32 will connect to your Wi-Fi by updating the SSID and password. Run idf.py menuconfig and go to WiFi Configuration → set WiFi SSID/Password to your network. Alternatively, edit the default values in sdkconfig or Kconfig.projbuild before building. (If you prefer to test using only the AP fallback, you can leave the STA credentials as-is and skip to step 2.)

Generate and Flash TLS Certs: Use the provided script to generate the TLS certificate and flash the NVS partition with the cert and key. For example:

python generateSaveCerts.py 0xF000 esp32 /dev/ttyUSB0

Replace esp32 with your chip target if needed (e.g., esp32s3) and /dev/ttyUSB0 with the serial port for your board. This will produce a 16KB NVS image containing serverCert, privateKey, etc., and write it to offset 0xF000 on the flash. You should see messages from the script indicating success (✓). Make sure this step completes without errors before proceeding.

Build the Firmware: In the project directory, run idf.py build. This will compile the application and all components. Ensure you have the ESP-IDF environment set up, since the project depends on the mDNS component (which will be downloaded if not present, per dependencies.lock). A successful build will produce an ELF and bin files.

Flash the Firmware: Once built, flash it to the ESP32 and start the monitor by running:

idf.py -p <PORT> flash monitor

Use the same serial port as in the earlier step. This will erase the old application (but will preserve the NVS partitions by default) and upload the new firmware. After flashing, the tool will attach a serial monitor so you can see logs in real time.

Wi-Fi Connection: On boot, the firmware will initialize Wi-Fi in station mode and try to connect to the configured network. In the serial output, watch for log lines indicating connection status. You should see something like wifi station: connected to AP SSID:<YourSSID> and an IP address acquisition (got ip: x.x.x.x). If connection fails, it will retry a few times. After the max retries, if it still cannot connect, the device will switch to AP mode (look for logs about starting AP). In that case, use your PC or phone to connect to the ESP32’s AP (check for an SSID that matches what you configured, or a default like "ESP32_AP") before continuing.

Access via Browser: Once the ESP32 is network-connected (either to your router or via its own AP), you can access the web server. On a device (PC/phone) connected to the same network, open a browser and navigate to https://esp32.local. (If mDNS is not working on your system, find the IP address from the serial logs and use https://<ESP32_IP>). Because the server uses a self-signed certificate, your browser will likely warn that the connection is not private. Proceed by accepting the certificate or adding an exception (in most browsers, you’ll find an "Advanced" option to ignore the warning for this site).

Web Interface Loaded: You should see the ST Server Dev Hub webpage served from the ESP32. It contains a heading and two sections for input: one for GET and one for POST/PUT/DELETE, as well as buttons for a dynamic URI demo. At this point, you can interact with the page to test the server’s features (detailed in the next sections).

Test GET Request: In the "Message for GET" field, type a sample message (e.g. "Hello ESP32") and click the Submit button. This will send a GET request to the ESP32 (the form action calls a /submit endpoint). The page will reload to display the server’s response, which should echo your message. (For example, the page might show "This was your text: Hello ESP32" as confirmation.)

Test POST/PUT/DELETE Requests: Next, try the dynamic requests. In the "Message for POST/PUT/DELETE" field, enter some text (e.g. "hello there") and click POST. The page will not reload; instead, a JavaScript fetch call sends your text to the ESP32’s /api/post endpoint. The server responds with the same message, and the page updates to show a “POST Response: hello there” line (all done asynchronously). Likewise, test the PUT and DELETE buttons – you should see “PUT Response: ...” or “DELETE Response: ...” with the echoed text appear on the page in each case. This confirms that the ESP32 is handling different HTTP methods via the same interface.

Dynamic URI Demo: At the bottom of the page, there are two additional buttons for Dynamic URI and System Info. Click Register URI – this will send a request to the ESP32’s control endpoint (/ctrl) instructing it to register a new URI handler (for the /info path). On success, the page will display "URI Registered!" to indicate the new route is active. Now click Get Device Info. This triggers a GET request to the newly registered /info endpoint. The server will respond with a JSON payload containing system information (such as device name, a unique ID, memory info, and Wi-Fi SSID). The page will display this JSON under a "Device Info:" label. You have now dynamically added and invoked a new API on the running server without restarting it!

Observe Serial Output: Throughout the testing, the serial monitor (in your idf.py monitor window) will show debug logs. You will see messages for Wi-Fi events (connect, IP acquired), mDNS initialization, and server actions. For each incoming HTTP request, the server prints logs; for example, when you sent the POST with "hello there", you should see a log like POST: Received: hello there. Similarly, the act of registering the new URI will be logged (e.g., ST_Server: Registering /info URI), and the device info retrieval might log the details being sent. Monitoring this output can help verify that each handler in the firmware is working as expected.

## Web Interface Overview

Screenshot: The ST Server Dev Hub web interface served by the ESP32. The page provides a text field and Submit button for GET requests (top), another input for sending text via POST/PUT/DELETE (with three corresponding buttons, middle), and buttons to register a new URI and get device info (bottom). This interface allows users to easily test different HTTP methods and dynamic server behaviors.

The web page is a simple HTML interface that lets you interact with the ESP32’s server. Key elements of the interface include:

Message for GET (form submit): A text box and a Submit button. Whatever you type here will be sent as a query parameter in a GET request when you press Submit. The page will navigate to the response (the ESP32 handles the /submit route to display the message back to you).

Message for POST/PUT/DELETE (JavaScript): Another text box and three buttons labeled POST, PUT, and DELETE. These do not navigate away when clicked. Instead, the page’s JavaScript sends an AJAX request (Fetch API) to the ESP32 for each respective HTTP method (/api/post, /api/put, /api/delete). The server’s response (just a text string in this demo) is then displayed on the page dynamically.

Dynamic URI and System Info: Two buttons – Register URI and Get Device Info. These demonstrate modifying the server at runtime. Register URI sends a command to the ESP32 to add a new endpoint. Once that’s done, Get Device Info will fetch data from that new endpoint (in JSON format) and display it.

The interface is intentionally minimalistic (no external styling) to keep the focus on functionality. It uses a bit of JavaScript in the background to handle the dynamic calls for POST/PUT/DELETE and the device info retrieval. All content is served directly from the ESP32 (the HTML is embedded in firmware, and no internet connection is needed aside from the ESP32 being on the local network).

## Testing Dynamic Routes

Once the web interface is up, you can actively test how the server handles various HTTP methods and dynamic registration:

Screenshot: Example of a dynamic POST request in action. The user entered "hello there" and clicked POST. The ESP32’s /api/post handler echoed the message back, and the page displays “POST Response: hello there” without reloading. Similar behavior occurs for PUT and DELETE requests, each showing a confirmation of the text sent.

GET request: After typing a message and hitting Submit, the browser is redirected to a simple response page generated by the ESP32. For example, if you submitted "hi from Akbar", the response page would show a line like "This was your text: hi from Akbar". This confirms the GET handler (submit_handler) received the data. (Note: Use the browser's back button to return to the main interface after a GET, since it navigates away.)

POST/PUT/DELETE requests: When you click any of these method buttons, the page will update a result field at the bottom with the response from the ESP32. In this demo, the server simply sends back the same text it received. This is why after a POST with "hello there", you see POST Response: hello there on the page. The PUT and DELETE handlers behave similarly (echoing the input text with a "PUT Response" or "DELETE Response" label). This demonstrates full bidirectional communication: the browser sends a request via JavaScript, the ESP32 processes it and replies, and the browser updates the UI – all over HTTPS.

Registering a new URI: Clicking Register URI sends a PUT request to /ctrl on the ESP32. The firmware’s control handler (ctrl_put_handler) is implemented to register a new URI (/info) at runtime (if not already registered). The moment this is done, the web page shows "URI Registered!" indicating success. Internally, the ESP32’s HTTP server now knows how to handle /info requests.

Fetching device info: After registering, clicking Get Device Info issues a GET request to the new /info endpoint. The handler for /info (registered on the fly) responds with a JSON object containing some system information. The page’s script receives that JSON and displays it. For example, you might see a JSON like:

{
"device": "ESP32",
"uuid": "ABC123DEF456",
"mem": "520KB RAM",
"wifi": "MySSID"
}

This confirms that the dynamic route is working – the server was able to supply data that wasn’t originally hard-coded at compile time. In a real scenario, this mechanism could be used to add or remove features on the fly or respond with live system diagnostics.

By testing these, you have verified the ESP32 server can handle multiple concurrent URI endpoints, different HTTP verbs, and can even modify its available endpoints during runtime. All communication is over HTTPS, ensuring that the data (e.g., your messages) is encrypted in transit.
## Serial Output

Screenshot: Serial console output from the ESP32 firmware. The logs (shown via idf.py monitor) include Wi-Fi events (connection attempts, success with IP address), confirmation that TLS certificates were loaded from NVS, mDNS initialization (setting hostname to esp32.local), the HTTPS server starting and registering URI handlers, and runtime messages such as registering the /info URI and receiving a POST request with content.

The serial output is an invaluable tool for understanding what’s happening on the device:

Wi-Fi connection logs: You will see the ESP-IDF Wi-Fi driver logs as the ESP32 tries to connect. For example, messages like wifi station: connect to the AP fail (with retry attempts) or wifi station: connected followed by got ip:192.168.xx.yy. These confirm whether the STA mode succeeded or if the device fell back to AP. If AP mode started, you’d see logs indicating the AP SSID and IP (not shown in the screenshot, as in this run it eventually connected to the configured AP after some retries).

Certificate loading: The certificates component logs a line when the TLS materials are loaded from NVS (e.g., "Certificates loaded successfully."). If there was an issue (like missing/incorrect data), you would see an error here and the server might not start.

mDNS startup: Look for logs with the tag mdns or mDNS. The firmware logs setting the hostname, e.g., “mDNS hostname set to: esp32.local”, and initializing the mDNS service. This indicates the device is announcing itself on the network.

Server start and handlers: The st_server component logs when the HTTPS server starts: “Starting server”, followed by “Registering URI handlers” for each of the built-in endpoints ("/", "/submit", "/api/post", etc.). This means the server is up and listening (on port 443 by default for HTTPS).

Request handling: Each time you interact with the web interface, the server prints info. For instance, pressing the POST button led to a log like POST: Received: hello there, showing the server received that payload. Similarly, the act of registering the new URI produced a log “Registering /info URI”, and the /info request might log details about the info sent. All HTTP method handlers can log their activity (in this project, they generally log the content they received or actions taken).

Errors or warnings: If anything goes wrong (e.g., certificate not found, or a null pointer), those would typically appear in red on the monitor. The absence of errors in the log implies everything is running smoothly.

Monitoring these logs in real time can help during development or debugging. For example, if the web interface isn’t reachable, you might check if the device got an IP or if mDNS announced the name. Or if a button press doesn’t yield a response on the page, the log might show an error in the handler or the request never arrived. In this demo, the logs should mostly show a smooth sequence of events as outlined above.