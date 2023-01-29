#include "new_thread0.h"

/* LEDs */
#define LED_1_PIN               BSP_IO_PORT_00_PIN_07 /* Green */
#define LED_2_PIN               BSP_IO_PORT_00_PIN_08 /* Red */
#define LED_ON_LEVEL            BSP_IO_LEVEL_HIGH
#define LED_OFF_LEVEL           BSP_IO_LEVEL_LOW

/* Debug output */
#include "SEGGER_RTT/RTT/SEGGER_RTT.h"
#define printf(fn_, ...)         SEGGER_RTT_printf(0, (fn_), ##__VA_ARGS__)
#define INFO_PRINT(fn_, ...)     printf((fn_), ##__VA_ARGS__);
#define ERROR_ASSERT(a, b, c, d) if(a){ printf("  Error in " b ": 0x%x\n", c); \
                                 R_IOPORT_PinWrite(NULL, LED_2_PIN, LED_ON_LEVEL); d;}

/* TODO(2): Add additional variables definition */
/* Global packet pool */
NX_PACKET_POOL g_packet_pool0;
uint8_t g_packet_pool0_pool_memory[G_PACKET_POOL0_PACKET_NUM * (G_PACKET_POOL0_PACKET_SIZE + sizeof(NX_PACKET))] BSP_ALIGN_VARIABLE(4) ETHER_BUFFER_PLACE_IN_SECTION;

/* IP instance */
NX_IP g_ip0;

/* Stack memory for g_ip0. */
uint8_t g_ip0_stack_memory[G_IP0_TASK_STACK_SIZE] BSP_PLACE_IN_SECTION(".stack.g_ip0") BSP_ALIGN_VARIABLE(BSP_STACK_ALIGNMENT);

/* ARP cache memory for g_ip0. */
uint8_t g_ip0_arp_cache_memory[G_IP0_ARP_CACHE_SIZE] BSP_ALIGN_VARIABLE(4);

/* DHCP instance. */
NX_DHCP g_dhcp_client0;

/* DNS instance. */
NX_DNS g_dns0;

#define DNS_SERVER_ADDRESS              IP_ADDRESS(8,8,8,8)

NXD_ADDRESS server_ip_address;
#define HTTP_HOST_NAME                  "notify-api.line.me"
#define HTTP_HOST_IP_ADDRESS_EXAMPLE    IP_ADDRESS(147,92,242,65)

/// ########## User Settings ##########
#define ACCESS_TOKEN                    "<add your access token number>"
#define POST_MESSAGE                    "Hello"
/// ###################################

// HTTP Request Parameters:
#define HTTP_HOST_RESOURCE              "/api/notify"
#define HTTP_POST_PARAM_MESSAGE         "message="

unsigned char transfer_message_buff[1000];
unsigned long transfer_message_len;

#define HTTP_AUTH_FIELD_NAME            "Authorization"
#define HTTP_AUTH_FIELD_VALUE           "Bearer "
#define HTTP_CONTENTTYPE_FIELD_NAME     "Content-Type"
#define HTTP_CONTENTTYPE_FIELD_VALUE    "application/x-www-form-urlencoded"

/* Web HTTP Client instance. */
NX_WEB_HTTP_CLIENT  g_web_http_client0;

unsigned char receive_message_buff[10000];
unsigned long receive_message_len;

unsigned char http_server_ca_cert_der[];
unsigned int http_server_ca_cert_der_len;

CHAR                crypto_metadata_client[20000 * NX_WEB_HTTP_SERVER_SESSION_MAX];
UCHAR               tls_packet_buffer[40000];
NX_SECURE_X509_CERT trusted_certificate;
NX_SECURE_X509_CERT remote_certificate, remote_issuer;
UCHAR               remote_cert_buffer[2000];
UCHAR               remote_issuer_buffer[2000];

extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;



volatile bool g_sw1_pushed = false;

void netx_packet_pool_setup(void);
void netx_ip_setup(void);
void netx_dhcp_client_setup(void);
void netx_dns_setup(void);
void server_ip_address_get(void);
void line_notify_packet_send(void);

/* TODO(3): Add function definition */
VOID http_response_callback(NX_WEB_HTTP_CLIENT *client_ptr, CHAR *field_name, UINT field_name_length,
                            CHAR *field_value, UINT field_value_length);

UINT tls_setup_callback(NX_WEB_HTTP_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls_session);

void new_thread0_entry(void)
{
    UINT status = 0;
    UINT sw_push_counter = 0;
    volatile bool g_led1_status = false;

    INFO_PRINT("\n==============================================\n");
    INFO_PRINT("Application Thread started.\n");

    R_ICU_ExternalIrqOpen(&g_external_irq0_ctrl, &g_external_irq0_cfg);
    R_ICU_ExternalIrqEnable(&g_external_irq0_ctrl);

    /* Setup the platform; initialize the SCE and the TRNG */
    status = nx_crypto_initialize();
    ERROR_ASSERT(NX_CRYPTO_SUCCESS != status, "nx_crypto_initialize", status, __BKPT(0));

    /* Initialize NetX system */
    nx_system_initialize();

    /* Setup NetX packet pool memory */
    netx_packet_pool_setup();

    /* Setup NetX IP */
    netx_ip_setup();

    /* Setup NetX DHCP Client and get device ip address */
    netx_dhcp_client_setup();

    /* Setup DNS */
    netx_dns_setup();

    /* Get server ip address */
    server_ip_address_get();

    INFO_PRINT("All setup completed. Https client application is ready.\n");
    INFO_PRINT("Press SW1 to send LINE notification\n");

    while (1)
    {
        if(g_sw1_pushed)
        {
            g_sw1_pushed = false;
            sw_push_counter++;

            INFO_PRINT("-----------------------\n");
            INFO_PRINT("LINE Notify Send Action\n");

            /* Prepare message data */
            transfer_message_len = sprintf((char*)transfer_message_buff,
                                           "%s%d: %s", HTTP_POST_PARAM_MESSAGE, sw_push_counter, POST_MESSAGE);

            /* Send packet for LINE notify */
            line_notify_packet_send();
        }

        tx_thread_sleep (50);

        /* Blinks LED */
        g_led1_status = !g_led1_status;
        if(g_led1_status)
        {
            R_IOPORT_PinWrite(NULL, LED_1_PIN, LED_ON_LEVEL);
        }
        else
        {
            R_IOPORT_PinWrite(NULL, LED_1_PIN, LED_OFF_LEVEL);
        }
    }

    R_IOPORT_PinWrite(NULL, LED_2_PIN, LED_ON_LEVEL);

    while (1)
    {
        tx_thread_sleep (1);
    }
}

void netx_packet_pool_setup(void)
{
    UINT status = NX_SUCCESS;
    INFO_PRINT("NetX Packet Pool Setup:\n");

    /* Create the packet pool. */
    status = nx_packet_pool_create(&g_packet_pool0,
                                   "g_packet_pool0 Packet Pool",
                                   G_PACKET_POOL0_PACKET_SIZE,
                                   &g_packet_pool0_pool_memory[0],
                                   G_PACKET_POOL0_PACKET_NUM * (G_PACKET_POOL0_PACKET_SIZE + sizeof(NX_PACKET)));
    ERROR_ASSERT(status != NX_SUCCESS, "nx_packet_pool_create", status, __BKPT(0));

    INFO_PRINT("  Completed successfully\n\n");
}

void netx_ip_setup(void)
{
    UINT status;
    INFO_PRINT("NetX IP Setup:\n");

    /* Create the ip instance. */
    status = nx_ip_create(&g_ip0,
                          "g_ip0 IP Instance",
                          G_IP0_ADDRESS,
                          G_IP0_SUBNET_MASK,
                          &g_packet_pool0,
                          G_IP0_NETWORK_DRIVER,
                          &g_ip0_stack_memory[0],
                          G_IP0_TASK_STACK_SIZE,
                          G_IP0_TASK_PRIORITY);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_ip_create", status, __BKPT(0));

    /* If using Embedded Wireless Framework then uncomment this out to set the adapter_ptr. See the FSP user manual for more details. */
    // g_ip0.nx_ip_reserved_ptr = adapter_ptr;

    /* Set the gateway address if it is configured. Make sure this is set if using the Embedded Wireless Framework! */
    if(IP_ADDRESS(0, 0, 0, 0) != G_IP0_GATEWAY_ADDRESS)
    {
        status = nx_ip_gateway_address_set(&g_ip0, G_IP0_GATEWAY_ADDRESS);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_ip_gateway_address_set", status, __BKPT(0));
    }

    status = nx_arp_enable(&g_ip0, &g_ip0_arp_cache_memory[0], G_IP0_ARP_CACHE_SIZE);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_arp_enable", status, __BKPT(0));

    /* Enable TCP */
    status = nx_tcp_enable(&g_ip0);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_tcp_enable", status, __BKPT(0));

    /* Enable UDP */
    status = nx_udp_enable(&g_ip0);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_udp_enable", status, __BKPT(0));

    /* Enable ICMP */
    status = nx_icmp_enable(&g_ip0);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_icmp_enable", status, __BKPT(0));

    INFO_PRINT("  Wait for IP link up\n");

    /* Wait for the link to be enabled. */
    ULONG current_state;
    do{
        nx_ip_status_check(&g_ip0, NX_IP_LINK_ENABLED, &current_state, 1000U);
    }while(NX_IP_LINK_ENABLED != current_state);

    INFO_PRINT("  Completed successfully\n\n");
}

void netx_dhcp_client_setup(void)
{
    UINT status = NX_SUCCESS;
    INFO_PRINT("NetX DHCP Client Setup:\n");

    /* Create the DHCP instance. */
    status = nx_dhcp_create(&g_dhcp_client0,
                            &g_ip0,
                            "g_dhcp_client0");
    ERROR_ASSERT(status != NX_SUCCESS, "nx_dhcp_create", status, __BKPT(0));

    /* Set packet pool for DHCP */
    status = nx_dhcp_packet_pool_set(&g_dhcp_client0, &g_packet_pool0);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_dhcp_packet_pool_set", status, __BKPT(0));

    /* Start DHCP service. */
    status = nx_dhcp_start(&g_dhcp_client0);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_dhcp_start", status, __BKPT(0));

    /* Wait until an IP address is acquired via DHCP. */
    ULONG requested_status;
    status = nx_ip_status_check(&g_ip0, NX_IP_ADDRESS_RESOLVED, &requested_status, 1000);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_ip_status_check", status, __BKPT(0));
    ERROR_ASSERT(requested_status != NX_IP_ADDRESS_RESOLVED, "nx_ip_status_check", requested_status, __BKPT(0));

    /* Get the updated ip address */
    ULONG ip_address;
    ULONG network_mask;
    status = nx_ip_interface_address_get(&g_ip0, 0, &ip_address, &network_mask);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_ip_interface_address_get", status, __BKPT(0));

    INFO_PRINT("\n");
    INFO_PRINT("  Device IP Address: %d:%d:%d:%d\n", (ip_address >> 24) & 0xFF,
                                                     (ip_address >> 16) & 0xFF,
                                                     (ip_address >> 8) & 0xFF,
                                                     (ip_address >> 0) & 0xFF);
    INFO_PRINT("\n");

    INFO_PRINT("  Completed successfully\n\n");
}

void netx_dns_setup(void)
{
    UINT status = NX_SUCCESS;
    INFO_PRINT("NetX DNS Setup:\n");

    /* Create the DNS instance. */
    status = nx_dns_create(&g_dns0,
                           &g_ip0,
                           (UCHAR *)"g_dns0");
    ERROR_ASSERT(status != NX_SUCCESS, "nx_dns_create", status, __BKPT(0));

    /* Set packet pool for DNS */
    status = nx_dns_packet_pool_set(&g_dns0, &g_packet_pool0);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_dns_packet_pool_set", status, __BKPT(0));

    INFO_PRINT("  Completed successfully\n\n");
}

void server_ip_address_get(void)
{
    UINT status = NX_SUCCESS;
    ULONG record_buffer[50];
    UINT  record_count;

    INFO_PRINT("Server IP Address Get:\n");

    INFO_PRINT("\n");
    INFO_PRINT("  Server Host Name: %s\n", HTTP_HOST_NAME);

    /* Add an IPv4 server address to the Client list. */
    status = nx_dns_server_add(&g_dns0, DNS_SERVER_ADDRESS);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_dns_server_add", status, __BKPT(0));

    /* Request the IPv4 address for the specified host. */
    status =  nx_dns_ipv4_address_by_name_get(&g_dns0,
                                              (UCHAR *)HTTP_HOST_NAME,
                                              record_buffer,
                                              sizeof(record_buffer),&record_count,
                                              500);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_dns_ipv4_address_by_name_get", status, __BKPT(0));

    if(record_count > 0)
    {
        server_ip_address.nxd_ip_address.v4 = record_buffer[0];
        server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

        INFO_PRINT("  Server IP Address: %d:%d:%d:%d\n", (server_ip_address.nxd_ip_address.v4 >> 24) & 0xFF,
                                                         (server_ip_address.nxd_ip_address.v4 >> 16) & 0xFF,
                                                         (server_ip_address.nxd_ip_address.v4 >> 8) & 0xFF,
                                                         (server_ip_address.nxd_ip_address.v4 >> 0) & 0xFF);
    }
    else
    {
        server_ip_address.nxd_ip_address.v4 = HTTP_HOST_IP_ADDRESS_EXAMPLE;
        server_ip_address.nxd_ip_version = NX_IP_VERSION_V4;

        INFO_PRINT("  No record found\n\n");
        return;
    }
    INFO_PRINT("\n");

    INFO_PRINT("  Completed successfully\n\n");
}

void line_notify_packet_send(void)
{
    UINT status = NX_SUCCESS;
    UINT status2 = NX_SUCCESS;
    NX_PACKET *my_packet;
    NX_PACKET *receive_packet;

    /* Create the Web HTTP Client instance. */
    status = nx_web_http_client_create(&g_web_http_client0,
                                       "g_web_http_client0",
                                       &g_ip0,
                                       &g_packet_pool0,
                                       G_WEB_HTTP_CLIENT0_WINDOW_SIZE);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_web_http_client_create", status, NULL);

    /* Set the header callback routine. */
    if(status == NX_SUCCESS)
    {
        status = nx_web_http_client_response_header_callback_set(&g_web_http_client0, http_response_callback);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_web_http_client_response_header_callback_set", status, NULL);
    }

    /* Make secure connect to server */
    if(status == NX_SUCCESS)
    {
        status = nx_web_http_client_secure_connect(&g_web_http_client0,
                                                   &server_ip_address, NX_WEB_HTTPS_SERVER_PORT,
                                                   tls_setup_callback, NX_WAIT_FOREVER);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_web_http_client_secure_connect", status, NULL);
    }

    /* Initialize request packet */
    if(status == NX_SUCCESS)
    {
        status = nx_web_http_client_request_initialize_extended(&g_web_http_client0,
                                                                NX_WEB_HTTP_METHOD_POST, /* GET, PUT, DELETE, POST, HEAD */
                                                                HTTP_HOST_RESOURCE, sizeof(HTTP_HOST_RESOURCE) - 1,
                                                                HTTP_HOST_NAME, sizeof(HTTP_HOST_NAME) - 1,
                                                                transfer_message_len,
                                                                NX_FALSE,
                                                                NULL, 0, //"name",
                                                                NULL, 0, // "password",
                                                                NX_WAIT_FOREVER);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_web_http_client_request_initialize_extended", status, NULL);
    }

    /* Add additional http header */
    if(status == NX_SUCCESS)
    {
        status = nx_web_http_client_request_header_add(&g_web_http_client0,
                                                       HTTP_AUTH_FIELD_NAME, sizeof(HTTP_AUTH_FIELD_NAME) - 1,
                                                       HTTP_AUTH_FIELD_VALUE ACCESS_TOKEN, sizeof(HTTP_AUTH_FIELD_VALUE ACCESS_TOKEN) - 1,
                                                       NX_WAIT_FOREVER);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_web_http_client_request_header_add (AUTH)", status, NULL);
    }

    /* Add additional http header */
    if(status == NX_SUCCESS)
    {
        status = nx_web_http_client_request_header_add(&g_web_http_client0,
                                                       HTTP_CONTENTTYPE_FIELD_NAME, sizeof(HTTP_CONTENTTYPE_FIELD_NAME) - 1,
                                                       HTTP_CONTENTTYPE_FIELD_VALUE, sizeof(HTTP_CONTENTTYPE_FIELD_VALUE) - 1,
                                                       NX_WAIT_FOREVER);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_web_http_client_request_header_add (CONTENT TYPE)", status, NULL);
    }

    /* Start sending http packet request to server */
    if(status == NX_SUCCESS)
    {
        status = nx_web_http_client_request_send(&g_web_http_client0, NX_WAIT_FOREVER);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_web_http_client_request_send", status, NULL);
    }

    /* Create a new data packet request */
    if(status == NX_SUCCESS)
    {
        status = nx_web_http_client_request_packet_allocate(&g_web_http_client0,
                                                            &my_packet,
                                                            NX_WAIT_FOREVER);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_web_http_client_request_packet_allocate", status, NULL);
    }

    /* Fill the data into new data packet */
    if(status == NX_SUCCESS)
    {
        INFO_PRINT("  Transfer message: %s\n", &transfer_message_buff[sizeof(HTTP_POST_PARAM_MESSAGE) - 1]);

        status = nx_packet_data_append(my_packet,
                                       transfer_message_buff, transfer_message_len,
                                       &g_packet_pool0,
                                       NX_WAIT_FOREVER);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_packet_data_append", status, NULL);
    }

    /* Send data packet request to server. */
    if(status == NX_SUCCESS)
    {
        status = nx_web_http_client_request_packet_send(&g_web_http_client0,
                                                        my_packet,
                                                        0,
                                                        NX_WAIT_FOREVER);
        ERROR_ASSERT(status != NX_SUCCESS, "nx_web_http_client_request_packet_send", status, NULL);
    }

    /* Check response */
    if(status == NX_SUCCESS)
    {
        UINT get_status = NX_SUCCESS;
        while(get_status != NX_WEB_HTTP_GET_DONE)
        {
            /* Check and get response body */
            get_status = nx_web_http_client_response_body_get(&g_web_http_client0,
                                                              &receive_packet,
                                                              NX_WAIT_FOREVER);

            if (get_status != NX_SUCCESS && get_status != NX_WEB_HTTP_GET_DONE)
            {
                status = get_status;
                ERROR_ASSERT(1, "nx_web_http_client_response_body_get", get_status, break);
            }
            else
            {
                /* Receive data packet from packet pool */
                status = nx_packet_data_extract_offset(receive_packet, 0, receive_message_buff, 100, &receive_message_len);
                if(status != NX_SUCCESS)
                {
                    ERROR_ASSERT(1, "extracting response body data", status, break);
                }
                else
                {
                    if(receive_message_len > 0)
                    {
                        receive_message_buff[receive_message_len] = 0;
                        INFO_PRINT("  Received data: %s\n", receive_message_buff);
                        nx_packet_release(receive_packet);
                    }
                }
            }
        }
    }

    /* Clear out the HTTP client */
    status2 = nx_web_http_client_delete(&g_web_http_client0);
    ERROR_ASSERT(status2 != NX_SUCCESS, "nx_web_http_client_delete", status2, NULL);

    if(status != NX_SUCCESS)
    {
        tx_thread_sleep (100);
        R_IOPORT_PinWrite(NULL, LED_2_PIN, LED_OFF_LEVEL);
    }
}

void irq_sw1_cb(external_irq_callback_args_t *p_args)
{
    FSP_PARAMETER_NOT_USED(p_args);
    g_sw1_pushed = true;
}

VOID http_response_callback(NX_WEB_HTTP_CLIENT *client_ptr, CHAR *field_name, UINT field_name_length,
                            CHAR *field_value, UINT field_value_length)
{
    CHAR name[100];
    CHAR value[100];

    NX_PARAMETER_NOT_USED(client_ptr);

    memset(name, 0, sizeof(name));
    memset(value, 0, sizeof(value));

    memcpy(name, field_name, field_name_length);
    memcpy(value, field_value, field_value_length);

#if 0
    INFO_PRINT("  Received header: \n\tField name: %s (%d bytes)\n\tValue: %s (%d bytes)\n--------------\n",
               name, field_name_length,
               value, field_value_length);
#endif
}

UINT tls_setup_callback(NX_WEB_HTTP_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls_session)
{
    UINT status;
    NX_PARAMETER_NOT_USED(client_ptr);

    /* Initialize and create TLS session. */
    status = nx_secure_tls_session_create(tls_session,
                                          &nx_crypto_tls_ciphers,
                                          crypto_metadata_client,
                                          sizeof(crypto_metadata_client));
    ERROR_ASSERT(status != NX_SUCCESS, "nx_secure_tls_session_create", status, return(status));

    /* Allocate space for packet reassembly. */
    status = nx_secure_tls_session_packet_buffer_set(tls_session,
                                                     tls_packet_buffer,
                                                     sizeof(tls_packet_buffer));
    ERROR_ASSERT(status != NX_SUCCESS, "nx_secure_tls_session_packet_buffer_set", status, return(status));

    /* Add a CA Certificate to our trusted store for verifying incoming server certificates. */
    status = nx_secure_x509_certificate_initialize(&trusted_certificate,
                                                   http_server_ca_cert_der, (USHORT)http_server_ca_cert_der_len,
                                                   NX_NULL, 0,
                                                   NULL, 0,
                                                   NX_SECURE_X509_KEY_TYPE_NONE);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_secure_x509_certificate_initialize", status, return(status));

    /* Apply trusted certificate to TLS instance */
    status = nx_secure_tls_trusted_certificate_add(tls_session, &trusted_certificate);
    ERROR_ASSERT(status != NX_SUCCESS, "nx_secure_tls_trusted_certificate_add", status, return(status));

        /* Need to allocate space for the certificate coming in from the remote host. */
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_certificate, remote_cert_buffer, sizeof(remote_cert_buffer));
    nx_secure_tls_remote_certificate_allocate(tls_session, &remote_issuer, remote_issuer_buffer, sizeof(remote_issuer_buffer));

    return(NX_SUCCESS);
}

unsigned char http_server_ca_cert_der[] = {
  0x30, 0x82, 0x03, 0x5F, 0x30, 0x82, 0x02, 0x47, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0B, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x21, 0x58, 0x53, 0x08, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
  0x00, 0x30, 0x4C, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x17, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x53, 0x69, 0x67, 0x6E, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x20, 0x2D, 0x20, 0x52, 0x33, 0x31, 0x13, 0x30,
  0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0A, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x53, 0x69, 0x67, 0x6E, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0A, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x53, 0x69, 0x67, 0x6E, 0x30,
  0x1E, 0x17, 0x0D, 0x30, 0x39, 0x30, 0x33, 0x31, 0x38, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x32, 0x39, 0x30, 0x33, 0x31, 0x38, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x4C, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x03, 0x55,
  0x04, 0x0B, 0x13, 0x17, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x53, 0x69, 0x67, 0x6E, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x20, 0x2D, 0x20, 0x52, 0x33, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0A, 0x47, 0x6C,
  0x6F, 0x62, 0x61, 0x6C, 0x53, 0x69, 0x67, 0x6E, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0A, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x53, 0x69, 0x67, 0x6E, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48,
  0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xCC, 0x25, 0x76, 0x90, 0x79, 0x06, 0x78, 0x22, 0x16, 0xF5, 0xC0, 0x83, 0xB6, 0x84, 0xCA, 0x28, 0x9E, 0xFD,
  0x05, 0x76, 0x11, 0xC5, 0xAD, 0x88, 0x72, 0xFC, 0x46, 0x02, 0x43, 0xC7, 0xB2, 0x8A, 0x9D, 0x04, 0x5F, 0x24, 0xCB, 0x2E, 0x4B, 0xE1, 0x60, 0x82, 0x46, 0xE1, 0x52, 0xAB, 0x0C, 0x81, 0x47, 0x70, 0x6C, 0xDD, 0x64, 0xD1, 0xEB, 0xF5, 0x2C, 0xA3,
  0x0F, 0x82, 0x3D, 0x0C, 0x2B, 0xAE, 0x97, 0xD7, 0xB6, 0x14, 0x86, 0x10, 0x79, 0xBB, 0x3B, 0x13, 0x80, 0x77, 0x8C, 0x08, 0xE1, 0x49, 0xD2, 0x6A, 0x62, 0x2F, 0x1F, 0x5E, 0xFA, 0x96, 0x68, 0xDF, 0x89, 0x27, 0x95, 0x38, 0x9F, 0x06, 0xD7, 0x3E,
  0xC9, 0xCB, 0x26, 0x59, 0x0D, 0x73, 0xDE, 0xB0, 0xC8, 0xE9, 0x26, 0x0E, 0x83, 0x15, 0xC6, 0xEF, 0x5B, 0x8B, 0xD2, 0x04, 0x60, 0xCA, 0x49, 0xA6, 0x28, 0xF6, 0x69, 0x3B, 0xF6, 0xCB, 0xC8, 0x28, 0x91, 0xE5, 0x9D, 0x8A, 0x61, 0x57, 0x37, 0xAC,
  0x74, 0x14, 0xDC, 0x74, 0xE0, 0x3A, 0xEE, 0x72, 0x2F, 0x2E, 0x9C, 0xFB, 0xD0, 0xBB, 0xBF, 0xF5, 0x3D, 0x00, 0xE1, 0x06, 0x33, 0xE8, 0x82, 0x2B, 0xAE, 0x53, 0xA6, 0x3A, 0x16, 0x73, 0x8C, 0xDD, 0x41, 0x0E, 0x20, 0x3A, 0xC0, 0xB4, 0xA7, 0xA1,
  0xE9, 0xB2, 0x4F, 0x90, 0x2E, 0x32, 0x60, 0xE9, 0x57, 0xCB, 0xB9, 0x04, 0x92, 0x68, 0x68, 0xE5, 0x38, 0x26, 0x60, 0x75, 0xB2, 0x9F, 0x77, 0xFF, 0x91, 0x14, 0xEF, 0xAE, 0x20, 0x49, 0xFC, 0xAD, 0x40, 0x15, 0x48, 0xD1, 0x02, 0x31, 0x61, 0x19,
  0x5E, 0xB8, 0x97, 0xEF, 0xAD, 0x77, 0xB7, 0x64, 0x9A, 0x7A, 0xBF, 0x5F, 0xC1, 0x13, 0xEF, 0x9B, 0x62, 0xFB, 0x0D, 0x6C, 0xE0, 0x54, 0x69, 0x16, 0xA9, 0x03, 0xDA, 0x6E, 0xE9, 0x83, 0x93, 0x71, 0x76, 0xC6, 0x69, 0x85, 0x82, 0x17, 0x02, 0x03,
  0x01, 0x00, 0x01, 0xA3, 0x42, 0x30, 0x40, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF,
  0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x8F, 0xF0, 0x4B, 0x7F, 0xA8, 0x2E, 0x45, 0x24, 0xAE, 0x4D, 0x50, 0xFA, 0x63, 0x9A, 0x8B, 0xDE, 0xE2, 0xDD, 0x1B, 0xBC, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
  0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x4B, 0x40, 0xDB, 0xC0, 0x50, 0xAA, 0xFE, 0xC8, 0x0C, 0xEF, 0xF7, 0x96, 0x54, 0x45, 0x49, 0xBB, 0x96, 0x00, 0x09, 0x41, 0xAC, 0xB3, 0x13, 0x86, 0x86, 0x28, 0x07, 0x33, 0xCA,
  0x6B, 0xE6, 0x74, 0xB9, 0xBA, 0x00, 0x2D, 0xAE, 0xA4, 0x0A, 0xD3, 0xF5, 0xF1, 0xF1, 0x0F, 0x8A, 0xBF, 0x73, 0x67, 0x4A, 0x83, 0xC7, 0x44, 0x7B, 0x78, 0xE0, 0xAF, 0x6E, 0x6C, 0x6F, 0x03, 0x29, 0x8E, 0x33, 0x39, 0x45, 0xC3, 0x8E, 0xE4, 0xB9,
  0x57, 0x6C, 0xAA, 0xFC, 0x12, 0x96, 0xEC, 0x53, 0xC6, 0x2D, 0xE4, 0x24, 0x6C, 0xB9, 0x94, 0x63, 0xFB, 0xDC, 0x53, 0x68, 0x67, 0x56, 0x3E, 0x83, 0xB8, 0xCF, 0x35, 0x21, 0xC3, 0xC9, 0x68, 0xFE, 0xCE, 0xDA, 0xC2, 0x53, 0xAA, 0xCC, 0x90, 0x8A,
  0xE9, 0xF0, 0x5D, 0x46, 0x8C, 0x95, 0xDD, 0x7A, 0x58, 0x28, 0x1A, 0x2F, 0x1D, 0xDE, 0xCD, 0x00, 0x37, 0x41, 0x8F, 0xED, 0x44, 0x6D, 0xD7, 0x53, 0x28, 0x97, 0x7E, 0xF3, 0x67, 0x04, 0x1E, 0x15, 0xD7, 0x8A, 0x96, 0xB4, 0xD3, 0xDE, 0x4C, 0x27,
  0xA4, 0x4C, 0x1B, 0x73, 0x73, 0x76, 0xF4, 0x17, 0x99, 0xC2, 0x1F, 0x7A, 0x0E, 0xE3, 0x2D, 0x08, 0xAD, 0x0A, 0x1C, 0x2C, 0xFF, 0x3C, 0xAB, 0x55, 0x0E, 0x0F, 0x91, 0x7E, 0x36, 0xEB, 0xC3, 0x57, 0x49, 0xBE, 0xE1, 0x2E, 0x2D, 0x7C, 0x60, 0x8B,
  0xC3, 0x41, 0x51, 0x13, 0x23, 0x9D, 0xCE, 0xF7, 0x32, 0x6B, 0x94, 0x01, 0xA8, 0x99, 0xE7, 0x2C, 0x33, 0x1F, 0x3A, 0x3B, 0x25, 0xD2, 0x86, 0x40, 0xCE, 0x3B, 0x2C, 0x86, 0x78, 0xC9, 0x61, 0x2F, 0x14, 0xBA, 0xEE, 0xDB, 0x55, 0x6F, 0xDF, 0x84,
  0xEE, 0x05, 0x09, 0x4D, 0xBD, 0x28, 0xD8, 0x72, 0xCE, 0xD3, 0x62, 0x50, 0x65, 0x1E, 0xEB, 0x92, 0x97, 0x83, 0x31, 0xD9, 0xB3, 0xB5, 0xCA, 0x47, 0x58, 0x3F, 0x5F
};

unsigned int http_server_ca_cert_der_len = sizeof(http_server_ca_cert_der);
