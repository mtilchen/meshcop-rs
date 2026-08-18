#include "mbedtls/build_info.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct simple_timer {
    struct timespec start;
    uint32_t intermediate_ms;
    uint32_t final_ms;
    int running;
};

static unsigned char hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return (unsigned char) (c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (unsigned char) (10 + c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return (unsigned char) (10 + c - 'A');
    }
    fprintf(stderr, "invalid hex character\n");
    exit(2);
}

static void parse_pskc_from_dataset(unsigned char out[16])
{
    const char *hex = getenv("ESP_MATTER_TEST_THREAD_DATASET_HEX");
    size_t len;
    size_t i = 0;

    if (hex == NULL) {
        fprintf(stderr, "ESP_MATTER_TEST_THREAD_DATASET_HEX is required\n");
        exit(2);
    }

    len = strlen(hex);
    while (i + 4 <= len) {
        unsigned int ty = (hex_nibble(hex[i]) << 4) | hex_nibble(hex[i + 1]);
        unsigned int tlv_len = (hex_nibble(hex[i + 2]) << 4) | hex_nibble(hex[i + 3]);
        size_t value = i + 4;

        if (value + tlv_len * 2 > len) {
            fprintf(stderr, "dataset TLV is truncated\n");
            exit(2);
        }
        if (ty == 0x04 && tlv_len == 16) {
            for (size_t j = 0; j < 16; j++) {
                out[j] = (hex_nibble(hex[value + j * 2]) << 4)
                    | hex_nibble(hex[value + j * 2 + 1]);
            }
            return;
        }
        i = value + tlv_len * 2;
    }

    fprintf(stderr, "dataset does not contain a 16-byte PSKc\n");
    exit(2);
}

static void debug_log(void *ctx, int level, const char *file, int line, const char *str)
{
    (void) level;
    fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}

static int deterministic_rng(void *ctx, unsigned char *out, size_t len)
{
    unsigned long long *state = (unsigned long long *) ctx;

    for (size_t i = 0; i < len; i++) {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        out[i] = (unsigned char) (*state >> 24);
    }
    return 0;
}

static void simple_timer_set(void *ctx, uint32_t intermediate_ms, uint32_t final_ms)
{
    struct simple_timer *timer = (struct simple_timer *) ctx;

    timer->intermediate_ms = intermediate_ms;
    timer->final_ms = final_ms;
    timer->running = final_ms != 0;
    if (timer->running) {
        clock_gettime(CLOCK_MONOTONIC, &timer->start);
    }
}

static int simple_timer_get(void *ctx)
{
    struct simple_timer *timer = (struct simple_timer *) ctx;
    struct timespec now;
    uint64_t elapsed_ms;

    if (!timer->running) {
        return -1;
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed_ms = (uint64_t) (now.tv_sec - timer->start.tv_sec) * 1000;
    elapsed_ms += (uint64_t) (now.tv_nsec - timer->start.tv_nsec) / 1000000;

    if (elapsed_ms >= timer->final_ms) {
        return 2;
    }
    if (elapsed_ms >= timer->intermediate_ms) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *bind_port = argc > 1 ? argv[1] : "49157";
    const int ciphersuites[] = { MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8, 0 };
    const char *pers = "mesh50-mbedtls-server";
    unsigned char pskc[16];
    unsigned char client_ip[16] = { 0 };
    unsigned char buf[2048];
    size_t client_ip_len = 0;
    int ret = 0;
    unsigned long long rng_state = 0x123456789abcdef0ULL;

    mbedtls_net_context listen_fd;
    mbedtls_net_context client_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    struct simple_timer timer = { 0 };

    parse_pskc_from_dataset(pskc);

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_cookie_init(&cookie_ctx);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    mbedtls_debug_set_threshold(4);

    (void) pers;

    fprintf(stderr, "stage bind\n");
    ret = mbedtls_net_bind(&listen_fd, "127.0.0.1", bind_port, MBEDTLS_NET_PROTO_UDP);
    if (ret != 0) {
        goto exit;
    }

    fprintf(stderr, "stage defaults\n");
    ret = mbedtls_ssl_config_defaults(
        &conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_DATAGRAM,
        MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        goto exit;
    }

    fprintf(stderr, "stage configure\n");
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, deterministic_rng, &rng_state);
    mbedtls_ssl_conf_dbg(&conf, debug_log, stderr);
    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);
    mbedtls_ssl_conf_read_timeout(&conf, 10000);
    mbedtls_ssl_conf_min_version(
        &conf,
        MBEDTLS_SSL_MAJOR_VERSION_3,
        MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(
        &conf,
        MBEDTLS_SSL_MAJOR_VERSION_3,
        MBEDTLS_SSL_MINOR_VERSION_3);
    fprintf(
        stderr,
        "version min=0x%04x max=0x%04x transport=%d endpoint=%d\n",
        conf.MBEDTLS_PRIVATE(min_tls_version),
        conf.MBEDTLS_PRIVATE(max_tls_version),
        conf.MBEDTLS_PRIVATE(transport),
        conf.MBEDTLS_PRIVATE(endpoint));
    ret = mbedtls_ssl_conf_max_frag_len(&conf, MBEDTLS_SSL_MAX_FRAG_LEN_1024);
    if (ret != 0) {
        goto exit;
    }

    fprintf(stderr, "stage cookie\n");
    ret = mbedtls_ssl_cookie_setup(&cookie_ctx, deterministic_rng, &rng_state);
    if (ret != 0) {
        goto exit;
    }
    mbedtls_ssl_conf_dtls_cookies(
        &conf,
        mbedtls_ssl_cookie_write,
        mbedtls_ssl_cookie_check,
        &cookie_ctx);

    fprintf(stderr, "stage setup\n");
    mbedtls_ssl_set_mtu(&ssl, 1280);
    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        goto exit;
    }
    fprintf(stderr, "stage password\n");
    ret = mbedtls_ssl_set_hs_ecjpake_password(&ssl, pskc, sizeof(pskc));
    if (ret != 0) {
        goto exit;
    }
    mbedtls_ssl_set_timer_cb(&ssl, &timer, simple_timer_set, simple_timer_get);

    fprintf(stderr, "listening on 127.0.0.1:%s\n", bind_port);

reset:
    mbedtls_net_free(&client_fd);
    ret = mbedtls_ssl_session_reset(&ssl);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_ssl_set_hs_ecjpake_password(&ssl, pskc, sizeof(pskc));
    if (ret != 0) {
        goto exit;
    }

    ret = mbedtls_net_accept(
        &listen_fd,
        &client_fd,
        client_ip,
        sizeof(client_ip),
        &client_ip_len);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_ssl_set_client_transport_id(&ssl, client_ip, client_ip_len);
    if (ret != 0) {
        goto exit;
    }
    mbedtls_ssl_set_bio(
        &ssl,
        &client_fd,
        mbedtls_net_send,
        mbedtls_net_recv,
        mbedtls_net_recv_timeout);

    do {
        ret = mbedtls_ssl_handshake(&ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
        fprintf(stderr, "hello verify requested\n");
        goto reset;
    }
    if (ret != 0) {
        goto exit;
    }

    fprintf(stderr, "handshake ok\n");

    do {
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (ret > 0) {
        int read_len = ret;
        fprintf(stderr, "read %d application bytes\n", read_len);
        do {
            ret = mbedtls_ssl_write(&ssl, buf, (size_t) read_len);
        } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    }

exit:
    if (ret != 0) {
        char error[160];
        mbedtls_strerror(ret, error, sizeof(error));
        fprintf(stderr, "mbedtls error: -0x%x: %s\n", (unsigned int) -ret, error);
    }
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_cookie_free(&cookie_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret == 0 ? 0 : 1;
}
