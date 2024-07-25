#include "client/auth.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


int 
start_auth_flow(auth_ctx *ctx) 
{
    
}


static int 
https_post( const char *hostname, const char *path, const char *data,
            char *response, size_t *response_size )
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    int len;
    int bytes;
    int result = -1; 

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return result;
    }

    bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return result;
    }

    BIO_set_conn_hostname(bio, hostname);
    BIO_set_conn_port(bio, "443");

    BIO_get_ssl(bio, &ssl);
    if (ssl == NULL) {
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return result;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (BIO_do_connect(bio) <= 0) {
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return result;
    }

    char request[4096];
    snprintf(request, sizeof(request),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/json\r\n"
             "Content-Length: %lu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s", path, hostname, strlen(data), data);

    BIO_write(bio, request, strlen(request));

    bytes = 0;
    while ((len = BIO_read(bio, response + bytes, *response_size - bytes - 1)) > 0) {
        bytes += len;
    }
    response[bytes] = '\0';
    *response_size = bytes;

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    result = 0;
    return result;
}