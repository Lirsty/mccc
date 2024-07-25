#ifndef _CONNECTION_H
#define _CONNECTION_H

#include "packet.h"
#include <openssl/rsa.h>

#define RECV_BUF_SIZE 4096
#define SEND_BUF_SIZE 2048
#define INFLATE_BUF_SIZE 2048

typedef struct connection_st {
    int socket_fd;

    struct {
        uint8_t data[RECV_BUF_SIZE];
        size_t head, tail, remaining;
    } recv_buf;

    uint8_t send_buf[SEND_BUF_SIZE];

    struct {
        uint8_t *data;
        size_t capacity;
    } deflate_buf;

    EVP_CIPHER_CTX *dec_ctx, *enc_ctx;

    int threshold;
    uint8_t inflate_buf[INFLATE_BUF_SIZE];

} connection;

void init_conn(connection *conn);
void close_conn(connection *conn);
int connect_to_server(connection *conn, const char *address, int port);
void set_threshold(connection *conn, int threshold);
void send_packet(connection *conn, packet *p);
void recv_packet(connection *conn, packet *p);

#endif /* _CONNECTION_H */