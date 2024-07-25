#include "connection.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <zlib.h>

#define PANIC(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while(0)

void
init_conn(connection *conn)
{
    conn->threshold = -1;
    conn->socket_fd = -1;
    conn->recv_buf.head = 0;
    conn->recv_buf.tail = 0;
    conn->recv_buf.remaining = 0;
    conn->deflate_buf.data = NULL;
    conn->deflate_buf.capacity = 0;
    conn->dec_ctx = NULL;
    conn->enc_ctx = NULL;
}

int
connect_to_server(connection *conn, const char *address, int port)
{
    if (conn->socket_fd != -1)
    {
        perror("already connected");
        return -1;
    }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status;
    if ((status = getaddrinfo(address, NULL, &hints, &res)))
    {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        goto fail;
    }

    conn->socket_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (conn->socket_fd < 0)
    {
        perror("socket creation failed");
        goto fail;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = res->ai_family;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;

    if (connect(conn->socket_fd, (struct sockaddr *)&server_addr, sizeof server_addr) < 0)
    {
        perror("connect failed");
        goto fail;
    }

    freeaddrinfo(res);
    return 0;
fail:
    if(res) freeaddrinfo(res);
    return -1;
}

void set_threshold(connection *conn, int threshold)
{
    conn->threshold = threshold;
    if (conn->deflate_buf.data)
        return;
    conn->deflate_buf.capacity = SEND_BUF_SIZE;
    conn->deflate_buf.data = malloc(SEND_BUF_SIZE);
}

void close_conn(connection *conn)
{
    if (conn->socket_fd == -1) return;

    close(conn->socket_fd);
    conn->socket_fd = -1;
    conn->threshold = -1;
    EVP_CIPHER_CTX_free(conn->dec_ctx); conn->dec_ctx = NULL;
    EVP_CIPHER_CTX_free(conn->enc_ctx); conn->enc_ctx = NULL;
    if(conn->deflate_buf.data) free(conn->deflate_buf.data);
}

static size_t
read_bytes(connection *conn, uint8_t *dest, size_t length) {
    size_t total_read = 0;
    ssize_t bytes_read;

    while (total_read < length) 
    {
        if (conn->recv_buf.remaining == 0 && length - total_read >= RECV_BUF_SIZE) 
        {
            bytes_read = recv(conn->socket_fd, conn->recv_buf.data, RECV_BUF_SIZE, 0);
            if (bytes_read < 0) {
                if (errno == EINTR) continue;
                perror("recv");
                return -1;
            } else if (bytes_read == 0) {
                close_conn(conn);
                PANIC("Connection closed unexpectedly");
            }
            if (conn->dec_ctx) {
                int output_len;
                if (EVP_CipherUpdate(conn->dec_ctx, dest + total_read, &output_len,
                    conn->recv_buf.data, bytes_read) != 1) 
                {
                    PANIC("EVP_CipherUpdate()");
                }
            }
            else memcpy(dest + total_read, conn->recv_buf.data, bytes_read);
            total_read += bytes_read;
            continue;
        }

        if (conn->recv_buf.remaining == 0) 
        {
            const static size_t half_recv_buf_size = RECV_BUF_SIZE >> 1;
            bytes_read = recv(  conn->socket_fd,
                                conn->recv_buf.data + half_recv_buf_size,
                                half_recv_buf_size, 0  );
            if (bytes_read < 0) {
                if (errno == EINTR) continue; 
                PANIC("recv");
            } else if (bytes_read == 0) {
                close_conn(conn);
                PANIC("Connection closed unexpectedly");
            }
            if (conn->dec_ctx) {
                int output_len;
                if (EVP_CipherUpdate(conn->dec_ctx, conn->recv_buf.data, &output_len,
                    conn->recv_buf.data + half_recv_buf_size, bytes_read) != 1) 
                {
                    PANIC("EVP_CipherUpdate()");
                }
            }
            else memcpy(conn->recv_buf.data, conn->recv_buf.data + half_recv_buf_size, bytes_read);

            conn->recv_buf.head = 0;
            conn->recv_buf.tail = bytes_read;
            conn->recv_buf.remaining = bytes_read;
        }

        size_t to_copy = length - total_read;
        if (to_copy > conn->recv_buf.remaining) 
            to_copy = conn->recv_buf.remaining;
        
        memcpy(dest + total_read, conn->recv_buf.data + conn->recv_buf.head, to_copy);
    
        total_read += to_copy;

        conn->recv_buf.head = conn->recv_buf.head + to_copy;
        conn->recv_buf.remaining -= to_copy;
    }

    return total_read;
}

#define SEGMENT_BITS 0x7F
#define CONTINUE_BIT 0x80
static size_t
next_varint(connection *conn, int32_t *ret)
{
    int32_t value = 0;
    int position = 0;
    uint8_t currentByte;

    size_t count = 0;
    do {
        read_bytes(conn, &currentByte, 1);

        value |= (currentByte & SEGMENT_BITS) << position;
        count++;

        if ((currentByte & CONTINUE_BIT) == 0) break;

        position += 7;

        if (position >= 32)
            PANIC("VarInt is too big.");

    } while (1);
    
    *ret = value;
    return count;
}

static void
send_encrypted(connection *conn, uint8_t *enc_head, size_t enc_size) 
{
    size_t total_sent = 0;
    while (total_sent < enc_size)
    {
        size_t to_send = enc_size - total_sent;
        if (to_send > SEND_BUF_SIZE)
            to_send = SEND_BUF_SIZE;
        if (conn->enc_ctx) {
            int output_len; 
            if (EVP_CipherUpdate(conn->enc_ctx, conn->send_buf, &output_len, enc_head + total_sent, to_send) != 1)
                PANIC("EVP_CipherUpdata()");
            if (send(conn->socket_fd, conn->send_buf, to_send, 0) < 0)
                PANIC("send()");
        } else {
            if (send(conn->socket_fd, enc_head + total_sent, to_send, 0) < 0)
                PANIC("send()");
        }
        total_sent += to_send;
    }
}

static void
send_packet_uncompressed(connection *conn, packet *p)
{
    size_t used_size = write_length(&p->buf, 0, p->buf.data_len);
    if (conn->enc_ctx == NULL) {
        if (send(conn->socket_fd, (p->buf.data - used_size), (p->buf.data_len + used_size), 0) < 0)
            PANIC("send packet");
    } else {
        send_encrypted(conn, (p->buf.data - used_size), (p->buf.data_len + used_size));
    }
}

static void
send_packet_compressed(connection *conn, packet *p)
{
    if (p->buf.data_len >= conn->threshold) {
        
    } else {
        size_t used_size = write_length(&p->buf, (p->buf.data_len + 1), 0);
        send_encrypted(conn, p->buf.data - used_size, p->buf.data_len + used_size);
    }
}

void
send_packet(connection *conn, packet *p)
{
    if (conn->threshold > 0)
        send_packet_compressed(conn, p);
    else 
        send_packet_uncompressed(conn, p);
}

static void
recv_packet_uncompressed(connection *conn, packet *p)
{
    int32_t pk_len, pid;           next_varint(conn, &pk_len);
    int32_t pk_data_len = pk_len - next_varint(conn, &pid);
    init_packet_buffer(&p->buf, pk_data_len);
    read_bytes(conn, p->buf.data, pk_data_len);
    p->buf.data_len = pk_data_len;
    p->pid = pid;
}

static void
recv_packet_compressed(connection *conn, packet *p)
{
    int32_t pk_len; next_varint(conn, &pk_len);
    int32_t pk_data_len; pk_len -= next_varint(conn, &pk_data_len);
    if (pk_data_len == 0) 
    {
        int32_t pid; pk_len -= next_varint(conn, &pid);
        init_packet_buffer(&p->buf, pk_len);
        read_bytes(conn, p->buf.data, pk_len);
        p->buf.data_len = pk_len;
        p->pid = pid;
        return;
    }

    init_packet_buffer(&p->buf, pk_data_len);
    p->buf.data_len = pk_data_len;
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    inflateInit(&strm);

    size_t total_read = 0;
    while (total_read < pk_len)
    {
        size_t to_read = pk_len - total_read;
        if (INFLATE_BUF_SIZE < to_read)
            to_read = INFLATE_BUF_SIZE;
        read_bytes(conn, conn->inflate_buf, to_read);
        strm.next_in = conn->inflate_buf;
        strm.avail_in = to_read;

        int inflate_ret;
        do {
            strm.next_out = p->buf.data + strm.total_out;
            strm.avail_out = pk_data_len - strm.total_out;
            inflate_ret = inflate(&strm, Z_NO_FLUSH);
            switch (inflate_ret) {
                case Z_NEED_DICT:
                    PANIC("Z_NEED_DICT");
                case Z_DATA_ERROR:
                    PANIC("Z_DATA_ERROR");
                case Z_MEM_ERROR:
                    PANIC("Z_MEM ERROR");
            }
        } while (strm.avail_in > 0);
        total_read += to_read;
    }
    inflateEnd(&strm);
    size_t ofs = _pread_varint(p->buf.data, &p->pid);
    p->buf.data += ofs;
    p->buf.data_len -= ofs;
}

void
recv_packet(connection *conn, packet *p)
{
    if (conn->threshold > 0)
        return recv_packet_compressed(conn, p);
    else
        return recv_packet_uncompressed(conn, p);
}