#include "client/configuration.h"
#include "data/packetid.h"
#include <string.h>

#define PANIC(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while(0);

static void handle_known_packs(connection *conn, packet *p);

int
configuration(client *c)
{
    connection *conn = &c->conn;
    
    while(1)
    {
        packet p;
        recv_packet(conn, &p);
        switch (p.pid)
        {
            case configuration_clientbound_disconnect:
                PANIC("disconnect")
            case configuration_clientbound_keep_alive:
            {
                pk_long keepalive_id = read_long(p.buf.data); 
                SEND(conn, configuration_serverbound_keep_alive, keepalive_id);
                break;
            }
            case configuration_clientbound_ping:
            {
                pk_int id = read_int(p.buf.data); (void) id;
                SEND(conn, configuration_serverbound_pong, id);
                break;
            }
            case configuration_clientbound_finish_configuration:
                SEND(conn, configuration_serverbound_acknowledge_finish_configuration);
                free(p.buf.base);
    return 0;
            case configuration_clientbound_known_packs:
                handle_known_packs(conn, &p);
                break;
        }
        free(p.buf.base);
    }
}

static void
handle_known_packs(connection *conn, packet *p)
{
    packet known_packs;
    packet_buffer *buf = &known_packs.buf;
    init_packet_buffer(buf, p->buf.data_len + 5);
    write_varint(buf, configuration_serverbound_known_packs);

    size_t to_copy = p->buf.data_len;
    memcpy(buf->data + buf->data_len, p->buf.data, to_copy);
    buf->data_len += to_copy;

    send_packet(conn, &known_packs); free(known_packs.buf.base);

    // TODO: storage packs
    /* 
    for (int i=0; i<known_pack_count; ++i)
    {
        pk_string namespace, id, version;
        SCAN(p, scanned_len, namespace, id, version);
    } 
    */
}