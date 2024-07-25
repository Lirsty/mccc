#include "network/connection.h"
#include "client/client.h"
#include <stdio.h>
#include "network/packet.h"
#include "data/packetid.h"
#include <string.h>

int main() {
    client c;
    join_server(&c, "localhost", 25565);

    connection *conn = &c.conn;

    while(1) {
        packet p;
        recv_packet(conn, &p);
        if (p.pid == play_clientbound_keep_alive) {
            printf("keep alive, pid: %d, p_len: %zu\n", p.pid, p.buf.data_len);
            SEND(conn, play_serverbound_keep_alive, read_long(p.buf.data));
        }
        free(p.buf.base);
    }
    close_conn(conn);
}

