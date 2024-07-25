#include "client/client.h"
#include "client/login.h"
#include "client/configuration.h"

int 
join_server(client *c, const char *address, int port)
{
    init_conn(&c->conn);
    if (connect_to_server(&c->conn, address, port) != 0)
        return -1;
    
    if (login(c, address, port) != 0)
        return -1;

    if (configuration(c) != 0)
        return -1;

    return 0;   
}