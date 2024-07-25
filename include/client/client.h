#ifndef _CLIENT_H
#define _CLIENT_H

#include "../network/connection.h"
#include "auth.h"

typedef struct client_st {
    connection conn;
    auth_ctx auth; 
} client;

int join_server(client *c, const char *address, int port);

#endif /* _CLIENT_H */