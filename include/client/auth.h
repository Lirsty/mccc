#ifndef _AUTH_H
#define _AUTH_H

typedef struct auth_ctx_st {
    char *xbox_live_token;
    char *XSTX_token;
    char *username;
    char *access_token;
    int stage;
} auth_ctx;

int start_auth_flow(auth_ctx *ctx);

#endif /* _AUTH_H */