#include <librpma.h>

const size_t KILOBYTE = 1024;

struct rpma_context
{
    struct rpma_peer *peer;
    struct rpma_conn *conn;
    struct ibv_wc wc;

    void *dst_ptr;
    struct rpma_mr_local *dst_mr;
    struct rpma_mr_remote *src_mr;
    size_t src_size;
};

void *malloc_aligned(size_t size);
int client_connect(struct rpma_peer *peer, const char *addr,
                   const char *port, struct rpma_conn_cfg *cfg,
                   struct rpma_conn_private_data *pdata,
                   struct rpma_conn **conn_ptr);
int common_disconnect_and_wait_for_conn_close(struct rpma_conn **connptr);
int init_rpma(struct rpma_context *ctx, const char *addr);
