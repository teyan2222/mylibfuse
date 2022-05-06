#include <librpma.h>

const size_t BUFFER_SIZE = 4 * 1024 * 1024;
#define DESCRIPTORS_MAX_SIZE 24

struct rpma_context
{
    struct rpma_peer *peer;
    struct rpma_conn *conn;
    struct ibv_wc wc;

    void *rd_dst_ptr;
    struct rpma_mr_local *rd_local_mr;
    struct rpma_mr_remote *remote_mr;
    size_t remote_size;
    uint64_t time_us0, time_us1, time_us2, time_us3;
    uint64_t rd_count;
    
    //---- Write ----
    void *wr_src_ptr;
    struct rpma_mr_local *wr_local_mr;
    uint64_t time_usa, time_usb, time_usc, time_usd, time_use, time_usf;
    uint64_t wr_count;

};

struct common_data
{
    uint16_t data_offset;
    uint8_t mr_desc_size;
    uint8_t pcfg_desc_size;
    char descriptors[DESCRIPTORS_MAX_SIZE];
};


void *malloc_aligned(size_t size);
int client_connect(struct rpma_peer *peer, const char *addr,
                   const char *port, struct rpma_conn_cfg *cfg,
                   struct rpma_conn_private_data *pdata,
                   struct rpma_conn **conn_ptr);
int common_disconnect_and_wait_for_conn_close(struct rpma_conn **connptr);
int timespan_us(struct timespec *from, struct timespec *to);
int init_rpma(struct rpma_context *ctx, const char *addr);
