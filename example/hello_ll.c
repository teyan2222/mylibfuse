/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * minimal example filesystem using low-level API
 *
 * Compile with:
 *
 *     gcc -Wall hello_ll.c `pkg-config fuse3 --cflags --libs` -o hello_ll
 *
 * ## Source code ##
 * \include hello_ll.c
 */

#define FUSE_USE_VERSION 34

#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <librpma.h>
#include "rpma_fuse.h"

void *malloc_aligned(size_t size)
{
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize < 0) {
        perror("sysconf");
        return NULL;
    }

    /* allocate a page size aligned local memory pool */
    void *mem;
    int ret = posix_memalign(&mem, (size_t)pagesize, size);
    if (ret) {
        (void) fprintf(stderr, "posix_memalign: %s\n", strerror(ret));
        return NULL;
    }

    /* zero the allocated memory */
    memset(mem, 0, size);
    return mem;
}

int
client_connect(struct rpma_peer *peer, const char *addr, const char *port,
		struct rpma_conn_cfg *cfg, struct rpma_conn_private_data *pdata,
		struct rpma_conn **conn_ptr)
{
	struct rpma_conn_req *req = NULL;
	enum rpma_conn_event conn_event = RPMA_CONN_UNDEFINED;

	/* create a connection request */
	int ret = rpma_conn_req_new(peer, addr, port, cfg, &req);
	if (ret)
    {
        printf("rpma_conn_req_new error\n");
		return ret;
    }

	/* connect the connection request and obtain the connection object */
	ret = rpma_conn_req_connect(&req, pdata, conn_ptr);
	if (ret) {
		(void) rpma_conn_req_delete(&req);
		return ret;
	}

	/* wait for the connection to establish */
	ret = rpma_conn_next_event(*conn_ptr, &conn_event);
	if (ret) {
		goto err_conn_delete;
	} else if (conn_event != RPMA_CONN_ESTABLISHED) {
		fprintf(stderr,
			"rpma_conn_next_event returned an unexpected event: %s\n",
			rpma_utils_conn_event_2str(conn_event));
		ret = -1;
		goto err_conn_delete;
	}

	return 0;

err_conn_delete:
	(void) rpma_conn_delete(conn_ptr);

	return ret;
}

int common_disconnect_and_wait_for_conn_close(struct rpma_conn **conn_ptr)
{
	int ret = 0;

	ret |= rpma_conn_disconnect(*conn_ptr);
	if (ret == 0)
    {
        enum rpma_conn_event conn_event = RPMA_CONN_UNDEFINED;
        ret = rpma_conn_next_event(*conn_ptr, &conn_event);
        if(!ret && conn_event != RPMA_CONN_CLOSED)
        {
            printf("rpma_conn_next_event returned error.\n");
        }
    }

	ret |= rpma_conn_delete(conn_ptr);

	return ret;
}


int init_rpma(struct rpma_context *ctx, const char *addr)
{
//    int ret = client_peer_via_address(addr, &ctx->peer);
    const char *port = "19007";
    struct ibv_context *ibv_ctx = NULL;
    ctx->time_us0 = 0;
    ctx->time_us1 = 0;
    ctx->time_us2 = 0;
    ctx->time_us3 = 0;
    ctx->rd_count = 0;
    ctx->time_usa = 0;
    ctx->time_usb = 0;
    ctx->time_usc = 0;
    ctx->time_usd = 0;
    ctx->time_use = 0;
    ctx->time_usf = 0;
    ctx->wr_count = 0;
    int ret = rpma_utils_get_ibv_context(addr, RPMA_UTIL_IBV_CONTEXT_REMOTE, &ibv_ctx);
    if(ret) return ret;
    ret = rpma_peer_new(ibv_ctx, &ctx->peer);
    if(ret) return ret;
    ctx->rd_dst_ptr = malloc_aligned(BUFFER_SIZE);
    ctx->wr_src_ptr = malloc_aligned(BUFFER_SIZE);
    if(ctx->rd_dst_ptr == NULL || ctx->wr_src_ptr == NULL)
    {
        ret = -1;
        goto err_peer_delete;
    }
    if(ret) goto err_mr_free;

    ret = rpma_mr_reg(ctx->peer, ctx->rd_dst_ptr, BUFFER_SIZE, RPMA_MR_USAGE_READ_DST, &ctx->rd_local_mr);
    if(ret) goto err_mr_free;

    ret = rpma_mr_reg(ctx->peer, ctx->wr_src_ptr, BUFFER_SIZE, RPMA_MR_USAGE_WRITE_SRC, &ctx->wr_local_mr);
    if(ret) goto err_mr_free;

    ret = client_connect(ctx->peer, addr, port, NULL, NULL, &ctx->conn);
    if(ret) goto err_mr_deret;

    struct rpma_conn_private_data pdata;
    ret = rpma_conn_get_private_data(ctx->conn, &pdata);
    if(ret)
    {
        goto err_conn_disconnect;
    }
    else if(pdata.ptr == NULL)
    {
        printf(" the server has not provide a remote mem region.\n");
        goto err_conn_disconnect;
    }
    struct common_data *dst_data = pdata.ptr;
    ret = rpma_mr_remote_from_descriptor(&dst_data->descriptors[0],
            dst_data->mr_desc_size, &ctx->remote_mr);
    if(ret)
    {
        printf("rpma_mr_remote_from_descriptor error\n");
        goto err_conn_disconnect;
    }


    ret = rpma_mr_remote_get_size(ctx->remote_mr, &ctx->remote_size);
    if(ret)
    {
        printf("rpma_mr_remote_get_size error \n");
        goto err_mr_remote_delete;
    }
    else if (ctx->remote_size > BUFFER_SIZE)
    {
        printf("too big\n");
        goto err_mr_remote_delete;
    }

    return 0;

err_mr_remote_delete:
    rpma_mr_remote_delete(&ctx->remote_mr);
err_conn_disconnect:
    common_disconnect_and_wait_for_conn_close(&ctx->conn);
err_mr_deret:
    rpma_mr_dereg(&ctx->rd_local_mr);
    rpma_mr_dereg(&ctx->wr_local_mr);
err_mr_free:
    free(&ctx->rd_dst_ptr);
    free(&ctx->wr_src_ptr);
err_peer_delete:
    rpma_peer_delete(&ctx->peer);
    return ret;
}

//static const char *hello_str = "Hello World!\n";
//static char *file_buffer;
//static const size_t file_len = 64*1024;
static const size_t times = 1;
static const char *hello_name = "hello";
struct rpma_context *rpmactx;

static int hello_stat(fuse_ino_t ino, struct stat *stbuf)
{
    stbuf->st_ino = ino;
    switch (ino) {
    case 1:
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        break;

    case 2:
        stbuf->st_mode = S_IFREG | 0777;
        stbuf->st_nlink = 1;
                //stbuf->st_size = strlen(hello_str);
       // stbuf->st_size = file_len * times;
        stbuf->st_size = rpmactx->remote_size* times;
        break;

    default:
        return -1;
    }
    return 0;
}

static void hello_ll_getattr(fuse_req_t req, fuse_ino_t ino,
                 struct fuse_file_info *fi)
{
    struct stat stbuf;

    (void) fi;

    memset(&stbuf, 0, sizeof(stbuf));
    if (hello_stat(ino, &stbuf) == -1)
        fuse_reply_err(req, ENOENT);
    else
        fuse_reply_attr(req, &stbuf, 1.0);
}

static void hello_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse_entry_param e;

    if (parent != 1 || strcmp(name, hello_name) != 0)
        fuse_reply_err(req, ENOENT);
    else {
        memset(&e, 0, sizeof(e));
        e.ino = 2;
        e.attr_timeout = 1.0;
        e.entry_timeout = 1.0;
        hello_stat(e.ino, &e.attr);

        fuse_reply_entry(req, &e);
    }
}

struct dirbuf {
    char *p;
    size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
               fuse_ino_t ino)
{
    struct stat stbuf;
    size_t oldsize = b->size;
    b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
    b->p = (char *) realloc(b->p, b->size);
    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = ino;
    fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
              b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
                 off_t off, size_t maxsize)
{
    if (off < bufsize)
        return fuse_reply_buf(req, buf + off,
                      min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

static void hello_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                 off_t off, struct fuse_file_info *fi)
{
    (void) fi;

    if (ino != 1)
        fuse_reply_err(req, ENOTDIR);
    else {
        struct dirbuf b;

        memset(&b, 0, sizeof(b));
        dirbuf_add(req, &b, ".", 1);
        dirbuf_add(req, &b, "..", 1);
        dirbuf_add(req, &b, hello_name, 2);
        reply_buf_limited(req, b.p, b.size, off, size);
        free(b.p);
    }
}

static void hello_ll_open(fuse_req_t req, fuse_ino_t ino,
              struct fuse_file_info *fi)
{
    if (ino != 2)
        fuse_reply_err(req, EISDIR);
//    else if ((fi->flags & O_ACCMODE) != O_RDONLY)
//        fuse_reply_err(req, EACCES);
    else
        fuse_reply_open(req, fi);
}

int timespan_us(struct timespec *from, struct timespec *to)
{
    size_t result = 0;
    if(to->tv_nsec < from->tv_nsec)
    {
        result = (to->tv_sec - from->tv_sec -1) * 1000000000;
        result += 1000000000 + to->tv_nsec - from->tv_nsec;
    }
    else
    {
        result = (to->tv_sec - from->tv_sec) * 1000000000;
        result += to->tv_nsec - from->tv_nsec;

    }
    return result; 
}

static void hello_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
              off_t off, struct fuse_file_info *fi)
{
    (void) fi;
    struct timespec time0, time1, time2, time3, time4;

    size_t off_in_buf = off % rpmactx->remote_size;
    assert(ino == 2);
    int ret = 0;
    clock_gettime(CLOCK_MONOTONIC, &time0);
    ret = rpma_read(rpmactx->conn, rpmactx->rd_local_mr, off_in_buf, rpmactx->remote_mr, off_in_buf, size,
            RPMA_F_COMPLETION_ALWAYS, NULL);
    struct rpma_cq *cq = NULL;
    clock_gettime(CLOCK_MONOTONIC, &time1);
    ret = rpma_conn_get_cq(rpmactx->conn, &cq);
   // printf("Ret %d\n",ret);
    clock_gettime(CLOCK_MONOTONIC, &time2);
    ret = rpma_cq_wait(cq);
    clock_gettime(CLOCK_MONOTONIC, &time3);
    ret = rpma_cq_get_wc(cq, 1, &rpmactx->wc, NULL);
    clock_gettime(CLOCK_MONOTONIC, &time4);
    if(ret) {printf("Error");}
    reply_buf_limited(req, rpmactx->rd_dst_ptr, rpmactx->remote_size, off_in_buf, size);
    rpmactx->time_us0 += timespan_us(&time0, &time1);
    rpmactx->time_us1 += timespan_us(&time1, &time2);
    rpmactx->time_us2 += timespan_us(&time2, &time3);
    rpmactx->time_us3 += timespan_us(&time3, &time4);
    rpmactx->rd_count +=1000;
    //printf("Time: %ld, %ld, %ld, %ld\n", rpmactx->time_us0, rpmactx->time_us1, rpmactx->time_us2, rpmactx->time_us3);
    //reply_buf_limited(req, hello_str, strlen(hello_str), off, size);
}

static void hello_ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
                   size_t size, off_t off, struct fuse_file_info *fi)
{
//    printf("Size: %ld, Offset %ld\n", size, off);
    (void)fi;
    struct timespec time0, time1, time2, time3, time4, time5, time6;
    size_t off_in_buf = off % rpmactx->remote_size;
    assert(ino == 2);
    clock_gettime(CLOCK_MONOTONIC, &time0);
    memcpy(rpmactx->wr_src_ptr + off_in_buf, buf, size);
    int ret = 0;
    clock_gettime(CLOCK_MONOTONIC, &time1);
    ret = rpma_write(rpmactx->conn, rpmactx->remote_mr, off_in_buf, rpmactx->wr_local_mr, off_in_buf,
            size, RPMA_F_COMPLETION_ON_ERROR, NULL);
    if(ret) {printf("Error");}
    clock_gettime(CLOCK_MONOTONIC, &time2);
    ret = rpma_read(rpmactx->conn, rpmactx->rd_local_mr, off_in_buf, rpmactx->remote_mr, off_in_buf, 8, RPMA_F_COMPLETION_ALWAYS, NULL);
    if(ret) {printf("Error");}

    clock_gettime(CLOCK_MONOTONIC, &time3);
    struct rpma_cq *cq=NULL;
    ret = rpma_conn_get_cq(rpmactx->conn, &cq);
    if(ret) {printf("Error");}
    clock_gettime(CLOCK_MONOTONIC, &time4);
    ret = rpma_cq_wait(cq);
    if(ret) {printf("Error");}

    clock_gettime(CLOCK_MONOTONIC, &time5);
    ret = rpma_cq_get_wc(cq, 1, &rpmactx->wc, NULL);
    if(ret) {printf("Error");}
    clock_gettime(CLOCK_MONOTONIC, &time6);
    /*
    if(off_in_buf + size < rpmactx->src_size)
    {
        memcpy(file_buffer + off_in_buf, buf, size);
    }
    else
    {
        size_t size1 = rpmactx->src_size - off_in_buf;
        size_t size2 = size - size1;
        memcpy(file_buffer + off_in_buf, buf, size1);
        memcpy(file_buffer, buf + size1, size2);
    }
    */
    fuse_reply_write(req, size);
    rpmactx->time_usa += timespan_us(&time0, &time1);
    rpmactx->time_usb += timespan_us(&time1, &time2);
    rpmactx->time_usc += timespan_us(&time2, &time3);
    rpmactx->time_usd += timespan_us(&time3, &time4);
    rpmactx->time_use += timespan_us(&time4, &time5);
    rpmactx->time_usf += timespan_us(&time5, &time6);
    rpmactx->wr_count +=1000;

}

static void hello_ll_init(void *userdata, struct fuse_conn_info *conn)
{
    struct rpma_context *ctx = (struct rpma_context*)userdata;
    (void)(conn);
    printf("Hello Init\n");
    init_rpma(ctx, "100.84.21.13");
    printf("Filesize: %ld\n", ctx->remote_size);
}

static void hello_ll_destroy(void *userdata)
{
    struct rpma_context *ctx = (struct rpma_context*)userdata;
    printf("Hello destroy\n");
    printf("===== Read =====\n");
    printf("Count %ld\n", ctx->rd_count / 1000);
    printf("rpma_read %.3f\n", (double)ctx->time_us0 / ctx->rd_count );
    printf("rpma_conn_get_cq %.3f\n", (double)ctx->time_us1 / ctx->rd_count );
    printf("rpma_cq_wait %.3f\n", (double)ctx->time_us2 / ctx->rd_count );
    printf("rpma_cq_get_wc %.3f\n", (double)ctx->time_us3 / ctx->rd_count );
    printf("===== Write =====\n");
    printf("Count %ld\n", ctx->wr_count / 1000);
    printf("memcpy %.3f\n", (double)ctx->time_usa / ctx->wr_count );
    printf("rpma_write %.3f\n", (double)ctx->time_usb / ctx->wr_count );
    printf("rpma_read %.3f\n", (double)ctx->time_usc / ctx->wr_count );
    printf("rpma_conn_get_cq %.3f\n", (double)ctx->time_usd / ctx->wr_count );
    printf("rpma_cq_wait %.3f\n", (double)ctx->time_use / ctx->wr_count );
    printf("rpma_cq_get_wc %.3f\n", (double)ctx->time_usf / ctx->wr_count );
}

static const struct fuse_lowlevel_ops hello_ll_oper = {
    .init       = hello_ll_init,
    .destroy    = hello_ll_destroy,
    .lookup     = hello_ll_lookup,
    .getattr    = hello_ll_getattr,
    .readdir    = hello_ll_readdir,
    .open       = hello_ll_open,
    .read       = hello_ll_read,
    .write      = hello_ll_write,
};

int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config config;
    //struct rpma_context rpmactx;
    //file_buffer = (char*)malloc(file_len);
    rpmactx = (struct rpma_context*)malloc(sizeof(struct rpma_context));
    //for(size_t i = 0;i<file_len;i++)
    //{
    //    file_buffer[i] = 'a' + i % 26;
    //}
    int ret = -1;

    if (fuse_parse_cmdline(&args, &opts) != 0)
        return 1;
    if (opts.show_help) {
        printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
        fuse_cmdline_help();
        fuse_lowlevel_help();
        ret = 0;
        goto err_out1;
    } else if (opts.show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        ret = 0;
        goto err_out1;
    }

    if(opts.mountpoint == NULL) {
        printf("usage: %s [options] <mountpoint>\n", argv[0]);
        printf("       %s --help\n", argv[0]);
        ret = 1;
        goto err_out1;
    }

    se = fuse_session_new(&args, &hello_ll_oper,
                  sizeof(hello_ll_oper), rpmactx);
    if (se == NULL)
        goto err_out1;

    if (fuse_set_signal_handlers(se) != 0)
        goto err_out2;

    if (fuse_session_mount(se, opts.mountpoint) != 0)
        goto err_out3;

    fuse_daemonize(opts.foreground);

    /* Block until ctrl+c or fusermount -u */
    if (opts.singlethread)
        ret = fuse_session_loop(se);
    else {
        config.clone_fd = opts.clone_fd;
        config.max_idle_threads = opts.max_idle_threads;
        ret = fuse_session_loop_mt(se, &config);
    }

    fuse_session_unmount(se);
err_out3:
    fuse_remove_signal_handlers(se);
err_out2:
    fuse_session_destroy(se);
err_out1:
    free(opts.mountpoint);
    fuse_opt_free_args(&args);

    return ret ? 1 : 0;
}
