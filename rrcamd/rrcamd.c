#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <string.h>
#include <signal.h>
#include <alloca.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

/* libevent */
#include <event2/event_struct.h>
#include <event2/event.h>

/* libturbojpeg */
#include <turbojpeg.h>

#define HTTP_DEFAULT_ADDR  "127.0.0.1"
#define HTTP_DEFAULT_PORT  8000
#define HTTP_READ_TIMEOUT  30
#define HTTP_READ_BUFFER   16384

#define RRCAM_SOCKET_NAME  "rrcamd.sock"
#define RRCAM_READ_TIMEOUT 30
#define RRCAM_BUFFER_SIZE  1048576  // 1MiB
#define RRCAM_READ_SIZE    65536

#define SPLASH_INTERVAL    500      // msec

const static char boundary_charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static struct event_base *eb;

static char *splash_file_name = NULL;
static struct event splash_ev;
static int splash_len = 0;
static char *splash_data = NULL;
static int offline_len = 0;
static char *offline_data = NULL;

static int rrcam_fd = -1;
static char rrbuffer1[RRCAM_BUFFER_SIZE];
static char rrbuffer2[RRCAM_BUFFER_SIZE];
static char *rrbuffer = rrbuffer1;
static int rrbuf_len = 0;
static char *frame = NULL; // current frame
static int frame_size = 0; // current frame size
static char *prev = NULL;  // previous frame
static int prev_size = 0;  // previous frame size
static int replace = 0;

struct http_client {
    struct http_client *next;
    char boundary[32];
    struct event ev;
    size_t reqsize;
    char *request;
    int waitreq;
    int fd;
};

static struct http_client *http_clients = NULL;
char http_reply_mpjpeg[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: multipart/x-mixed-replace; boundary=\"%s\"\r\n"
    "Cache-Control: no-store, no-cache, must-revalidate, pre-check=0, post-check=0, max-age=0\r\n"
    "Pragma: no-cache\r\n"
    "Expires: Sun, 1 Jan 2000 00:00:00 GMT\r\n"
    "Connection: close\r\n\r\n--%s\r\n";
char frame_headers[] =
    "Content-Type: image/jpeg\r\n"
    "Content-Length: %d\r\n"
    "X-Timestamp: 0.000000\r\n"
    "\r\n";


static void render_splash_image(const unsigned char *bg, int bg_len, const unsigned char*img, int img_len)
{
    tjhandle handle = NULL;
    unsigned char *bg_raw = NULL;
    unsigned char *img_raw = NULL;
    int bg_width, bg_height;
    int img_width, img_height;
    int subsamp, colorspace;
    unsigned char *jpeg = NULL;
    unsigned long jlen = 0;

    if ((handle = tjInitDecompress()) == NULL)
        return;

    if (tjDecompressHeader3(handle, bg, bg_len, &bg_width, &bg_height, &subsamp, &colorspace) < 0)
        goto done;

    if (tjDecompressHeader3(handle, img, img_len, &img_width, &img_height, &subsamp, &colorspace) < 0)
        goto done;

    if ((bg_raw = malloc(bg_width*bg_height)) == NULL)
        goto done;

    if ((img_raw = malloc(img_width*img_height)) == NULL)
        goto done;

    if (tjDecompress2(handle, bg, bg_len, bg_raw, bg_width, 0, bg_height, TJPF_GRAY, 0) < 0)
        goto done;

    if (tjDecompress2(handle, img, img_len, img_raw, img_width, 0, img_height, TJPF_GRAY, 0) < 0)
        goto done;

    tjDestroy(handle);
    handle = NULL;

    if (bg_height > img_height) {
        int hoff = (bg_height - img_height) / 2;
        int h;

        if (bg_width > img_width) {
            int woff = (bg_width - img_width) / 2;

            for (h = 0; h < img_height; h++)
                memcpy(bg_raw + ((h + hoff) * bg_width) + woff, img_raw + (h * img_width), img_width);
        } else {
            int woff = (img_width - bg_width) / 2;

            for (h = 0; h < img_height; h++)
                memcpy(bg_raw + ((h + hoff) * bg_width), img_raw + (h * img_width) + woff, bg_width);
        }
    } else {
        int hoff = (img_height - bg_height) / 2;
        int h;

        if (bg_width > img_width) {
            int woff = (bg_width - img_width) / 2;

            for (h = 0; h < bg_height; h++)
                memcpy(bg_raw + (h * bg_width) + woff, img_raw + ((h + hoff) * img_width), img_width);
        } else {
            int woff = (img_width - bg_width) / 2;

            for (h = 0; h < bg_height; h++)
                memcpy(bg_raw + (h * bg_width), img_raw + ((h + hoff) * img_width) + woff, bg_width);
        }
    }

    free(img_raw);
    img_raw = NULL;

    if ((handle = tjInitCompress()) == NULL)
        goto done;

    if (tjCompress2(handle, bg_raw, bg_width, 0, bg_height, TJPF_GRAY, &jpeg, &jlen, TJSAMP_GRAY, 85, TJFLAG_FASTDCT) != 0)
        goto done;

    if ((img_raw = malloc(jlen)) == NULL)
        goto done;

    memcpy(img_raw, jpeg, jlen);
    free(splash_data);
    splash_data = (char *)img_raw;
    splash_len = jlen;
    img_raw = NULL;

    if (replace) {
        char *new_file_name;
        int fd;

        new_file_name = malloc(strlen(splash_file_name) + 5);
        if (new_file_name == NULL)
            goto done;

        strcpy(new_file_name, splash_file_name);
        strcat(new_file_name, ".tmp");

        fd = open(new_file_name, O_WRONLY | O_TRUNC | O_CREAT, 0644);
        if (fd == -1) {
            free(new_file_name);
            goto done;
        }

        if (write(fd, splash_data, splash_len) != splash_len) {
            close(fd);
            unlink(new_file_name);
            free(new_file_name);
            goto done;
        }

        close(fd);

        if (rename(new_file_name, splash_file_name) == -1)
            unlink(new_file_name);

        free(new_file_name);
    }

    done:
    if (jpeg != NULL)
        tjFree(jpeg);
    if (img_raw != NULL)
        free(img_raw);
    if (bg_raw != NULL)
        free(bg_raw);
    if (handle != NULL)
        tjDestroy(handle);
    return;
}


static void http_client_close(struct http_client *client)
{
    if (client == http_clients)
        http_clients = client->next;
    else {
        struct http_client *curr;
        for (curr = http_clients; curr->next != client; curr = curr->next);
        curr->next = client->next;
    }

    event_del(&client->ev);

    if (client->request)
        free(client->request);

    close(client->fd);

    free(client);
}


static void on_splash_timer(int fd, short ev, void *arg)
{
    struct http_client *client;
    size_t headers_len;
    char headers[256];

    if (rrcam_fd != -1)
        return;

    if (prev != splash_data) {
        prev = splash_data;
        prev_size = splash_len;
    }

    if (http_clients != NULL)
        headers_len = snprintf(headers, sizeof(headers),
                               frame_headers, splash_len);

    /* send splash to http clients */
    for (client = http_clients; client;) {
        struct iovec iov[3];
        char bndbuf[64];
        ssize_t ret;

        /* client not sent full request yet */
        if (client->waitreq) {
            client = client->next;
            continue;
        }

        /* send frame to client */
        iov[0].iov_base = headers;
        iov[0].iov_len = headers_len;
        iov[1].iov_base = splash_data;
        iov[1].iov_len = splash_len;
        iov[2].iov_base = bndbuf;
        iov[2].iov_len = snprintf(bndbuf, sizeof(bndbuf),
                                  "--%s\r\n", client->boundary);

        ret = writev(client->fd, iov, 3);

        if (ret == -1) {
            struct http_client *to_close = client;

            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                client = client->next;
                continue;
            }

            warn("error writing frame");
            client = client->next;
            http_client_close(to_close);
            continue;
        }

        client = client->next;
    }
}


static void on_rrcam_read(int fd, short ev, void *arg)
{
    struct event *rrev = (struct event *)arg;
    struct http_client *client;
    uint32_t payload_size;
    size_t headers_len;
    char headers[256];
    size_t size;
    int ret;

    /* read data into input buffer */
    size = RRCAM_BUFFER_SIZE - rrbuf_len;
    if (size > RRCAM_READ_SIZE)
        size = RRCAM_READ_SIZE;

    if (size == 0) {
        warnx("rrcam buffer overflow (corrupted stream?)");
        goto close;
    }

    ret = read(fd, rrbuffer + rrbuf_len, size);

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        warn("failed to read from rrcam client");
        goto close;
    }

    if (ret == 0)
        goto close;

    rrbuf_len += ret;

    /* parse length */
    parse:
    if (rrbuf_len < 4)
        return;

    payload_size = *(uint32_t *)rrbuffer;

    /* check payload size */
    if (payload_size > rrbuf_len + 4)
        return;

    frame = rrbuffer + 4;
    frame_size = payload_size;

    /* send frame to http clients */
    if (http_clients != NULL)
        headers_len = snprintf(headers, sizeof(headers),
                               frame_headers, frame_size);

    for (client = http_clients; client;) {
        struct iovec iov[3];
        char bndbuf[64];
        ssize_t ret;

        /* client not sent full request yet */
        if (client->waitreq) {
            client = client->next;
            continue;
        }

        /* send frame to client */
        iov[0].iov_base = headers;
        iov[0].iov_len = headers_len;
        iov[1].iov_base = rrbuffer + 4;
        iov[1].iov_len = frame_size;
        iov[2].iov_base = bndbuf;
        iov[2].iov_len = snprintf(bndbuf, sizeof(bndbuf),
                                  "--%s\r\n", client->boundary);

        ret = writev(client->fd, iov, 3);

        if (ret == -1) {
            struct http_client *to_close = client;

            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                client = client->next;
                continue;
            }

            warn("error writing frame");
            client = client->next;
            http_client_close(to_close);
            continue;
        }

        client = client->next;
    }

    /* swap rrbuffers */
    size = rrbuf_len - payload_size - 4;

    if (rrbuffer == rrbuffer1)
        rrbuffer = rrbuffer2;
    else
        rrbuffer = rrbuffer1;

    if (size > 0)
        memcpy(rrbuffer, frame + frame_size, size);

    rrbuf_len = size;

    /* save previous frame */
    prev = frame;
    prev_size = frame_size;

    /* reset current frame */
    frame = NULL;
    frame_size = 0;

    /* retry parse left data in buffer */
    if (rrbuf_len > 0)
        goto parse;

    return;

    close:
    render_splash_image((unsigned char *)prev, prev_size, (unsigned char *)offline_data, offline_len);
    event_del(rrev);
    close(rrcam_fd);
    rrcam_fd = -1;
}


static void on_http_read(int fd, short ev, void *arg)
{
    struct http_client *client = (struct http_client *)arg;
    char *http_reply;
    char *buffer;
    ssize_t ret;
    int start;
    void *b;

    /* client read timeout */
    if (ev == EV_TIMEOUT) {
        fprintf(stderr, "http client read timeout\n");
        goto close;
    }

    /* client already sent request */
    if (!client->waitreq)
        goto close;

    /* reallocate request buffer */
    buffer = realloc(client->request, client->reqsize + HTTP_READ_BUFFER);
    if (buffer == NULL) {
        fprintf(stderr, "cannot allocate memory\n");
        goto close;
    }
    client->request = buffer;

    /* read (part of) request */
    ret = read(fd, buffer + client->reqsize, HTTP_READ_BUFFER);

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        else
            goto close;
    }

    if (ret == 0)
        goto close;

    /* search \r\n\r\n in request */
    start = client->reqsize - 3;
    client->reqsize += ret;

    if (start < 0) {
        if (client->reqsize > 4)
            b = memmem(client->request, client->reqsize, "\r\n\r\n", 4);
        else
            b = NULL;
    } else
        b = memmem(client->request + start, client->reqsize - start, "\r\n\r\n", 4);

    if (b == NULL)
        return;

    /* whole request was read */
    client->waitreq = 0;

    http_reply = alloca(sizeof(http_reply_mpjpeg) + sizeof(client->boundary) * 2 + 1);

    snprintf(http_reply, sizeof(http_reply_mpjpeg) + sizeof(client->boundary) * 2 + 1,
             http_reply_mpjpeg, client->boundary, client->boundary);

    if (write(fd, http_reply, strlen(http_reply)) == -1)
        goto close;

    free(client->request);
    client->request = NULL;
    client->reqsize = 0;

    /* handle first frame */
    if (prev) {
        struct iovec iov[3];
        char headers[256];
        char bndbuf[64];

        iov[0].iov_base = headers;
        iov[0].iov_len = snprintf(headers, sizeof(headers),
                                  frame_headers, prev_size);
        iov[1].iov_base = prev;
        iov[1].iov_len = prev_size;
        iov[2].iov_base = bndbuf;
        iov[2].iov_len = snprintf(bndbuf, sizeof(bndbuf),
                                  "--%s\r\n", client->boundary);

        ret = writev(client->fd, iov, 3);

        if (ret == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
            warn("error writing frame");
            goto close;
        }
    }

    /* reschedule read event without read timeout */
    event_del(&client->ev);
    event_add(&client->ev, NULL);

    return;

    close:
    http_client_close(client);
}


static void on_httpd_accept(int fd, short ev, void *arg)
{
    struct http_client *client;
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    struct timeval tv;
    int client_fd;
    int i;

    /* accept the new connection. */
    client_fd = accept4(fd, (struct sockaddr *)&addr, &len, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (client_fd == -1) {
        warn("http accept failed");
        return;
    }

    /* allocate client context */
    client = malloc(sizeof(struct http_client));
    if (client == NULL) {
        fprintf(stderr, "malloc failed\n");
        close(client_fd);
        return;
    }

    /* fill context fields */
    client->fd = client_fd;
    client->reqsize = 0;
    client->request = NULL;
    client->waitreq = 1;

    for (i = 0; i < sizeof(client->boundary) - 1; i++)
        client->boundary[i] = boundary_charset[rand() % (sizeof(boundary_charset) - 1)];
    client->boundary[i] = '\0';

    /* add http client to list */
    client->next = http_clients;
    http_clients = client;

    /* schedule read events */
    event_assign(&client->ev, eb, client_fd, EV_READ | EV_TIMEOUT | EV_PERSIST, on_http_read, client);
    tv.tv_sec = HTTP_READ_TIMEOUT;
    tv.tv_usec = 0;
    event_add(&client->ev, &tv);
}


static void on_rrcam_accept(int fd, short ev, void *arg)
{
    struct event *rrev;
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    struct timeval tv;
    int client_fd;

    /* accept the new connection. */
    client_fd = accept4(fd, (struct sockaddr *)&addr, &len, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (client_fd == -1) {
        warn("rrcam accept failed");
        return;
    }

    /* check rrcam already connected */
    if (rrcam_fd != -1) {
        warnx("rrcam already connected");
        close(client_fd);
        return;
    }

    rrev = malloc(sizeof(struct event));
    if (rrev == NULL) {
        warnx("malloc failed");
        close(client_fd);
        return;
    }

    rrcam_fd = client_fd;
    rrbuf_len = 0;

    prev = splash_data;
    prev_size = splash_len;

    frame = NULL;
    frame_size = 0;

    /* schedule read event */
    event_assign(rrev, eb, rrcam_fd, EV_READ | EV_TIMEOUT | EV_PERSIST, on_rrcam_read, rrev);
    tv.tv_sec = RRCAM_READ_TIMEOUT;
    tv.tv_usec = 0;
    event_add(rrev, &tv);
}


static void usage(int exit_code) {
    fprintf(stderr, "Usage: rrcamd [option]...\n"
            "\n"
            "Options:\n"
            " -h, --help            show this help\n"
            " -a, --addr=ADDRESS    listen address, default loopback\n"
            " -p, --port=PORT       listen port, default 8080\n"
            " -s, --splash=FILE     splash screen jpeg file location (mandatory option)\n"
            " -o, --offline=FILE    offline image jpeg file location (mandatory option)\n"
            " -r, --replace         save new splash image when camera disconnected\n"
            "\n"
            "Requests:\n"
            " GET /                 play mjpeg stream\n"
            "\n");
    exit(exit_code);
}


int main(int argc, char **argv)
{
    struct timeval tv;

    struct event rrcam_ev;
    struct sockaddr_un su;
    size_t su_size;
    int rrcam;

    struct event httpd_ev;
    struct sockaddr_storage ss;
    size_t ss_size;
    int httpd;

    char *addr = NULL;
    int port = HTTP_DEFAULT_PORT;
    int c;

    /* srand */
    srand(time(NULL));

    /* init libevent */
    eb = event_base_new();
    if (eb == NULL)
        err(EXIT_FAILURE, "event_base_new");

    /* init signals */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    /* parse arguments */
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help", no_argument, NULL, 'h'},
            {"addr", required_argument, NULL, 'a'},
            {"port", required_argument, NULL, 'p'},
            {"splash", required_argument, NULL, 's'},
            {"offline", required_argument, NULL, 'o'},
            {"replace", no_argument, NULL, 'r'},
            {NULL, 0, NULL, 0}
        };

        c = getopt_long(argc, argv, "ha:p:s:o:r", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(0);

            case 'a':
                addr = strdup(optarg);
                break;

            case 'p': {
                char *endptr;
                port = strtol(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "Bad port: %s\n", endptr);
                    usage(EXIT_FAILURE);
                }
                if (port < 1 || port > 65535) {
                    fprintf(stderr, "Port out of range: %d\n", port);
                    usage(EXIT_FAILURE);
                }
                break;
            }

            case 's': {
                int fd = open(optarg, O_RDONLY);
                struct stat st;

                if (fd == -1)
                    err(EXIT_FAILURE, "failed to open() splash file");

                if (fstat(fd, &st) == -1)
                    err(EXIT_FAILURE, "failed to fstat() splash file");

                if (st.st_size > RRCAM_BUFFER_SIZE)
                    errx(EXIT_FAILURE, "splash file too big");

                if ((splash_data = malloc(st.st_size)) == NULL)
                    errx(EXIT_FAILURE, "cannot allocate memory");

                if (read(fd, splash_data, st.st_size) != st.st_size)
                    err(EXIT_FAILURE, "failed to read() splash file");

                splash_len = (int)st.st_size;
                close(fd);

                splash_file_name = strdup(optarg);
                if (splash_file_name == NULL)
                    errx(EXIT_FAILURE, "Cannot allocate memory");

                break;
            }

            case 'o': {
                int fd = open(optarg, O_RDONLY);
                struct stat st;

                if (fd == -1)
                    err(EXIT_FAILURE, "failed to open() offline file");

                if (fstat(fd, &st) == -1)
                    err(EXIT_FAILURE, "failed to fstat() offline file");

                if (st.st_size > RRCAM_BUFFER_SIZE)
                    errx(EXIT_FAILURE, "offline file too big");

                if ((offline_data = malloc(st.st_size)) == NULL)
                    errx(EXIT_FAILURE, "cannot allocate memory");

                if (read(fd, offline_data, st.st_size) != st.st_size)
                    err(EXIT_FAILURE, "failed to read() offline file");

                offline_len = (int)st.st_size;
                close(fd);
                break;
            }

            case 'r':
                replace++;

            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                abort();
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unknown argument: %s\n", argv[optind]);
        usage(EXIT_FAILURE);
    }

    if (splash_data == NULL || offline_data == NULL)
        usage(EXIT_FAILURE);

    /* setup default values */
    if (addr == NULL)
        addr = HTTP_DEFAULT_ADDR;

    /* create, bind and listen RRCAM_SOCKET_NAME */
    su.sun_family = AF_LOCAL;
    strncpy(su.sun_path + 1, RRCAM_SOCKET_NAME, sizeof(su.sun_path) - 2);
    su.sun_path[0] = 'S';
    su_size = SUN_LEN(&su);
    su.sun_path[0] = 0;

    rrcam = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (rrcam < 0)
        err(EXIT_FAILURE, "rrcam socket failed");

    if (bind(rrcam, (struct sockaddr *)&su, su_size) < 0)
        err(EXIT_FAILURE, "rrcam bind failed");

    if (listen(rrcam, 5) < 0)
        err(EXIT_FAILURE, "rrcam listen failed");

    /* create sockaddr_storage from addr and port */
    if (inet_pton(AF_INET6, addr, &(*((struct sockaddr_in6 *)&ss)).sin6_addr) != 0) {
        ss.ss_family = AF_INET6;
        (*((struct sockaddr_in6 *)&ss)).sin6_port = htons(port);
        ss_size = sizeof(struct sockaddr_in6);
    } else if (inet_pton(AF_INET, addr, &(*((struct sockaddr_in *)&ss)).sin_addr) != 0) {
        (*((struct sockaddr_in *)&ss)).sin_port = htons(port);
        ss.ss_family = AF_INET;
        ss_size = sizeof(struct sockaddr_in);
    } else {
        fprintf(stderr, "Can't parse address: %s\n", addr);
        usage(EXIT_FAILURE);
    }

    /* create, bind and listen httpd socket */
    httpd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (httpd < 0)
        err(EXIT_FAILURE, "httpd socket failed");

    c = 1;
    if (setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c)) == -1)
        err(EXIT_FAILURE, "httpd setsockopt failed");

    if (bind(httpd, (struct sockaddr *)&ss, ss_size) < 0)
        err(EXIT_FAILURE, "httpd bind failed");

    if (listen(httpd, 5) < 0)
        err(EXIT_FAILURE, "httpd listen failed");

    /* set previous frame to slash */
    prev = splash_data;
    prev_size = splash_len;

    /* start splash event loop */
    event_assign(&splash_ev, eb, -1, EV_PERSIST, on_splash_timer, NULL);
    tv.tv_sec = 0;
    tv.tv_usec = SPLASH_INTERVAL * 1000;
    event_add(&splash_ev, &tv);

    /* start rrcam read loop */
    event_assign(&rrcam_ev, eb, rrcam, EV_READ | EV_PERSIST, on_rrcam_accept, NULL);
    event_add(&rrcam_ev, NULL);

    /* start httpd loop */
    event_assign(&httpd_ev, eb, httpd, EV_READ | EV_PERSIST, on_httpd_accept, NULL);
    event_add(&httpd_ev, NULL);

    /* event_base start */
    event_base_dispatch(eb);

    return 0;
}
