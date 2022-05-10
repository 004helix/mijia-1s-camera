#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <turbojpeg.h>
#include <linux/videodev2.h>


#define DEVICE           "/dev/video1"  // track device name
#define RRCAM_SOCK_NAME  "rrcamd.sock"  // rrcamd socket name
#define JPEG_QUALITY     85             // jpeg image quality
#define SKIP_FRAMES      5              // skip frames (30 fps, skip 5 after each: 30/6 = 5 fps)


// track v4l2 stream
static struct {
    int devfd;           // track device fd
    uint32_t width;      // detected image width
    uint32_t height;     // detected image height
    uint32_t sizeimage;  // detected image size
    int mmaps_count;     // allocated mmaps count
    struct buffers {     // allocated mmaps
        int offset_set;
        off_t offset;
        void *data;
    } *mmaps;
    int skip;            // current skip counter
} cfg;


// mjpeg variables
static pthread_t mjpeg_thread_id;
static pthread_cond_t frame_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t frame_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned char *frame_buffer = NULL;
static int mjpeg_exit = 0;  // thread exit flag
static int mjpeg = 0;       // thread running


// hooked functions
static int (*orig_open)(const char*, int oflag, ...);
static int (*orig_close)(int fd);
static int (*orig_ioctl)(int fd, int cmd, void *arg);
static void *(*orig_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);


void __attribute__((constructor)) libcamd_init(void)
{
    orig_open = dlsym(RTLD_NEXT, "open");
    orig_close = dlsym(RTLD_NEXT, "close");
    orig_ioctl = dlsym(RTLD_NEXT, "ioctl");
    orig_mmap = dlsym(RTLD_NEXT, "mmap");

    memset(&cfg, 0, sizeof(cfg));
    cfg.devfd = -1;
}


static void cfg_cleanup(void)
{
    if (cfg.mmaps != NULL)
        free(cfg.mmaps);

    memset(&cfg, 0, sizeof(cfg));

    cfg.devfd = -1;
}


static void *mjpeg_compress_loop(void *args)
{
    size_t su_size;
    struct sockaddr_un su;
    unsigned char *jpeg;
    unsigned long jlen;
    tjhandle handle;
    int fd;

    // check image width and height
    if (cfg.width == 0 || cfg.height == 0) {
        fprintf(stderr, "libcamd: mjpeg_compress_loop(): image width and height is unknown!\n");
        goto dryrun;
    }

    // connect to rrcamd
    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd == -1) {
        fprintf(stderr, "libcamd: mjpeg_compress_loop(): failed to create socket!\n");
        goto dryrun;
    }

    memset(&su, 0, sizeof(su));
    su.sun_family = AF_LOCAL;
    strncpy(su.sun_path + 1, RRCAM_SOCK_NAME, sizeof(su.sun_path) - 2);
    su.sun_path[0] = '@';
    su_size = SUN_LEN(&su);
    su.sun_path[0] = 0;

    if (connect(fd, (const struct sockaddr *)&su, su_size) == -1) {
        close(fd);
        fprintf(stderr, "libcamd: mjpeg_compress_loop(): failed to connect to rrcam!\n");
        goto dryrun;
    }

    // init turbojpeg compression
    if ((handle = tjInitCompress()) == NULL) {
        close(fd);
        fprintf(stderr, "libcamd: mjpeg_compress_loop(): tjInitCompress() failed!\n");
        goto dryrun;
    }

    // NV12 grayscale -> only first (width*height) bytes are used
    // U & V planes are empty (0x80)
    jlen = tjBufSize(cfg.width, cfg.height, TJSAMP_GRAY);
    jpeg = tjAlloc(jlen);
    if (jpeg == NULL) {
        close(fd);
        tjDestroy(handle);
        fprintf(stderr, "libcamd: mjpeg_compress_loop(): failed to allocate output buffer!\n");
        goto dryrun;
    }

    // init done
    fprintf(stderr, "libcamd: mjpeg_compress_loop(): start\n");

    while (1) {
        pthread_mutex_lock(&frame_mutex);

        while (frame_buffer == NULL && !mjpeg_exit)
            pthread_cond_wait(&frame_cond, &frame_mutex);

        if (mjpeg_exit) {
            pthread_mutex_unlock(&frame_mutex);
            close(fd);
            tjFree(jpeg);
            tjDestroy(handle);
            fprintf(stderr, "libcamd: mjpeg_compress_loop(): exit\n");
            return NULL;
        }

        // compress frame
        if (tjCompress2(handle, frame_buffer, cfg.width, 0, cfg.height, TJPF_GRAY, &jpeg, &jlen, TJSAMP_GRAY, JPEG_QUALITY, TJFLAG_NOREALLOC | TJFLAG_FASTDCT) == 0) {
            uint32_t frame_len = jlen;
            struct iovec iov[2] = {
               { .iov_base = &frame_len, .iov_len = 4 },
               { .iov_base = jpeg, .iov_len = jlen },
            };

            writev(fd, iov, 2);
        } else {
            fprintf(stderr, "libcamd: frame compression failed!\n");
        }

        frame_buffer = NULL;

        pthread_mutex_unlock(&frame_mutex);
    }

    dryrun:
    while (1) {
        pthread_mutex_lock(&frame_mutex);

        while (frame_buffer == NULL && !mjpeg_exit)
            pthread_cond_wait(&frame_cond, &frame_mutex);

        if (mjpeg_exit) {
            pthread_mutex_unlock(&frame_mutex);
            fprintf(stderr, "libcamd: mjpeg_compress_loop(): exit\n");
            return NULL;
        }

        frame_buffer = NULL;

        pthread_mutex_unlock(&frame_mutex);
    }

    return NULL;
}


int open(const char *path, int oflag, ...)
{
    int ret = orig_open(path, oflag);

    if (ret < 0 || cfg.devfd != -1)
        return ret;

    if (strcmp(path, DEVICE))
        return ret;

    fprintf(stderr, "libcamd: open(\"%s\", %d) = %d\n", DEVICE, oflag, ret);
    cfg.devfd = ret;

    return ret;
}


int close(int fd)
{
    if (fd != -1 && cfg.devfd == fd) {
        fprintf(stderr, "libcamd: close(%d)\n", fd);
        cfg_cleanup();
    }

    return orig_close(fd);
}


void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    void *ret = orig_mmap(addr, length, prot, flags, fd, offset);
    int i;

    if (cfg.devfd == -1)
        return ret;

    if (ret == (void *) -1 || fd != cfg.devfd)
        return ret;

    if (length == 0 || length != cfg.sizeimage)
        return ret;

    for (i = 0; i < cfg.mmaps_count; i++) {
        if (!cfg.mmaps[i].offset_set)
            continue;
        if (cfg.mmaps[i].offset == offset) {
            cfg.mmaps[i].data = ret;
            fprintf(stderr, "libcamd: mmap(%p, %llu, %d, %d, %d, %llu): mmaps[%d].data=%p\n",
                            addr, (long long unsigned)length, prot, flags,
                            fd, (long long unsigned)offset, i, ret);
            break;
        }
    }

    return ret;
}


int ioctl(int fd, int cmd, void *arg)
{
    int ret = orig_ioctl(fd, cmd, arg);

    if (ret == -1 || fd != cfg.devfd)
        return ret;

    switch (cmd) {
        case VIDIOC_QUERYCAP:
            fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_QUERYCAP)\n", fd);
            break;

        case VIDIOC_S_FMT: {
                struct v4l2_format *fmt = arg;

                switch (fmt->type) {
                    case V4L2_BUF_TYPE_VIDEO_CAPTURE:
                        cfg.width = fmt->fmt.pix.width;
                        cfg.height = fmt->fmt.pix.height;
                        cfg.sizeimage = fmt->fmt.pix.sizeimage;
                        fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_S_FMT, {type=V4L2_BUF_TYPE_VIDEO_CAPTURE}): width=%u, height=%u, sizeimage=%u\n",
                                        fd, (unsigned int)cfg.width, (unsigned int)cfg.height, (unsigned int)cfg.sizeimage);
                        break;

                    case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
                        if (fmt->fmt.pix_mp.num_planes == 1) {
                            cfg.width = fmt->fmt.pix_mp.width;
                            cfg.height = fmt->fmt.pix_mp.height;
                            cfg.sizeimage = fmt->fmt.pix_mp.plane_fmt[0].sizeimage;
                            fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_S_FMT, {type=V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE, fmt.pix_mp.num_planes=1}): width=%u, height=%u, sizeimage=%u\n",
                                            fd, (unsigned int)cfg.width, (unsigned int)cfg.height, (unsigned int)cfg.sizeimage);
                        } else {
                            fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_S_FMT, {type=V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE, fmt.pix_mp.num_planes=%u}): unsupported num planes\n",
                                            fd, (unsigned int)fmt->fmt.pix_mp.num_planes);
                            goto err;
                        }
                        break;

                    default:
                        fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_S_FMT, {type=?}): unsupported\n", fd);
                        goto err;
                }
            }
            break;

        case VIDIOC_REQBUFS: {
                struct v4l2_requestbuffers *req = arg;

                if (req->memory != V4L2_MEMORY_MMAP || req->count < 1)
                    goto err;

                cfg.mmaps_count = req->count;

                cfg.mmaps = malloc(sizeof(struct buffers) * cfg.mmaps_count);
                if (cfg.mmaps == NULL)
                    goto err;

                memset(cfg.mmaps, 0, sizeof(struct buffers) * cfg.mmaps_count);

                fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_REQBUFS): allocated %d mmaps\n", fd, cfg.mmaps_count);
            }
            break;

        case VIDIOC_QUERYBUF: {
                struct v4l2_buffer *buf = arg;

                if (buf->memory != V4L2_MEMORY_MMAP)
                    goto err;

                if (buf->index >= cfg.mmaps_count)
                    goto err;

                switch (buf->type) {
                    case V4L2_BUF_TYPE_VIDEO_CAPTURE:
                        cfg.mmaps[buf->index].offset_set = 1;
                        cfg.mmaps[buf->index].offset = buf->m.offset;
                        break;
                    case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
                        cfg.mmaps[buf->index].offset_set = 1;
                        cfg.mmaps[buf->index].offset = buf->m.planes[0].m.mem_offset;
                        break;
                    default:
                        goto err;
                }

                fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_QUERYBUF): index=%d, offset=%llu\n",
                                fd, buf->index, (long long unsigned)cfg.mmaps[buf->index].offset);
            }
            break;

        case VIDIOC_STREAMON:
            fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_STREAMON)\n", fd);

            // start mjpeg compression thread
            if (!mjpeg) {
                if (pthread_create(&mjpeg_thread_id, NULL, mjpeg_compress_loop, NULL) == 0) {
                    mjpeg = 1;
                }
            }

            break;

        case VIDIOC_STREAMOFF:
            fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_STREAMOFF)\n", fd);

            // stop mjpeg compression thread
            if (mjpeg) {
                pthread_mutex_lock(&frame_mutex);
                mjpeg_exit = 1;
                pthread_cond_signal(&frame_cond);
                pthread_mutex_unlock(&frame_mutex);

                pthread_join(mjpeg_thread_id, NULL);

                frame_buffer = NULL;
                mjpeg_exit = 0;
                mjpeg = 0;
            }

            break;

        case VIDIOC_DQBUF: {
                struct v4l2_buffer *buf = arg;

                if (mjpeg && buf->index < cfg.mmaps_count && cfg.mmaps[buf->index].data != NULL) {
                    if (cfg.skip == 0) {
                        pthread_mutex_lock(&frame_mutex);
                        frame_buffer = cfg.mmaps[buf->index].data;
                        pthread_cond_signal(&frame_cond);
                        pthread_mutex_unlock(&frame_mutex);
                        cfg.skip = SKIP_FRAMES;
                    } else
                        cfg.skip--;
                }
            }
            break;
/*
        case VIDIOC_QBUF: {
                struct v4l2_buffer *buf = arg;
                fprintf(stderr, "libcamd: ioctl(%d, VIDIOC_QBUF, buf.index=%d)\n", fd, buf->index);
            }
            break;
*/
    }

    return ret;

err:
    cfg_cleanup();
    return ret;
}
