# mijia-1s-camera

```
[root@rk3326_64:~]# LD_PRELOAD=<path-to-libcamd>/libcamd.so /opt/rockrobo/cleaner/bin/rr_loader -d
```

```
[root@rk3326_64:~]# rrcamd
Usage: rrcamd [option]...

Options:
 -h, --help            show this help
 -a, --addr=ADDRESS    listen address, default loopback
 -p, --port=PORT       listen port, default 8080
 -s, --splash=FILE     splash screen jpeg file location (mandatory option)
 -o, --offline=FILE    offline image jpeg file location (mandatory option)
 -r, --replace         save new splash image when camera disconnected

Requests:
 GET /                 play mjpeg stream

[root@rk3326_64:~]# rrcamd -a 0.0.0.0 -p 8080 -s <path-to-splash-image>/splash.jpg -o <path-to-offline-image>/offline.jpg -r
```

Type http://IP_ADDRESS:8080/ into your browser:

![camera](images/camera.jpg?raw=true "Camera View")
