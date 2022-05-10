# mijia-1s-camera

```
[root@rk3326_64:~]# LD_PRELOAD=<path-to-libcamd>/libcamd.so /opt/rockrobo/cleaner/bin/rr_loader -d
```

```
[root@rk3326_64:~]# rrcamd -a 0.0.0.0 -p 8080 -s <path-to-offline-image>/splash.jpg
```

Type http://IP_ADDRESS:8080/ into your browser:

![camera](images/camera.jpg?raw=true "Camera View")
