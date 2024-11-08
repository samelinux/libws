# libws
A simple websocket server written in c using poll and openssl

# References
Some years ago I downloaded the source of [wsServer](https://github.com/Theldus/wsServer) to use it in one of my project.
My changes include:
 - merged all source file in one single c/h, also removing the sha1 and base64 implementations in favour of the openssl ones
 - added openssl to support secure websocket (still in beta, it needs some work and errors handling)
 - use poll instaed of threads to ease the integration in project where cuncurrency can become a problem

Since the code has changed too much i'm not going to fork the original repo, but still, all credits for the initial release go to Davidson Francis.
