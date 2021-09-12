#!/bin/bash

NGINX_DIR="/home/chehw/git/nginx-release-1.18.0"
NGINX_SRC_DIR="$NGINX_DIR/src"


INCLUDES=" -I$NGINX_DIR/objs "
INCLUDES+=" -I$NGINX_SRC_DIR/core "
INCLUDES+=" -I$NGINX_SRC_DIR/event "
INCLUDES+=" -I$NGINX_SRC_DIR/http "
INCLUDES+=" -I$NGINX_SRC_DIR/os/unix "
INCLUDES+=" -I$NGINX_SRC_DIR/http/modules "

CC="gcc -std=gnu99"
CFLAGS="-g -Wall $INCLUDES "

${CC} -fPIC -pipe -g -Wall -Wpointer-arith -o json_api_filter.o -c json_api_filter.c ${CFLAGS}
