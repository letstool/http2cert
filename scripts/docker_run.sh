#!/bin/bash

docker run -it --rm -p 8080:8080 -e LISTEN_ADDR=0.0.0.0:8080 letstool/http2cert:latest
