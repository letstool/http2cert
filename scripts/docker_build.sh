#!/bin/bash

IMAGE_TAG=letstool/http2cert:latest

docker build \
	-t "$IMAGE_TAG" \
       -f build/Dockerfile \
       .
