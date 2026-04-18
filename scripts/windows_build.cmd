@echo off
go build ^
    -trimpath ^
    -ldflags="-s -w" ^
    -tags netgo ^
    -o .\out\http2cert.exe .\cmd\http2cert
