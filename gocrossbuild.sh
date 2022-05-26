#!/bin/bash

GOOS=darwin GOARCH=amd64 go build -o tcpfw-darwin tcpfw.go
GOOS=windows GOARCH=amd64 go build -o tcpfw-windows.exe tcpfw.go
GOOS=freebsd GOARCH=amd64 go build -o tcpfw-freebsd tcpfw.go
GOOS=linux GOARCH=arm64 go build -o tcpfw-linux-arm64 tcpfw.go
GOOS=linux GOARCH=amd64 go build -o tcpfw-linux tcpfw.go
