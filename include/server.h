#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int start_server(int port, void(*callback)(int fd, void* data, ssize_t data_size));