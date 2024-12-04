#include "../include/server.h"


int start_server(int port, void(*callback)(int fd, void* data, ssize_t data_size))
{
    int sock_fd;
    int conn;
    struct sockaddr_in addr;
    int status = true;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0) ) == 0)
    {
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sock_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    {
        return -1;
    }


    if (listen(sock_fd, 1) < 0)
    {
        return -1;
    }


    while (1)
    {
        conn = accept(sock_fd, (struct sockaddr*) &addr, (socklen_t*) sizeof(addr));

        if (conn < 0)
        {
            puts("Accept failed!");
            status = false;
            break;
        }
    }

    return status;
}