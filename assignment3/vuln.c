#include <stdio.h>
#include<string.h>

void echo(char *in)
{
    char buffer[1024];

    printf("Enter some text:\n");
    strcpy(buffer, in);
    printf("You entered: %s\n", buffer);    
}

int main(int argc, char *argv[])
{
    echo(argv[1]);

    return 0;
}
