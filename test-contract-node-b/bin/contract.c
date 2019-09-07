#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {

    char buffer[1024];

    int lc = 0;
    while (fgets(buffer, 1023, stdin)) {
        buffer[1023] = '\0';
        int len = strlen(buffer);
        if (len < 1022) {
            buffer[len-1] = '^';
            buffer[len] = '\n';
            buffer[len+1] = '\0';
        }
        //printf("%s", buffer);
        fflush(stdout);

        if (lc > 0) {
            char* tok = buffer;
            while(*tok && *tok++ != '=');
           
            if (*tok) { 
                int fdin = -1, fdout = -1;
                sscanf(tok, "%d:%d", &fdin, &fdout);
                //printf("FDS: %d, %d\n", fdin, fdout);
            
                int bytes_available = 0;
                ioctl(fdin, FIONREAD, &bytes_available);


                printf("Bytes available on %d: %d bytes\n", fdin, bytes_available); 

                char b2[1024];
                if (bytes_available > 0) {
                    int len = read(fdin, b2, 1024);
                    if (len > 0) {
                        for (size_t i = 0; i < len; ++i) {
                            b2[i] = toupper(b2[i]);
                        }
                        write(fdout, b2, len);
                        fprintf(stdout, "wrote %d bytes to fd %d\n", len, fdout);
                    }
                }
            }
        }
        lc++;
    }

    return 0;
}
