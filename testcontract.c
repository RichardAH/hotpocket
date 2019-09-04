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
        printf("%s", buffer);
        fflush(stdout);

        if (lc > 0) {
            char* tok = buffer;
            while(*tok && *tok++ != '=');
           
            if (*tok) { 
                int fdin = -1, fdout = -1;
                sscanf(tok, "%d:%d", &fdin, &fdout);
                printf("FDS: %d, %d\n", fdin, fdout);
            
                FILE* inp = fdopen(fdin, "rb");
                FILE* out = fdopen(fdout, "wb");

                char b2[1024];
                if (fgets(b2, 1023, inp)) {
                    b2[0] = '*';
                    fprintf(out, "%s", b2);
                    fprintf(stdout, "%s", b2);
                }
            }
        }
        lc++;
    }

    return 0;
}
