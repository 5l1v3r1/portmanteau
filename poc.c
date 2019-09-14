/*
 * poc.c
 * 
 * Portmanteau
 * 
 * Proof-of-Concept Generation 
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <regex.h>

#include "include/main.h"

const char *poc_begin = "#include <stdio.h>\n"
                        "#include <stdlib.h>\n"
                        "#include <fcntl.h>\n"
                        "#include <errno.h>\n\n"
                        "int main() {\n";
                        
const char *poc_end = "close(fd);\n"
                      "return 0; }\n";

int GeneratePoc(int inId, char *inDeviceName, uint inIoctl, char *inIoctlDirection, char *inIoctlBufType, char *inIoctlName, int inIoctlBuffer, int inIoctlBufferSize)
{
    char pocFilePath[256], pocFilePathOld[256], pocBuffer[4096];
    int ret, regRet;
    unsigned int i;
    regex_t regex;
    FILE *fd;
    DIR *dir;
    
    dir = opendir(POC_DIRECTORY);
    
    if(!dir)
    {
        mkdir(POC_DIRECTORY, 0700);
    }
    
    closedir(dir);
    
    if(debug) printf("Generating proof-of-concept for crash id '%d'\n\n", inId);
    
    //
    // delete the next-to-last PoC to make sure we don't unnecessarily fill up the disk
    // in other words, we try to save both the last and current PoC in case of crashes
    //
    // sure, in most cases we only want the current PoC (which caused the crash), but
    // maybe having the one before it is valuable too
    //
    // yes, this can wrap and fail, but I'm not checking the return value anyways
    //
    snprintf(pocFilePathOld, sizeof(pocFilePath), "%s/pmt-%x_%d.c", POC_DIRECTORY, inIoctl, inId - 2);
    unlink(pocFilePathOld);
    
    snprintf(pocFilePath, sizeof(pocFilePath), "%s/pmt-%x_%d.c", POC_DIRECTORY, inIoctl, inId);
    
    fd = fopen(pocFilePath, "w");
    
    if(!fd)
    {
        snprintf(errorMsg, sizeof(errorMsg), "\nError: could not open file for writing: %s\n\n", pocFilePath);
        Inception(errorMsg);
        return -1;
    }
    
    if(sizeof(inIoctlBuffer) > MAX_IOCTL_BUFFER_SIZE)
    {
        snprintf(errorMsg, sizeof(errorMsg), "\nError: ioctl buffer is huge, check yo'self: %d\n\n", sizeof(inIoctlBuffer));
        Inception(errorMsg);
        return -1;
    }
    
    fprintf(fd, "%s", poc_begin);
    
    //
    // choose the declaration based on inIoctlBufType
    //
    
    if(strncmp(inIoctlBufType, "char", 4) == 0)    fprintf(fd, "char buffer = 0x%x;\n\n", inIoctlBuffer);
    if(strncmp(inIoctlBufType, "uchar", 12) == 0)  fprintf(fd, "unsigned char buffer = 0x%x;\n\n", inIoctlBuffer);
    if(strncmp(inIoctlBufType, "short", 5) == 0)   fprintf(fd, "short buffer = 0x%x;\n\n", inIoctlBuffer);
    if(strncmp(inIoctlBufType, "ushort", 13) == 0) fprintf(fd, "unsigned short buffer = 0x%x;\n\n", inIoctlBuffer);
    if(strncmp(inIoctlBufType, "int", 3) == 0)     fprintf(fd, "int buffer = 0x%x;\n\n", inIoctlBuffer);
    if(strncmp(inIoctlBufType, "uint", 11) == 0)   fprintf(fd, "unsigned int buffer = 0x%x;\n\n", inIoctlBuffer);
    //if(strncmp(inIoctlBufType, "sock_fprog", 10) == 0)    fprintf(fd, "blah-type buffer = 0x%x;\n\n", inIoctlBuffer);
    
    fprintf(fd, "printf(\"Portmanteau PoC [id=%d]\\n\\n\");\n"
                "printf(\"device: %s\\nioctl: %s (0x%x)\\n"
                "buffer: 0x%%x\\nbuffer type: %s\\n\\n\", buffer);\n\n",
                inId, inDeviceName, inIoctlName, inIoctl, inIoctlBufType);
    
    if(strcasestr(inIoctlDirection, "ior"))  fprintf(fd, "int fd = open(\"%s\", O_RDONLY);\n\n", inDeviceName);
    if(strcasestr(inIoctlDirection, "iow"))  fprintf(fd, "int fd = open(\"%s\", O_WRONLY);\n\n", inDeviceName);
    if(strcasestr(inIoctlDirection, "iowr")) fprintf(fd, "int fd = open(\"%s\", O_RDWR);\n\n", inDeviceName);
    
    fprintf(fd, "if(fd < 0) { perror(\"open\"); return -1; }\n\n"
                "if(ioctl(fd, 0x%x, &buffer) < 0) "
                "printf(\"ioctl(): errno %%d\\n\\n\", errno);\n\n",
                inIoctl);
    
    if(strcasestr(inIoctlDirection, "ior") || strcasestr(inIoctlDirection, "iowr")) fprintf(fd, "printf(\"returned buffer: %%x\\n\\n\", buffer);\n\n");
    
    fprintf(fd, "%s", poc_end);
    
    fclose(fd);
    
    printf("[+] PoC saved at '%s'\n", pocFilePath);
    
    return 0;
}
