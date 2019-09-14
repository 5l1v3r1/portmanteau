/*
 * fuzz.c
 * 
 * Portmanteau
 *
 * Fuzzing operations
 * 
 * Notes:
 * 
 * eg. device=/dev/net/tun, ioctl=TUNGETFEATURES (0x800454cf), buf=[insert some int]
 * returned buf: 7003
 *
 * reference: http://sourceforge.net/p/ltp/mailman/ltp-list/?viewmonth=200812&viewday=21
 * 
 * Lots of repetition here.. look away! :P 
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include <inttypes.h>
#include <limits.h>
#include <regex.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include "include/main.h"

#undef CHAR_MIN
#define CHAR_MIN 0


/*
 * Fuzz a device with random buffers generated from type information
 * 
 * Notes:
 * 
 * Eg. device=/dev/net/tun, ioctl=0x400454c8, bufsize=4
 * 
 * open('tun', 0x400454c8, random-value-in-primitive-range)
 * 
 */
int FuzzRandom(char *inDeviceName, uint iterations, char *inIoctlName, uint inIoctl, char *inIoctlBufType, int inIoctlBufSize, char *inIoctlDirection)
{
    int regRet;
    uint id = 0;
    
    if(strncmp(inIoctlBufType, "char", 4) == 0)
    {
        for(id = 1; id <= iterations; id++)
        {
            printf("[%u/%u] iteration initiated for %s\n\n", id, iterations, inIoctlName);
            
            int ret = FuzzRandomSChar(id, inDeviceName, inIoctlName, inIoctl, inIoctlBufType, inIoctlBufSize, inIoctlDirection);
            
            printf("================================================================\n\n");
        }
    }
    
    else if(strncmp(inIoctlBufType, "uchar", 5) == 0)
    {
        for(id = 1; id <= iterations; id++)
        {
            printf("[%u/%u] iteration initiated for %s\n\n", id, iterations, inIoctlName);
            
            int ret = FuzzRandomUChar(id, inDeviceName, inIoctlName, inIoctl, inIoctlBufType, inIoctlBufSize, inIoctlDirection);
            
            printf("================================================================\n\n");
        }
    }
    
    else if(strncmp(inIoctlBufType, "short", 5) == 0)
    {
        for(id = 1; id <= iterations; id++)
        {
            printf("[%u/%u] iteration initiated for %s\n\n", id, iterations, inIoctlName);
            
            FuzzRandomSShort(id, inDeviceName, inIoctlName, inIoctl, inIoctlBufType, inIoctlBufSize, inIoctlDirection);
            
            printf("================================================================\n\n");
        }
    }
    
    else if(strncmp(inIoctlBufType, "ushort", 6) == 0)
    {
        for(id = 1; id <= iterations; id++)
        {
            printf("[%u/%u] iteration initiated for %s\n\n", id, iterations, inIoctlName);
            
            int ret = FuzzRandomUShort(id, inDeviceName, inIoctlName, inIoctl, inIoctlBufType, inIoctlBufSize, inIoctlDirection);
            
            printf("================================================================\n\n");
        }
    }

    else if(strncmp(inIoctlBufType, "int", 3) == 0)
    {
        for(id = 1; id <= iterations; id++)
        {
            printf("[%u/%u] iteration initiated for %s\n\n", id, iterations, inIoctlName);
            
            int ret = FuzzRandomSInt32(id, inDeviceName, inIoctlName, inIoctl, inIoctlBufType, inIoctlBufSize, inIoctlDirection);
            
            printf("================================================================\n\n");
        }
    }
    
    else if(strncmp(inIoctlBufType, "uint", 4) == 0)
    {
        for(id = 1; id <= iterations; id++)
        {
            printf("[%u/%u] iteration initiated for %s\n\n", id, iterations, inIoctlName);
            
            int ret = FuzzRandomUInt32(id, inDeviceName, inIoctlName, inIoctl, inIoctlBufType, inIoctlBufSize, inIoctlDirection);
            
            printf("================================================================\n\n");
        }
    }
    
    //
    // if the given inIoctlBufType isn't supported, don't just bail..
    //
    else
    {
        printf("[!] Buffer type \"%s\" is not supported, fuzzing with uint instead..\n\n", inIoctlBufType);
        
        for(id = 1; id <= iterations; id++)
        {
            printf("[%u/%u] iteration initiated for %s\n\n", id, iterations, inIoctlName);
            
            int ret = FuzzRandomUInt32(id, inDeviceName, inIoctlName, inIoctl, "uint", inIoctlBufSize, inIoctlDirection);
            
            printf("================================================================\n\n");
        }
    }
    
    printf("[!] Completed %u fuzzing iterations for %s\n\n", iterations, inIoctlName);
    
    return 0;
}

/*
 * Random fuzzing helper functions for each supported buffer type
 * 
 */


int FuzzRandomSChar(uint id, char *inDeviceName, char *inIoctlName, uint inIoctl, char *inIoctlBufType, int inIoctlBufSize, char *inIoctlDirection)
{
    int randomInt = random();
    signed char buffer = (signed char)randomInt;
    signed char bufferCopy = buffer;
    
    if(debug) printf("[debug] randomInt = %d\nbuffer = %d\n\n", randomInt, buffer);
        
    if(GeneratePoc(id, inDeviceName, inIoctl, inIoctlDirection, inIoctlBufType, inIoctlName, buffer, sizeof(buffer)) < 0) printf("[-] Error: GeneratePoc() failed\n");
    
    int fd = OpenDevice(inDeviceName);
    if(fd < 0) printf("[-] Error: OpenDevice failed, fd = %d\n", fd);
    
    printf("[+] Sending data...\n\ndevice: %s\nioctl: %s (0x%x)\nbuffer: 0x%x\nbuffer type: %s\n\n", inDeviceName, inIoctlName, inIoctl, buffer, inIoctlBufType);
        
    if(ioctl(fd, inIoctl, &buffer) < 0) printf("[-] Error: ioctl() errno %d - %s\n\n", errno, strerror(errno));

    if((strcasestr(inIoctlDirection, "ior") || strcasestr(inIoctlDirection, "iowr")) && (buffer != bufferCopy))
    {
        printf("[%] Device returned: 0x%x\n\n", buffer);
    }
    
    close(fd);
    
    return 0;
}

int FuzzRandomUChar(uint id, char *inDeviceName, char *inIoctlName, uint inIoctl, char *inIoctlBufType, int inIoctlBufSize, char *inIoctlDirection)
{
    int randomInt = random();
    unsigned char buffer = (unsigned char)randomInt;
    unsigned char bufferCopy = buffer;
    
    if(debug) printf("[debug] randomInt = %d\nbuffer = %d\n\n", randomInt, buffer);
        
    if(GeneratePoc(id, inDeviceName, inIoctl, inIoctlDirection, inIoctlBufType, inIoctlName, buffer, sizeof(buffer)) < 0) printf("[-] Error: GeneratePoc() failed\n");
    
    int fd = OpenDevice(inDeviceName);
    if(fd < 0) printf("[-] Error: OpenDevice failed, fd = %d\n", fd);
    
    printf("[+] Sending data...\n\ndevice: %s\nioctl: %s (0x%x)\nbuffer: 0x%x\nbuffer type: %s\n\n", inDeviceName, inIoctlName, inIoctl, buffer, inIoctlBufType);
        
    if(ioctl(fd, inIoctl, &buffer) < 0) printf("[-] Error: ioctl() errno %d - %s\n\n", errno, strerror(errno));

    if((strcasestr(inIoctlDirection, "ior") || strcasestr(inIoctlDirection, "iowr")) && (buffer != bufferCopy))
    {
        printf("[%] Device returned: 0x%x\n\n", buffer);
    }
    
    close(fd);
    
    return 0;
}


int FuzzRandomSShort(uint id, char *inDeviceName, char *inIoctlName, uint inIoctl, char *inIoctlBufType, int inIoctlBufSize, char *inIoctlDirection)
{
    int randomInt = random(), fd;
    signed short buffer = (signed short)randomInt;
    signed short bufferCopy = buffer;
        
    if(GeneratePoc(id, inDeviceName, inIoctl, inIoctlDirection, inIoctlBufType, inIoctlName, buffer, sizeof(buffer)) < 0) printf("[-] Error: GeneratePoc() failed\n");
    
    if(fd = OpenDevice(inDeviceName) < 0) printf("[-] Error: OpenDevice failed, fd = %d\n", fd);
    
    printf("[+] Sending data...\n\ndevice: %s\nioctl: %s (0x%x)\nbuffer: 0x%x\nbuffer type: %s\n\n", inDeviceName, inIoctlName, inIoctl, buffer, inIoctlBufType);
        
    if(ioctl(fd, inIoctl, &buffer) < 0) printf("[-] Error: ioctl() errno %d - %s\n\n", errno, strerror(errno));

    if((strcasestr(inIoctlDirection, "ior") || strcasestr(inIoctlDirection, "iowr")) && (buffer != bufferCopy))
    {
        printf("[%] Device returned: 0x%x\n\n", buffer);
    }
    
    close(fd);
    
    return 0;
}


int FuzzRandomUShort(uint id, char *inDeviceName, char *inIoctlName, uint inIoctl, char *inIoctlBufType, int inIoctlBufSize, char *inIoctlDirection)
{
    int randomInt = random(), fd;
    unsigned short buffer = (unsigned short)randomInt;
    unsigned short bufferCopy = buffer;
        
    if(GeneratePoc(id, inDeviceName, inIoctl, inIoctlDirection, inIoctlBufType, inIoctlName, buffer, sizeof(buffer)) < 0) printf("[-] Error: GeneratePoc() failed\n");
    
    if(fd = OpenDevice(inDeviceName) < 0) printf("[-] Error: OpenDevice failed, fd = %d\n", fd);
    
    printf("[+] Sending data...\n\ndevice: %s\nioctl: %s (0x%x)\nbuffer: 0x%x\nbuffer type: %s\n\n", inDeviceName, inIoctlName, inIoctl, buffer, inIoctlBufType);
        
    if(ioctl(fd, inIoctl, &buffer) < 0) printf("[-] Error: ioctl() errno %d - %s\n\n", errno, strerror(errno));

    if((strcasestr(inIoctlDirection, "ior") || strcasestr(inIoctlDirection, "iowr")) && (buffer != bufferCopy))
    {
        printf("[%] Device returned: 0x%x\n\n", buffer);
    }
    
    close(fd);
    
    return 0;
}

int FuzzRandomSInt32(uint id, char *inDeviceName, char *inIoctlName, uint inIoctl, char *inIoctlBufType, int inIoctlBufSize, char *inIoctlDirection)
{
    int randomInt = random();
    int32_t buffer = (int32_t)randomInt;
    int32_t bufferCopy = buffer;
    
    if(debug) printf("[debug] randomInt = %d\nbuffer = %d\n\n", randomInt, buffer);
        
    if(GeneratePoc(id, inDeviceName, inIoctl, inIoctlDirection, inIoctlBufType, inIoctlName, buffer, sizeof(buffer)) < 0) printf("[-] Error: GeneratePoc() failed\n");
    
    int fd = OpenDevice(inDeviceName);
    if(fd < 0) printf("[-] Error: OpenDevice failed, fd = %d\n", fd);
    
    printf("[~] Sending data...\n\ndevice: %s\nioctl: %s (0x%x)\nbuffer: 0x%x\nbuffer type: %s\n\n", inDeviceName, inIoctlName, inIoctl, buffer, inIoctlBufType);
        
    if(ioctl(fd, inIoctl, &buffer) < 0) printf("[-] Error: ioctl() errno %d - %s\n\n", errno, strerror(errno));

    if((strcasestr(inIoctlDirection, "ior") || strcasestr(inIoctlDirection, "iowr")) && (buffer != bufferCopy))
    {
        printf("[%] Device returned: 0x%x\n\n", buffer);
    }
        
    close(fd);
    
    return 0;
}


int FuzzRandomUInt32(uint id, char *inDeviceName, char *inIoctlName, uint inIoctl, char *inIoctlBufType, int inIoctlBufSize, char *inIoctlDirection)
{
    int randomInt = random();
    uint32_t buffer = (uint32_t)randomInt;
    uint32_t bufferCopy = buffer;
    
    if(debug) printf("[debug] randomInt = %d\nbuffer = %d\n\n", randomInt, buffer);
        
    if(GeneratePoc(id, inDeviceName, inIoctl, inIoctlDirection, inIoctlBufType, inIoctlName, buffer, sizeof(buffer)) < 0) printf("[-] Error: GeneratePoc() failed\n");
    
    int fd = OpenDevice(inDeviceName);
    if(fd < 0) printf("[-] Error: OpenDevice failed, fd = %d\n", fd);
    
    printf("[+] Sending data...\n\ndevice: %s\nioctl: %s (0x%x)\nbuffer: 0x%x\nbuffer type: %s\n\n", inDeviceName, inIoctlName, inIoctl, buffer, inIoctlBufType);
        
    if(ioctl(fd, inIoctl, &buffer) < 0) printf("[-] Error: ioctl() errno %d - %s\n\n", errno, strerror(errno));

    if((strcasestr(inIoctlDirection, "ior") || strcasestr(inIoctlDirection, "iowr")) && (buffer != bufferCopy))
    {
        printf("[%] Device returned: 0x%x\n\n", buffer);
    }
    
    close(fd);
    
    return 0;
}


/*
 * Get a random seed for fuzzing
 * 
 */
unsigned int GetRandomSeed(void)
{
    int fd;
    uint seed;
    
    fd = open(RANDOM_SOURCE, O_RDONLY);
    
    if(fd < 0)
    {
        snprintf(errorMsg, sizeof(errorMsg), "\nError: open() for %s failed\n\n", RANDOM_SOURCE);
        Inception(errorMsg);
        return -1;
    }
    
    read(fd, &seed, sizeof(seed));
    
    close(fd);
    
    if(seed < 0)
    {
        snprintf(errorMsg, sizeof(errorMsg), "\nError: read() failed for random seed\n\n", RANDOM_SOURCE);
        Inception(errorMsg);
        return -1;
    }

    if(debug) printf("\nseed = %u\n\n");

    return seed;
}
