/*
 * device.c
 * 
 * Portmanteau
 * 
 * Device-related functions 
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>

#include "include/main.h"


/*
 * Open a device and return a handle
 * 
 */
int OpenDevice(char *inDeviceName)
{
    //
    // "maximum allowed" cascading conditional
    //
    int fd = open(inDeviceName, O_RDWR);
    
    if(fd >= 0) printf("[+] Opened %s as O_RDWR\n", inDeviceName);
    
    if(fd < 0)
    {
        printf("[%] Could not open '%s' as O_RDWR, trying O_WRONLY\n", inDeviceName);
        
        fd = open(inDeviceName, O_WRONLY);
        
        if(fd >= 0) printf("[+] Opened %s as O_WRONLY\n", inDeviceName);
        
        else if(fd < 0)
        {
            printf("[%] Could not open '%s' as O_WRONLY, trying O_RDONLY\n", inDeviceName);
            
            fd = open(inDeviceName, O_RDONLY);
            
            if(fd >= 0) printf("[+] Opened %s as O_RDONLY\n", inDeviceName);
            
            else if(fd < 0)
            {
                perror("open");
                snprintf(errorMsg, sizeof(errorMsg)-1, "\n[-] Error: cannot open device %s\n\n", inDeviceName);
                Inception(errorMsg);
                return -1;
            }
        }
    }
    
    if(debug) printf("opened device: %s\n\n", inDeviceName);
    
    return fd;
}

/*
 * IOCTL brute force -- obviously not the most accurate approach
 * 
 */
int FindIoctlsForDevice(char *inDeviceName)
{
    char *argp;
    int count = 0, endCount = UINT32_MAX;
    unsigned int code;
    time_t currentTime, pastTime;
    
    if(inDeviceName == NULL)
    {
        snprintf(errorMsg, sizeof(errorMsg)-1, "\nError: device name cannot be null\n\n");
        Inception(errorMsg);
        return -1;
    }
    
    if(debug) printf("inDeviceName = %s\n", inDeviceName);
    
    int fd = OpenDevice(inDeviceName);
    
    if(fd < 0) return -1;
    
    //
    // similar to the way ioctlbf does it: https://code.google.com/p/ioctlbf/
    //
    for(code = 0; code < endCount; code++)
    //for(code = 0x40000000; code < endCount; code++)
    {
        int ret = ioctl(fd, code, &argp);
        
        //
        // success returns either 0 or driver may also return positive output buffer size
        //
        if(ret >= 0)
        {
            count++;
            printf("found ioctl: 0x%x\n", code);
        }
        
        //
        // this could be interesting, but not 100% th
        //
        //else if(ret < 0 && errno != EINVAL)
        //{
            //count++;
            //printf("[might have] found ioctl: 0x%x (errno %d)\n", code, ret);
        //}
    }
    
    printf("\nioctl count: %d\n\n", count);
    
    close(fd);
    
    return 0;
}
