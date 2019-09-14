/*
 * main.c
 * 
 * Portmanteau
 *
 * Main Switchboard 
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "include/main.h"


int main(int argc, char *argv[])
{
    char *deviceName = NULL, opt;
    int ret = 0;
    unsigned int iterations = 100;
    uint ioctl = 0;
    
    printf("\n[%s] %s\n\n", NAME, VERSION);
    
    while((opt = getopt(argc, argv, "OD:N:a:i:s:u:d:cfz")) != EOF)
    {
        switch(opt)
        {
            case 'O':
                PrintPmtOptions();
                break;
            
            case 'D':
                deviceName = optarg;
                break;
            
            case 'a':
                ret = AddDeviceToDatabase(optarg);
                break;
            
            case 'd':
                ret = DeleteDeviceInDatabase(optarg);
                break;
            
            case 'c':
                ret = ConvertDefineToIoctl();
                break;
            
            case 'N':
                iterations = atoi(optarg);
                break;
            
            case 'z':
                ret = SelectDeviceFromDatabaseToFuzz(deviceName, iterations);
                break;
            
            case 'f':
                ret = FindIoctlsForDevice(deviceName);
                break;
            
            case 'i':
                ret = ImportUnixIoctlsFromFile(optarg);
                break;

            case 'u':
                ret = UpdateColumnInDatabase(optarg);
                break;
            
            default:
                snprintf(errorMsg, sizeof(errorMsg), "\nError: Invalid arguments\n\n");
                Inception(errorMsg);
                break;
        }
        
    }
    
    if(argc < 2)
    {
        PrintHelp(argv[0]);
        return 0;
    }
    
    if(ret < 0)
    {
        snprintf(errorMsg, sizeof(errorMsg), "Portmanteau returned %d, error occured\n\n", ret);
        Inception(errorMsg);
        return -1;
    }
    
    return 0;
}
