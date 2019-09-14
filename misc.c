/*
 * misc.c
 * 
 * Portmanteau
 * 
 * Misc functions 
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stddef.h>

#include "include/main.h"


void PrintPmtOptions(void)
{
    printf("General>\n");
    printf("[-D device]    - Set device path\n"
           "                 Eg. -D /dev/net/tun\n\n");
    printf("[-N n]         - Set number of iterations (default: 100)\n"
           "                 Eg. -N 100000\n\n");
    printf("[-z]           - Start a fuzzing run (typed-based random generation)\n\n");
    
    //
    // these are simple routines for manipulating the database
    //
    // you'll need to open the drsig.db file with a sqlite3 client for more granular operations
    //
    printf("Database>\n");
    printf("[-i file]      - Import IOCTL definitions from a single file\n"
           "                 Eg. -i /path/to/driver_ioctls.h\n\n");
    printf("[-a signature] - Add a new device signature to the database (manual)\n"
           "                 Eg. -a \"/dev/net/nsa:SNIFF_ENTIRE_INTERNET:0xdeadb33f:uint\"\n\n");
    printf("[-d signature] - Delete a device signature from the database\n"
           "                 Eg. -d \"/dev/net/boring:IOCTL_EAT_CAKE\"\n\n");
    printf("[-u entry]     - Update all columns in the database\n"
           "                 Eg. -u \"device_name:/some/long/import/path.h:/dev/pwn\"\n\n");
    
    printf("Utility>\n");
    printf("[-c]           - Interactively convert an IOCTL definition to an integer\n\n");
    printf("[-f]           - Brute force ioctls for a given device (testing only)\n"
           "                 Eg. -D /dev/net/tun -f\n\n");
    
}

int PrintHelp(char *inBin)
{
    int i, ret = 0;
    
    printf("Usage: %s [-O for options]\n\n", inBin);
    
    printf("Driver Signatures\n\n");
    
    ret = PrintDriverSignatures();
    
    if(ret < 0)
    {
        printf("\nError: printDriverSignatures() failed\n\n");
        return -1;
    }
    
    return 0;
}

/*
 * Dicaprio errors
 * 
 */
void Inception(char *inErrorMsg)
{
    printf("%s", inErrorMsg);
}

/*
 * Interactively convert values from IOCTL definitions to a uint
 * 
 */
int ConvertDefineToIoctl()
{
    char *token = NULL;
    char ioctlDirection[64], ioctlMagic;
    uint ioctlNumber, ioctlBufSize; // BufSize = sizeof(BufType)
    
    uint ioctl = 0;
    
    printf("Direction: ");
    scanf(" %64s", ioctlDirection);
    
    printf("Magic: ");
    scanf(" %c", &ioctlMagic);
    
    printf("Number: ");
    scanf(" %u", &ioctlNumber);
    
    printf("Size: ");
    scanf(" %d", &ioctlBufSize);
    
    if(debug) printf("\n\nioctlDirection = %s\nioctlMagic = %c\nioctlNumber = %d\nioctlBufSize = %d\n", ioctlDirection, ioctlMagic, ioctlNumber, ioctlBufSize);
    
    if(strcasecmp(ioctlDirection, "ior") == 0)
    {
        ioctl = _IOC(_IOC_READ, ioctlMagic, ioctlNumber, ioctlBufSize);
    }
    
    if(strcasecmp(ioctlDirection, "iow") == 0)
    {
        ioctl = _IOC(_IOC_WRITE, ioctlMagic, ioctlNumber, ioctlBufSize);
    }
    
    if(strcasecmp(ioctlDirection, "iowr") == 0)
    {
        ioctl = _IOC(_IOC_READ|_IOC_WRITE, ioctlMagic, ioctlNumber, ioctlBufSize);
    }
    
    printf("\nioctl -> 0x%x (%u)\n\n", ioctl, ioctl);
    
    return ioctl;
}

/*
 * Non-Interactively convert values from IOCTL definitions to a uint
 * 
 */
int ConvertDefineToIoctlInternal(char *inIoctlDirection, char inIoctlMagic, unsigned int inIoctlNumber, unsigned int inIoctlBufSize)
{
    unsigned int ioctl = 0;
    
    if(debug) printf("\n\nioctlDirection = %s\nioctlMagic = %c\nioctlNumber = %d\nioctlBufSize = %d\n", inIoctlDirection, inIoctlMagic, inIoctlNumber, inIoctlBufSize);
    
    if(strcasestr(inIoctlDirection, "ior"))
    {
        ioctl = _IOC(_IOC_READ, inIoctlMagic, inIoctlNumber, inIoctlBufSize);
    }
    
    if(strcasestr(inIoctlDirection, "iow"))
    {
        ioctl = _IOC(_IOC_WRITE, inIoctlMagic, inIoctlNumber, inIoctlBufSize);
    }
    
    if(strcasestr(inIoctlDirection, "iowr"))
    {
        ioctl = _IOC(_IOC_READ|_IOC_WRITE, inIoctlMagic, inIoctlNumber, inIoctlBufSize);
    }
    
    if(debug) printf("\nioctl -> 0x%x (%u)\n\n", ioctl, ioctl);
    
    return ioctl;
}


/*
 * Parse an Ioctl Macro to calculate the exact ioctl number (eg. for fuzzing)
 * 
 * This code is not the easiest on the eyes, but it gets the job done..
 * 
 */
int ParseIoctlMacroFromDatabase(char *inDeviceName, unsigned int iterations, char *inIoctlName, char *inIoctlMacro)
{
    char ioctlMacro[512];
    char ioctlDirection[16], ioctlMagic[16], ioctlNumber[16], ioctlBufType[32];
    char *token = NULL;
    
    memset(ioctlMacro, 0, sizeof(ioctlMacro));
    snprintf(ioctlMacro, sizeof(ioctlMacro), "%s", inIoctlMacro);
    
    if(debug) printf("\ninIoctlMacro -> %s\n\n", &ioctlMacro);
    
    //
    // get buftype (and later bufsize)
    //
    snprintf(ioctlBufType, sizeof(ioctlBufType), "%s", SelectBufTypeByIoctl(ioctlMacro));
    
    //
    // get direction
    //
    token = strtok(ioctlMacro, "(");
    
    if(token != NULL)
    {
        snprintf(ioctlDirection, sizeof(ioctlDirection), "%s", token);
    }
    else snprintf(ioctlDirection, sizeof(ioctlDirection), NOT_FOUND, token);
    
    snprintf(ioctlMacro, sizeof(ioctlMacro), "%s", inIoctlMacro);
    
    //
    // get magic
    //
    token = strtok(ioctlMacro, "(");
    
    if(token != NULL)
    {
        token = strtok(NULL, ",");
        
        snprintf(ioctlMagic, sizeof(ioctlMagic), "%s", token);
    }
    else snprintf(ioctlMagic, sizeof(ioctlMagic), NOT_FOUND, token);
    
    snprintf(ioctlMacro, sizeof(ioctlMacro), "%s", inIoctlMacro);
    
    //
    // get number
    //
    token = strtok(ioctlMacro, ",");
    
    if(token != NULL)
    {
        token = strtok(NULL, ",");
        
        snprintf(ioctlNumber, sizeof(ioctlNumber), "%s", token);
    }
    else snprintf(ioctlNumber, sizeof(ioctlNumber), NOT_FOUND, token);
    
    snprintf(ioctlMacro, sizeof(ioctlMacro), "%s", inIoctlMacro);
    
    char ioctlMagicFinal = (char)ioctlMagic[0];
    int ioctlNumberFinal = atoi(ioctlNumber);
    
    if(debug)
    {
        printf("Direction: %s\n", ioctlDirection);
        printf("Magic: %c\n", ioctlMagicFinal);
        printf("Number: %d\n", ioctlNumberFinal);
        printf("BufType: %s\n\n", ioctlBufType);
    }
    
    //
    // get buffer size based on it's type
    //
    int ioctlBufSize = MapBufTypeToBufSize(ioctlBufType);
    
    if(debug) printf("BufSize: %d\n\n", ioctlBufSize);
    
    unsigned int ioctl = ConvertDefineToIoctlInternal(ioctlDirection, ioctlMagicFinal, ioctlNumberFinal, ioctlBufSize);
    
    printf("Fuzzing %s --> 0x%x\n", inIoctlName, ioctl);
    
    srandom(GetRandomSeed());
    
    int ret = FuzzRandom(inDeviceName, iterations, inIoctlName, ioctl, ioctlBufType, ioctlBufSize, ioctlDirection);
    
    // intentionally not checking the return value here
    
    return 0;
}

/*
 * Map each given buffer type (string) to a size
 * 
 * 32-bit only support was intentional -- more work needed for multi-platform support
 * 
 */
int MapBufTypeToBufSize(char *inIoctlBufType)
{
    int ioctlBufSize;

    if(strcasestr(inIoctlBufType, "char"))            ioctlBufSize = 1;
    else if(strcasestr(inIoctlBufType, "short"))      ioctlBufSize = 2;
    else if(strcasestr(inIoctlBufType, "int"))        ioctlBufSize = 4;
    else if(strcasestr(inIoctlBufType, "size_t"))     ioctlBufSize = 4;
    else if(strcasestr(inIoctlBufType, "sock_fprog")) ioctlBufSize = 6;
    
    else ioctlBufSize = 4; // so you're saying there's a chance..
    
    return ioctlBufSize;
}


/*
 * Compare each character of the string to the required number of chars
 * 
 */
int CheckStringForReqChars(char inChar, int inNumber, char *inString)
{
    int i, count = 0;
    
    if(debug) printf("inString = %s\n", inString);
    
    for(i = 0; i < strlen(inString); i++)
    {
        if(inString[i] == inChar)
        {
            count++;
        }
    }
    
    if(count != inNumber)
    {
        if(debug) printf("inString[i] = %c\n", inString[i]);
        snprintf(errorMsg, sizeof(errorMsg), "\nError: CheckStringForReqChars() failed for '%s'\n\n", inString);
        Inception(errorMsg);
        return -1;
    }
    
    return 0;
}
