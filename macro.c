/*
 * macro.c
 * 
 * Portmanteau
 * 
 * Macro Parser
 * 
 * -------
 * Support
 * -------
 * 
 * #define _IOR(type,nr,size)      _IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
 * 
 * #define _IOW(type,nr,size)      _IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
 * 
 * #define _IOWR(type,nr,size)     _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
 * 
 * ----------
 * No Support
 * ----------
 * 
 * #define _IOC(dir,type,nr,size) \
 *          (((dir)  << _IOC_DIRSHIFT) | \
 *           ((type) << _IOC_TYPESHIFT) | \
 *           ((nr)   << _IOC_NRSHIFT) | \
 *           ((size) << _IOC_SIZESHIFT))
 * 
 * -----------
 * Quick Stats
 * -----------
 * 
 * /usr/src/linux-source-3.2$ grep -R "_IOR(" * | wc -l
 * 756
 * 
 * /usr/src/linux-source-3.2$ grep -R "_IOW(" * | wc -l
 * 1058
 *
 * /usr/src/linux-source-3.2$ grep -R "_IOWR(" * | wc -l
 * 658
 * 
 * /usr/src/linux-source-3.2$ grep -R "_IOC(" * | wc -l
 * 152 
 * 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <regex.h>

#include "include/ioctl.h"

#include "include/main.h"

/*
 * Helper function to 'clean' IOCTL macro data before import
 * 
 */
char *CleanMacro(char *inString)
{
    char *newString = inString;
    int i, j;
    
    if(inString == NULL) return NOT_FOUND;
    
    if(debug) printf("\ninString = %s\n\n", inString);
    
    for(i = 0, j = 0; i < strlen(newString); i++, j++)
    {
        if(!isspace(inString[i]) && inString[i] != '(' && inString[i] != ')' && inString[i] != '\'' && inString[i] != '*')
        {
            newString[j] = inString[i];
        }
        else j--;
    }
    
    //
    // remove "struct" (6 characters) from bufType
    //
    if(strstr(newString, "struct"))
    {
        newString += 6;
        newString[j-6] = '\0';
    }
    else newString[j] = '\0';
    
    return newString;
}

/*
 * Get* Helper Functions for importing IOCTL macro data
 * 
 */
 
char *GetUnixIoctlName(char *inString)
{
    char *token = NULL;
    
    token = strtok(inString, " ");
    
    if(token != NULL)
    {
        token = strtok(NULL, " \t");
        
        if(debug) printf("name token = %s\n", token);
        return CleanMacro(token);
    }
    
    return token;
}


char *GetUnixIoctlDirection(char *inString)
{
    char *token = NULL;
    
    if(debug) printf("inString = %s\n\n", inString);
    
    token = strtok(inString, " ");
    
    if(token != NULL)
    {
        token = strtok(NULL, " \t");
        token = strtok(NULL, "(");
        
        if(debug) printf("direction token = %s\n", token);
        return CleanMacro(token);
    }
    
    return token;
}


char *GetUnixIoctlMagic(char *inString)
{
    char *token = NULL;
    
    token = strtok(inString, " ");
    
    if(token != NULL)
    {
        token = strtok(NULL, " \t");
        token = strtok(NULL, "(");
        token = strtok(NULL, ",");
        
        if(debug) printf("magic token = %s\n", token);
        return CleanMacro(token);
    }
    
    return token;
}


char *GetUnixIoctlNumber(char *inString)
{
    char *token = NULL;
    
    token = strtok(inString, " ");
    
    if(token != NULL)
    {
        token = strtok(NULL, " \t");
        token = strtok(NULL, "(");
        token = strtok(NULL, ",");
        token = strtok(NULL, ",");
        
        if(debug) printf("number token = %s\n", token);
        return CleanMacro(token);
    }
    
    return token;
}


char *GetUnixIoctlBufType(char *inString)
{
    char *token = NULL;
    
    token = strtok(inString, " ");
    
    if(token != NULL)
    {
        token = strtok(NULL, " \t");
        token = strtok(NULL, "(");
        token = strtok(NULL, ",");
        token = strtok(NULL, ",");
        token = strtok(NULL, ")");
        
        if(debug) printf("buftype token = %s\n", token);
        return CleanMacro(token);
    }
    
    return token;
}


/*
 * Read file streams and import found IOCTLs
 * 
 * input <-
 *              #define MGSL_IOCSPARAMS32 _IOW(MGSL_MAGIC_IOC,0,struct MGSL_PARAMS32)
 *
 * output ->
 *              name: MGSL_IOCSPARAMS32
 *              direction: _IOW
 *              magic: MGSL_MAGIC_IOC
 *              number: 0
 *              bufType: MGSL_PARAMS32
 * 
 */
int ImportUnixIoctlsFromFile(char *inFile)
{
    //
    // don't treat these as their primitive types as the macros could contain #defines
    //
    char ioctlName[64], ioctlDirection[64], ioctlMagic[64], ioctlNumber[64], ioctlBufType[64];
    char signature[256], *driverCaps;
    
    char line[256], line_temp[256], *token;
    FILE *fd;
    int ret, regRet;
    
    regex_t regex;
    
    fd = fopen(inFile, "r");
    
    if(!fd)
    {
        snprintf(errorMsg, sizeof(errorMsg), "\nError: could not open file: %s\n\n", inFile);
        Inception(errorMsg);
        return -1;
    } 
    
    while(fgets(line, sizeof(line), fd))
    {
        //
        // We're looking for _IOR, _IOW or _IOWR
        //
        regRet = regcomp(&regex, IOCTL_REGEX, 0);
        
        if(regRet)
        {
            //regerror(regret, &regex, errorMsg, sizeof(errorMsg)-1);
            snprintf(errorMsg, sizeof(errorMsg), "\nError: could not compile regex: %s\n\n", IOCTL_REGEX);
            Inception(errorMsg);
            return -1;
        }
        
        regRet = regexec(&regex, line, 0, NULL, 0);
        
        if(debug) printf("line = %s\n", line);
        
        if(regRet != REG_NOMATCH)
        {
            strncpy(line_temp, line, sizeof(line_temp)-1);
            snprintf(ioctlName, sizeof(ioctlName), "%s", GetUnixIoctlName(line_temp));
            
            strncpy(line_temp, line, sizeof(line_temp)-1);
            snprintf(ioctlDirection, sizeof(ioctlDirection), "%s", GetUnixIoctlDirection(line_temp));
            
            strncpy(line_temp, line, sizeof(line_temp)-1);
            snprintf(ioctlMagic, sizeof(ioctlMagic), "%s", GetUnixIoctlMagic(line_temp));
            
            strncpy(line_temp, line, sizeof(line_temp)-1);
            snprintf(ioctlNumber, sizeof(ioctlNumber), "%s", GetUnixIoctlNumber(line_temp));
            
            strncpy(line_temp, line, sizeof(line_temp)-1);
            snprintf(ioctlBufType, sizeof(ioctlBufType), "%s", GetUnixIoctlBufType(line_temp));
            
            //
            // covert known unsigned* to u* for better formatting on display
            //
            if(strcasestr(ioctlBufType, "unsignedchar")) strncpy(ioctlBufType, "uchar", sizeof(ioctlBufType)-1);
            if(strcasestr(ioctlBufType, "unsignedshort")) strncpy(ioctlBufType, "ushort", sizeof(ioctlBufType)-1);
            if(strcasestr(ioctlBufType, "unsignedint")) strncpy(ioctlBufType, "uint", sizeof(ioctlBufType)-1);
            
            snprintf(signature, sizeof(signature), "%s:%s:%s(%s,%s,%s):%s", inFile, ioctlName, ioctlDirection, ioctlMagic, ioctlNumber, ioctlBufType, ioctlBufType);
            
            ret = AddDeviceToDatabase(signature);
            
            if(ret < 0)
            {
                regfree(&regex);
                return ret;
            }
        }
    }
    
    printf("\nDone!\n");
    
    regfree(&regex);
    
    fclose(fd);
    
    return 0;
}
