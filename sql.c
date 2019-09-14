/*
 * sql.c
 * 
 * Portmanteau
 * 
 * Database Operations 
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <openssl/sha.h>

#include "include/main.h"

#define SQL_CREATE_DEVICE "CREATE TABLE " DRIVER_IOCTL_TABLE "(device_name CHAR(50), ioctl_name CHAR(50), ioctl_macro CHAR(50) PRIMARY KEY, ioctl_buftype CHAR(50));"
#define SQL_INSERT_DEVICE "INSERT INTO " DRIVER_IOCTL_TABLE "(device_name, ioctl_name, ioctl_macro, ioctl_buftype) VALUES "
#define SQL_DELETE_DEVICE "DELETE FROM " DRIVER_IOCTL_TABLE " WHERE"
#define SQL_SELECT_ALL_DEVICES "SELECT * FROM " DRIVER_IOCTL_TABLE

#define SQL_SELECT_DEVICE         "SELECT device_name FROM " DRIVER_IOCTL_TABLE
#define SQL_SELECT_NAME_DEVICE    "SELECT ioctl_name FROM " DRIVER_IOCTL_TABLE
#define SQL_SELECT_IOCTL_DEVICE   "SELECT ioctl_macro FROM " DRIVER_IOCTL_TABLE
#define SQL_SELECT_BUFTYPE_DEVICE "SELECT ioctl_buftype FROM " DRIVER_IOCTL_TABLE

#define SQL_UPDATE_COLUMN_BEGIN "UPDATE " DRIVER_IOCTL_TABLE " SET "
#define SQL_UPDATE_COLUMN_END   "' WHERE "

//#define SQL_SELECT_CAPS_DRIVER    "SELECT caps FROM " DRIVER_IOCTL_TABLE


/*
 * Retrieves a buffer type for a given IOCTL macro
 * 
 */
char *SelectBufTypeByIoctl(char *inIoctlMacro)
{
    char sqlQuery[128];
    static char ioctlBufType[64]; // keep the variable valid/in-scope for caller
    sqlite3 *database;
    
    char *sqlErrorMsg = NULL;
    int ret, r, c;
    
    char **result = NULL;
    int numberRows = 0, numberColumns;
    
    struct timeval tv;
    time_t currentTime;
    
    gettimeofday(&tv, NULL);
    currentTime = tv.tv_sec;
    
    ret = sqlite3_open(DRIVER_IOCTL_DB, &database);
    
    if(ret != SQLITE_OK)
    {
        printf("Error: sqlite3_open() failed (%s)\n\n", sqlite3_errmsg(database));
        sqlite3_close(database);
        return NULL;
    }
    
    snprintf(sqlQuery, sizeof(sqlQuery), "SELECT ioctl_buftype FROM %s WHERE ioctl_macro = '%s'", DRIVER_IOCTL_TABLE, inIoctlMacro);
    
    if(debug) printf("sqlQuery = %s\n\n", sqlQuery);
    
    ret = sqlite3_get_table(database, sqlQuery, &result, &numberRows, &numberColumns, &sqlErrorMsg);
    
    if(ret != SQLITE_OK && !strstr(sqlErrorMsg, "no such table"))
    {
        printf("Error: sqlite3_exec() failed (%s) - %s\n\n", sqlQuery, sqlErrorMsg);
        sqlite3_free_table(result);
        sqlite3_close(database);
        return NULL;
    }
    
    else if(numberRows <= 0 && numberColumns <= 0)
    {
        sqlite3_free_table(result);
        sqlite3_close(database);
        snprintf(errorMsg, sizeof(errorMsg), "Error: could not find '%s' in database\n\n", inIoctlMacro);
        Inception(errorMsg);
        return NULL;
    }
    
    else
    {
        for(r = 1; r <= numberRows; r++)
        {
            int pos = (r * numberColumns);
            
            if(debug) printf("\nioctl_buftype = %s\n", result[pos]);
            
            snprintf(ioctlBufType, sizeof(ioctlBufType), "%s", result[pos]);
        }
    }
    
    sqlite3_free_table(result);
    sqlite3_close(database);
    
    return ioctlBufType;
}

/*
 * Selects a device and it's attributes from the database to begin fuzzing
 * 
 */
int SelectDeviceFromDatabaseToFuzz(char *inDeviceName, unsigned int iterations)
{
    char sqlQuery[128];
    sqlite3 *database;
    
    char *sqlErrorMsg = NULL;
    int ret, r, c;
    
    char **result = NULL;
    int numberRows = 0, numberColumns;
    
    struct timeval tv;
    time_t currentTime;
    
    gettimeofday(&tv, NULL);
    currentTime = tv.tv_sec;
    
    ret = sqlite3_open(DRIVER_IOCTL_DB, &database);
    
    if(ret != SQLITE_OK)
    {
        printf("Error: sqlite3_open() failed (%s)\n\n", sqlite3_errmsg(database));
        sqlite3_close(database);
        return -1;
    }
    
    snprintf(sqlQuery, sizeof(sqlQuery), "SELECT * FROM %s WHERE device_name = '%s'", DRIVER_IOCTL_TABLE, inDeviceName);
    
    if(debug) printf("sqlQuery = %s\n\n", sqlQuery);
    
    ret = sqlite3_get_table(database, sqlQuery, &result, &numberRows, &numberColumns, &sqlErrorMsg);
    
    if(ret != SQLITE_OK &&!strstr(sqlErrorMsg, "no such table"))
    {
        printf("Error: sqlite3_exec() failed (%s) - %s\n\n", sqlQuery, sqlErrorMsg);
        sqlite3_free_table(result);
        sqlite3_close(database);
        return -1;
    }
    
    else if(numberRows <= 0 && numberColumns <= 0)
    {
        sqlite3_free_table(result);
        sqlite3_close(database);
        snprintf(errorMsg, sizeof(errorMsg), "Error: could not find '%s' in database\n\n", inDeviceName);
        Inception(errorMsg);
        return -1;
    }
    
    else
    {
        printf("Database has %d ioctls for '%s'\n\n", numberRows, inDeviceName);
        
        //
        // skip over the row name
        //
        //for(r = 8; r < 9; r++) // TUNGETFEATURES (unsigned int)
        //for(r = 12; r < 13; r++) // TUNGETSNDBUF (int)
        //for(r = 16; r < 17; r++) // TUNGETVNETHDRSZ (int)
        for(r = 1; r <= numberRows; r++)
        {
            int pos = (r * numberColumns);
            
            ParseIoctlMacroFromDatabase(inDeviceName, iterations, result[pos+1], result[pos+2]);
        }
    }
    
    sqlite3_free_table(result);
    sqlite3_close(database);
    
    return 0;
}

/*
 * Takes a given driver signature and adds it to the database
 * 
 * Format: [todo]
 * 
 */
int AddDeviceToDatabase(char *inSignature)
{
    sqlite3 *database;
    char sql_insert_ds[256];
    char *sqlErrorMsg = NULL;
    int i, ret;
    
    unsigned char hash[SHA_DIGEST_LENGTH];
    char deviceNameHash[SHA_DIGEST_LENGTH * 2 + 1];
    
    char deviceName[64], ioctlName[64], ioctl[128], ioctlBufType[32];
    
    char *token = strtok(inSignature, DELIMITER);
    
    while(token != NULL)
    {
        strncpy(deviceName, token, sizeof(deviceName)-1);
        
        token = strtok(NULL, DELIMITER);
        if(token != NULL) strncpy(ioctlName, token, sizeof(ioctlName)-1);
        
        token = strtok(NULL, DELIMITER);
        //if(token != NULL) ioctl = (unsigned int)strtol(token, NULL, 0); // in: 0x40001234, out: unsigned int
        if(token != NULL) strncpy(ioctl, token, sizeof(ioctl)-1);
        
        token = strtok(NULL, DELIMITER);
        if(token != NULL) strncpy(ioctlBufType, token, sizeof(ioctlBufType)-1);
        
        //token = strtok(NULL, DELIMITER);
        //if(token != NULL) strncpy(caps, token, sizeof(caps)-1);
        
        break;
    }
    
    //
    // SHA1 hashing for more 'friendly' initial device_names upon import
    //
    // Note: we only use the first 10 bytes (for security purposes of course.. ;)
    //
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, deviceName, sizeof(deviceName));
    SHA1_Final(hash, &ctx);
    
    for(i = 0; i < (10 / 2); i++)
    {
        sprintf(&deviceNameHash[i*2], "%02X", (unsigned int)hash[i]);
    }
    
    memset(deviceName, 0, sizeof(deviceName));
    strncpy(deviceName, deviceNameHash, sizeof(deviceNameHash));
    
    if(debug) printf("device = %s\nname = %s\nioctl = 0x%x\nbufType = %s\n\n", deviceName, ioctlName, ioctl, ioctlBufType);
    
    ret = sqlite3_open(DRIVER_IOCTL_DB, &database);
    
    if(ret != SQLITE_OK)
    {
        printf("Error: sqlite3_open() failed (%s)\n\n", sqlite3_errmsg(database));
        sqlite3_close(database);
        return -1;
    }
    
    printf("Adding found ioctl \"%s\" to the database...\n", ioctlName);
    
    snprintf(sql_insert_ds, sizeof(sql_insert_ds), "%s('%s', '%s', '%s', '%s');", SQL_INSERT_DEVICE, deviceName, ioctlName, ioctl, ioctlBufType);
    
    ret = sqlite3_exec(database, sql_insert_ds, NULL, 0, &sqlErrorMsg);
    
    if(ret != SQLITE_OK)
    {
        if(strstr(sqlErrorMsg, "no such table"))
        {
            printf("\nJust a sec, %s must be created first\n\nTrying to create the database for you..\n\n", DRIVER_IOCTL_TABLE);
            
            ret = CreateDriverSignatures(database);
            
            if(ret == 0) 
            {
                printf("Database created! Re-run your command and it should work now.\n\n");
                return -1;
            }
            else
            {
                printf("Database creation failed.\n\n");
                return -1;
            }
            
            return -1;
        }
        
        else if(strstr(sqlErrorMsg, "column ioctl_macro is not unique"))
        {
            printf("\nNote: ioctl was already in the database\n\n");
            sqlite3_close(database);
            
            //return -1;
        }
        
        else
        {
            printf("Error: sqlite3_exec() failed for \"%s\" - %s\n\n", sql_insert_ds, sqlErrorMsg);
            sqlite3_close(database);
            return -1;
        }
    }
    
    sqlite3_close(database);
    
    return 0;
}

/*
 * Deletes a device from the database
 * 
 */
int DeleteDeviceInDatabase(char *inSignature)
{
    sqlite3 *database;
    
    char sql_delete_ds[256];
    char *sqlErrorMsg = NULL;
    int ret;
    
    char deviceName[64], ioctlName[64];
    
    char *token = strtok(inSignature, DELIMITER);
    
    while(token != NULL)
    {
        strncpy(deviceName, token, sizeof(deviceName)-1);
        
        token = strtok(NULL, DELIMITER);
        if(token != NULL) strncpy(ioctlName, token, sizeof(ioctlName)-1);
        
        break;
    }
    
    if(debug) printf("device = %s\nname = %s\n\n\n", deviceName, ioctlName);
    
    ret = sqlite3_open(DRIVER_IOCTL_DB, &database);
    
    if(ret != SQLITE_OK)
    {
        printf("Error: sqlite3_open() failed (%s)\n\n", sqlite3_errmsg(database));
        sqlite3_close(database);
        return -1;
    }
    
    printf("\nDeleting ioctl from the database, \"%s\"...\n", ioctlName);
    
    snprintf(sql_delete_ds, sizeof(sql_delete_ds), "%s device_name='%s' AND ioctl_name='%s';", SQL_DELETE_DEVICE, deviceName, ioctlName);
    
    ret = sqlite3_exec(database, sql_delete_ds, NULL, 0, &sqlErrorMsg);
    
    if(ret != SQLITE_OK)
    {
        printf("Error: sqlite3_exec() failed for \"%s\" - %s\n\n", sql_delete_ds, sqlErrorMsg);
        sqlite3_close(database);
        return -1;
    }
    
    sqlite3_close(database);
    
    printf("Done!\n\n");
    
    return 0;
}

/*
 * Creates the db table
 * 
 */
int CreateDriverSignatures(sqlite3 *inDatabase)
{
    char *sqlErrorMsg = NULL;
    int ret;
    
    ret = sqlite3_exec(inDatabase, SQL_CREATE_DEVICE, NULL, 0, &sqlErrorMsg);
            
    if(ret != SQLITE_OK)
    {
        printf("Error: sqlite3_exec() failed (%s) - %s\n\n", SQL_CREATE_DEVICE, sqlErrorMsg);
        return -1;
    }
    
    return 0;
}

/*
 * Update a column in the sqlite database file
 * 
 * Parses data in this format: "column:oldData:newData"
 * eg. driver:name12345:name
 * 
 */
int UpdateColumnInDatabase(char *inData)
{
    sqlite3 *database;
    
    char sql_rename_ds[256], sql_exists_ds[256];
    char column[64], oldData[256], newData[256];
    char *sqlErrorMsg = NULL;
    int ret;
    
    char **result = NULL;
    int numberRows = 0, numberColumns;
    
    if(CheckStringForReqChars(':', 2, inData) < 0) return -1;
    
    char *token = strtok(inData, DELIMITER);
    
    while(token != NULL)
    {
        strncpy(column, token, sizeof(column)-1);
        
        token = strtok(NULL, DELIMITER);
        if(token != NULL) strncpy(oldData, token, sizeof(oldData)-1);
        
        token = strtok(NULL, DELIMITER);
        if(token != NULL) strncpy(newData, token, sizeof(newData)-1);
        
        break;
    }
    
    ret = sqlite3_open(DRIVER_IOCTL_DB, &database);
    
    if(ret != SQLITE_OK)
    {
        printf("Error: sqlite3_open() failed (%s)\n\n", sqlite3_errmsg(database));
        sqlite3_close(database);
        return -1;
    }
    
    //
    // check if column oldData exists in db first
    //
    snprintf(sql_exists_ds, sizeof(sql_exists_ds), "%s WHERE %s LIKE '%s'", SQL_SELECT_DEVICE, column, oldData);
    if(debug) printf("\nsql_exists_ds = %s\n", sql_exists_ds);
    
    ret = sqlite3_get_table(database, sql_exists_ds, &result, &numberRows, &numberColumns, &sqlErrorMsg);
    
    if(ret != SQLITE_OK)
    {
        printf("Error: sqlite3_exec() failed - %s\n\n", sqlErrorMsg);
        sqlite3_close(database);
        return -1;
    }
    
    if(numberRows > 0)
    {
        printf("Updating %s '%s' to '%s'...\n\n", column, oldData, newData);
    
        snprintf(sql_rename_ds, sizeof(sql_rename_ds), "%s%s='%s%s%s='%s'", SQL_UPDATE_COLUMN_BEGIN, column, newData, SQL_UPDATE_COLUMN_END, column, oldData);
        
        ret = sqlite3_exec(database, sql_rename_ds, NULL, 0, &sqlErrorMsg);
        
        if(ret != SQLITE_OK)
        {
            printf("Error: sqlite3_exec() failed - %s\n\n", sqlErrorMsg);
            sqlite3_close(database);
            return -1;
        }
    }
    
    else
    {
        snprintf(errorMsg, sizeof(errorMsg), "Error: %s '%s' does not exist\n\n", column, oldData);
        Inception(errorMsg);
        return -1;
    }
    
    printf("Done!\n\n");

    sqlite3_close(database);
    
    return 0;
}

int PrintDriverSignatures(void)
{
    sqlite3 *database;
    
    char *sqlErrorMsg = NULL;
    int ret, r, c;
    
    char **result = NULL;
    int numberRows = 0, numberColumns;
    
    ret = sqlite3_open(DRIVER_IOCTL_DB, &database);
    
    if(ret != SQLITE_OK)
    {
        printf("Error: sqlite3_open() failed (%s)\n\n", sqlite3_errmsg(database));
        sqlite3_close(database);
        return -1;
    }
    
    ret = sqlite3_get_table(database, SQL_SELECT_ALL_DEVICES, &result, &numberRows, &numberColumns, &sqlErrorMsg);
    
    if(ret != SQLITE_OK)
    {
        if(!strstr(sqlErrorMsg, "no such table"))
        {
            printf("Error: sqlite3_exec() failed (%s) - %s\n\n", SQL_SELECT_ALL_DEVICES, sqlErrorMsg);
            sqlite3_free_table(result);
            sqlite3_close(database);
            return -1;
        }
        
        else
        {
            //
            // nonchalantly create a db
            //
            CreateDriverSignatures(database);
        }
    }
    
    //
    // these should not be less than zero, but why not :-)
    //
    if(numberRows <= 0 && numberColumns <= 0)
    {
        printf("No driver signatures: Use -i to import IOCTLs from a header file\n\n");
    }
    
    else
    {
        printf("device_name\t\tioctl_name\t\tioctl_macro\n");
        printf("-----------\t\t----------\t\t-----------\n");
        
        //
        // skip over the row name
        //
        for(r = 1; r <= numberRows; r++)
        {
            int pos = (r * numberColumns);
            
            printf("%s\t\t%s\t\t%s\n", result[pos], result[pos+1], result[pos+2]);
        }
        
        printf("\nIoctls: %d\n\n", numberRows);
    }
    
    sqlite3_free_table(result);
    sqlite3_close(database);
    
    return 0;
}
