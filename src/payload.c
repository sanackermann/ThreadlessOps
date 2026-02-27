#include <windows.h>
#include "common/tcg.h"

// WinAPI import declarations (resolved by the loader / custom resolver)
DECLSPEC_IMPORT int    WINAPI USER32$MessageBoxW ( HWND, LPCWSTR, LPCWSTR, UINT );
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep     ( DWORD );

/*
 * Minimal position-independent payload that displays a MessageBox
 */
void go() {

    // Optional delay to prevent potential re-entrancy issues when a WDAC UI dialog is active
	KERNEL32$Sleep( 200 );

    // Show MessageBox
	USER32$MessageBoxW(
        NULL,
        L"Hello from Payload",
        L"Demo",
        MB_OK | MB_ICONINFORMATION
    );
    
}
