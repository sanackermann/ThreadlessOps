#include <windows.h>
#include <wininet.h>
#include <combaseapi.h>
#include "tcg.h"
#include "spoof.h"

DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$CreateThread       ( LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD );
// DECLSPEC_IMPORT int       WINAPI USER32$MessageBoxW          ( HWND, LPCWSTR, LPCWSTR, UINT );
// DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$CloseHandle        ( HANDLE );

HANDLE WINAPI _CreateThread ( LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$CreateThread );
    call.argc = 6;
    
    call.args [ 0 ] = spoof_arg ( lpThreadAttributes );
    call.args [ 1 ] = spoof_arg ( dwStackSize );
    call.args [ 2 ] = spoof_arg ( lpStartAddress );
    call.args [ 3 ] = spoof_arg ( lpParameter );
    call.args [ 4 ] = spoof_arg ( dwCreationFlags );
    call.args [ 5 ] = spoof_arg ( lpThreadId );

    return ( HANDLE ) spoof_call ( &call );
}

// BOOL WINAPI _CloseHandle ( HANDLE hObject )
// {
//     FUNCTION_CALL call = { 0 };

//     call.ptr  = ( PVOID ) ( KERNEL32$CloseHandle );
//     call.argc = 1;
    
//     call.args [ 0 ] = spoof_arg ( hObject );

//     return ( BOOL ) spoof_call ( &call );
// }

// int WINAPI _MessageBoxW ( HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType )
// {
//     FUNCTION_CALL call = { 0 };

//     call.ptr  = ( PVOID ) ( USER32$MessageBoxW );
//     call.argc = 4;
    
//     call.args [ 0 ] = spoof_arg ( hWnd );
//     call.args [ 1 ] = spoof_arg ( lpText );
//     call.args [ 2 ] = spoof_arg ( lpCaption );
//     call.args [ 3 ] = spoof_arg ( uType );

//     return ( int ) spoof_call ( &call );
// }
