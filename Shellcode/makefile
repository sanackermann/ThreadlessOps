# based on https://bruteratel.com/research/feature-update/2021/01/30/OBJEXEC/
make:
	nasm -f win64 adjuststack.asm -o adjuststack.o
	x86_64-w64-mingw32-gcc ApiResolve.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ApiResolve.o -Wl,--no-seh
	x86_64-w64-mingw32-gcc Shellcode.c -Wall -m64 -masm=intel -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o Shellcode.o -Wl,--no-seh
	x86_64-w64-mingw32-ld -T linker.ld -s adjuststack.o ApiResolve.o Shellcode.o -o Shellcode.exe
