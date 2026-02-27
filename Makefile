CC=i686-w64-mingw32-gcc
CC_64=x86_64-w64-mingw32-gcc
NASM=nasm

all: create

bin:
	mkdir bin

#
# x64 targets
#
create: bin
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/loader.c -o bin/loader.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/carokann.c  -o bin/carokann.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/payload.c  -o bin/payload.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/common/services.c -o bin/services.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/common/hook.c  -o bin/hook.x64.o
	$(CC_64) -DWIN_X64 -shared -masm=intel -Wall -Wno-pointer-arith -c src/common/spoof.c  -o bin/spoof.x64.o
	$(NASM) -f bin src/common/draugr.asm -o bin/draugr.x64.bin

clean:
	rm -f bin/*
