extern main
global go

segment .text

go:
    push rdi                    ; backup rdi since we will be using this as our main register
    mov rdi, rsp                ; save stack pointer to rdi
    and rsp, byte -0x10         ; align stack with 16 bytes
    sub rsp, byte +0x20         ; allocate some space for our C function
    call main                   ; call the C function void main()
    mov rsp, rdi                ; restore stack pointer
    pop rdi                     ; restore rdi
    ret                         ; return where we left