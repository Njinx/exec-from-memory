.intel_syntax noprefix
.global jmp_to_payload

jmp_to_payload:
    mov rsp, rsi
    xor rbp, rbp
    xor rdx, rdx
    jmp rdi
