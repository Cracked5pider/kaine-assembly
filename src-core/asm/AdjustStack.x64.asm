;;
;; Havoc kaine dotnet module
;;
[BITS 64]

DEFAULT REL

;;
;; Import
;;
EXTERN ScAssemblyEnter

;;
;; Export
;;
GLOBAL Start
GLOBAL ___chkstk_ms
GLOBAL KnRipData

;;
;; Main shellcode entrypoint.
;;
[SECTION .text$A]
    ;;
    ;; shellcode entrypoint
    ;; aligns the stack by 16-bytes to avoid any unwanted
    ;; crashes while calling win32 functions and execute
    ;; the true C code entrypoint
    ;;
    Start:
        ;;
        ;; prepare execution
        ;;
        push rsi                     ;; preserve rsi by pushing it to the stack
        mov  rsi, rsp                ;; save rsp value to restore it later
        and  rsp, 0FFFFFFFFFFFFFFF0h ;; align the stack by 16-byte
        sub  rsp, 020h               ;; allocate stack space

        ;;
        ;; execute C entry point function
        ;;
        call ScAssemblyEnter

        ;;
        ;; restore registers and stack
        ;;
        mov rsp, rsi ;; restore original rsp value
        pop rsi      ;; restore value of rsi from stack
    ret

;;
;; Retrieving data and string literals
;;
[SECTION .text$F]
    ;;
    ;; get rip to the included .rdata section
    ;;
    KnRipData:
        call KnRetPtrData
    ret
    ;;
    ;; get the return address of RetPtrData and put it into the rax register
    ;;
    KnRetPtrData:
        mov	rax, [rsp]
        sub	rax, 0x5
    ret

;;
;; shellcode functions
;;
[SECTION .text$B]
    ;;
    ;; fixes some compiler unresolved symbol issue
    ;;
    ___chkstk_ms:
        ;; dont execute anything
    ret