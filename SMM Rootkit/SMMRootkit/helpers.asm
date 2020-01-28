
.CODE

;
; UINT64 GetCR0(VOID)
;
GetCR0					proc
						mov		rax, cr0
						ret
GetCR0					endp

;
; UINT64 GetCR3(VOID)
;
GetCR3					proc
						mov		rax, cr3
						ret
GetCR3					endp

;
; UINT64 GetCR4(VOID)
;
GetCR4					proc
						mov		rax, cr4
						ret
GetCR4       			endp

;
; VOID LoadIDTR(UINT64 IDTR)
;
LoadIDTR			proc
					sidt fword ptr [rcx]
					ret
LoadIDTR			endp

;
; UINT64 ReadMsr64(UINT32  Index)
;
ReadMsr64			proc
					rdmsr                               ; edx & eax are zero extended
					shl     rdx, 0x20
					or      rax, rdx
					ret
ReadMsr64			endp

;
; UINT64 WriteMsr64(IN UINT32  Index, IN UINT64  Value)
;
WriteMsr64			proc
					mov     rax, rdx                    ; meanwhile, rax <- return value
					shr     rdx, 0x20                    ; edx:eax contains the value to write
					wrmsr
					ret
WriteMsr64			endp

;
; VOID GenerateSMI(VOID)
;
GenerateSMI			proc
					mov     al, 0x8A                    ; meanwhile, rax <- return value
					out     0xB2, al                    ; edx:eax contains the value to write
GenerateSMI			endp

;
; VOID SetDR0(UINT64 physicalAddress)
;
SetDR0				proc
					mov     dr0, rcx 
					mov     rax, rcx
					ret
SetDR0				endp

;
; UINT64 GetDR0(VOID)
;
GetDR0				proc
					mov     rax, dr0
					ret 
GetDR0				endp

;
; VOID SetDR1(UINT64 physicalAddress)
;
SetDR1				proc
					mov     dr1, rcx 
					mov     rax, rcx
					ret
SetDR1				endp

;
; UINT64 GetDR1(VOID)
;
GetDR1				proc
					mov     rax, dr1
					ret 
GetDR1				endp

;
; VOID SetDR2(UINT64 physicalAddress)
;
SetDR2				proc
					mov     dr2, rcx 
					mov     rax, rcx
					ret
SetDR2				endp

;
; UINT64 GetDR2(VOID)
;
GetDR2				proc
					mov     rax, dr2
					ret 
GetDR2				endp

;
; UINTN SetDR3(UINT64 physicalAddress)
;
SetDR3				proc
					mov     dr3, rcx 
					mov     rax, rcx
					ret
SetDR3				endp

;
; UINT64 GetDR3(VOID)
;
GetDR3				proc
					mov     rax, dr3
					ret 
GetDR3				endp


;
; VOID LongkitEFLAGS(UINT64 PhysRSP)
;
LongkitEFLAGS		proc
					mov rbx, [rax + 24]
					or rbx, 400000
					mov [rax + 24], rbx
LongkitEFLAGS		endp

END

