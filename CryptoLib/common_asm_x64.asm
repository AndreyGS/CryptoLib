; @file common_asm_x64.asm
; @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
;
; @section LICENSE
;
; Copyright 2022-2023 Andrey Grabov-Smetankin <ukbpyh@gmail.com>
;
; Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files
; (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
; publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
; subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
; THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
; IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
; WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
; OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

.code
align 16

HardwareFeaturesDetect PROC USES rbx
	push rbp
	mov bp, 0
	mov eax, 1
	cpuid
	mov edx, ecx
	and ecx, 002000000H
	cmp ecx, 002000000H			; check AESNI
	jne @f
	mov bp, 1					; can use AES hardware encryption
	and edx, 018000000H
	cmp edx, 018000000H			; check OSXSAVE, AVX
	jne @f
	or bp, 2					; can use 16 xmm registers
	mov ecx, 0
	xgetbv
	and eax, 06H
	cmp eax, 06H				; check OS enabled SSE and AVX
	jne @f
	or bp, 4					; can use VEX-encoded AES (not implemented for now)
	mov eax, 7
	mov ecx, 0
	cpuid
	and ecx, 00200H
	cmp ecx, 00200H				; check OS enabled VAES
	jne @f
	or bp, 8					; can use VAES (not implemented for now)
@@:
	cmp bp, 0
	je exit
	mov eax, 19H
	cpuid
	and ebx, 000000001H
	cmp ebx, 000000001H			; check AESKLE feature
	jne exit
	or bp, 16					; AESKLE feature enabled (not implemented for now)
exit:
	mov ax, bp
	pop rbp
	ret
HardwareFeaturesDetect ENDP

END
