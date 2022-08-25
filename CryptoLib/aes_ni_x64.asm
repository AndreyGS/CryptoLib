; @file aes.asm
; @author Andrey Grabov-Smetankin <ukbpyh@gmail.com>
;
; @section LICENSE
;
; Copyright 2022 Andrey Grabov-Smetankin
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

state SEGMENT align(64) 'data'

savedstate dq 1024 DUP(0)

state ENDS

.code

HardwareFeaturesDetect PROC C
	push rbx
	push rbp
	mov bp, 0
	mov eax, 1
	cpuid
	mov edx, ecx
	and ecx, 002000000H
	cmp ecx, 002000000H
	; check AESNI
	jne exit
	mov bp, 1
	and edx, 018000000H
	cmp edx, 018000000H 
	; check OSXSAVE, AVX
	jne exit
	mov ecx, 0
	xgetbv
	and eax, 06H
	cmp eax, 06H
	; check OS enabled SSE and AVX
	jne exit
	or bp, 2
	mov eax, 7
	mov ecx, 0
	cpuid
	and ecx, 00200H
	cmp ecx, 00200H
	; check OS enabled VAES
	jne exit
	or bp, 4
exit:
	mov ax, bp
	pop rbp
	pop rbx
	ret
HardwareFeaturesDetect ENDP

END