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

.386
.xmm
.model flat, c

.code
align 16

include macro_asm.inc
include macro_asm_only_x86.inc

Aes128AvxKeySchedule PROC key: PTR, roundKeys: PTR, decryptionRoundKeys: PTR
	mov eax, key
	mov ecx, roundKeys
	mov edx, decryptionRoundKeys
	push ebx
	push edi

	MakeStack16BytesAligned 48
	
	vmovdqa xmmword ptr [ebp-16], xmm0
	vmovdqa xmmword ptr [ebp-32], xmm4
	vmovdqa xmmword ptr [ebp-48], xmm5
	
	vmovdqu xmm0, xmmword ptr [eax]
	vmovdqa xmmword ptr [ecx], xmm0
	add ecx, 16

	aeskeygenassist xmm4, xmm0, RC1
	call aux
	aeskeygenassist xmm4, xmm0, RC2
	call aux
	aeskeygenassist xmm4, xmm0, RC3
	call aux
	aeskeygenassist xmm4, xmm0, RC4
	call aux
	aeskeygenassist xmm4, xmm0, RC5
	call aux
	aeskeygenassist xmm4, xmm0, RC6
	call aux
	aeskeygenassist xmm4, xmm0, RC7
	call aux
	aeskeygenassist xmm4, xmm0, RC8
	call aux
	aeskeygenassist xmm4, xmm0, RC9
	call aux
	aeskeygenassist xmm4, xmm0, RC10
	call aux
	jmp decryptionRoundKeysSchedule

aux:
	vpshufd xmm4, xmm4, 0ffh
										
	vpslldq xmm5, xmm0, 04h				; here we using vpslldq instead of pslldq and vpxor instead of pxor
	vpxor xmm0, xmm0, xmm5				; cause mixing SSE and AVX may lead to performance penalties
	vpslldq xmm5, xmm5, 04h				
	vpxor xmm0, xmm0, xmm5						
	vpslldq xmm5, xmm5, 04h
	vpxor xmm0, xmm0, xmm5

	vpxor xmm0, xmm0, xmm4

	vmovdqa xmmword ptr [ecx], xmm0
	add ecx, 16
	pop edi									; I use pop and jmp, cause ret instruction in x86 mode here is
	jmp edi									; tries to return to other place (i don't know why, probably some secure behavior)
											; it's strange that in x64 mode everything works fine
; end of aux

decryptionRoundKeysSchedule:
	vmovdqa xmm0, xmmword ptr [ecx-16]
	vmovdqa xmmword ptr [edx+160], xmm0

	aesimc xmm0, xmmword ptr [ecx-32]
	vmovdqa xmmword ptr [edx+144], xmm0
	aesimc xmm0, xmmword ptr [ecx-48]
	vmovdqa xmmword ptr [edx+128], xmm0
	aesimc xmm0, xmmword ptr [ecx-64]
	vmovdqa xmmword ptr [edx+112], xmm0
	aesimc xmm0, xmmword ptr [ecx-80]
	vmovdqa xmmword ptr [edx+96], xmm0
	aesimc xmm0, xmmword ptr [ecx-96]
	vmovdqa xmmword ptr [edx+80], xmm0
	aesimc xmm0, xmmword ptr [ecx-112]
	vmovdqa xmmword ptr [edx+64], xmm0
	aesimc xmm0, xmmword ptr [ecx-128]
	vmovdqa xmmword ptr [edx+48], xmm0
	aesimc xmm0, xmmword ptr [ecx-144]
	vmovdqa xmmword ptr [edx+32], xmm0
	aesimc xmm0, xmmword ptr [ecx-160]
	vmovdqa xmmword ptr [edx+16], xmm0

	vmovdqa xmm0, xmmword ptr [ecx-176]
	vmovdqa xmmword ptr [edx], xmm0

; end of decryptionRoundKeysSchedule

	vmovdqa xmm5, xmmword ptr [ebp-48]
	vmovdqa xmm4, xmmword ptr [ebp-32]
	vmovdqa xmm0, xmmword ptr [ebp-16]

	RestoreStack16BytesAligned ebx
	pop edi
	pop ebx
	leave
	ret	
Aes128AvxKeySchedule ENDP

Aes192AvxKeySchedule PROC key: PTR, roundKeys: PTR, decryptionRoundKeys: PTR
	mov eax, key
	mov ecx, roundKeys
	mov edx, decryptionRoundKeys
	push ebx
	push edi

	MakeStack16BytesAligned 64

	vmovdqa xmmword ptr [ebp-16], xmm0
	vmovdqa xmmword ptr [ebp-32], xmm1
	vmovdqa xmmword ptr [ebp-48], xmm4
	vmovdqa xmmword ptr [ebp-64], xmm5

	vmovdqu xmm0, xmmword ptr [eax]
	movq xmm1, qword ptr [eax+16]
	vmovdqa xmmword ptr [ecx], xmm0
	movq qword ptr [ecx+16], xmm1
	add ecx, 24

	aeskeygenassist xmm4, xmm1, RC1
	call aux
	aeskeygenassist xmm4, xmm1, RC2
	call aux
	aeskeygenassist xmm4, xmm1, RC3
	call aux
	aeskeygenassist xmm4, xmm1, RC4
	call aux
	aeskeygenassist xmm4, xmm1, RC5
	call aux
	aeskeygenassist xmm4, xmm1, RC6
	call aux
	aeskeygenassist xmm4, xmm1, RC7
	call aux
	aeskeygenassist xmm4, xmm1, RC8
	call aux

	jmp decryptionRoundKeysSchedule

aux:
	vpshufd xmm4, xmm4, 055h
	
	vpslldq xmm5, xmm0, 04h
	vpxor xmm0, xmm0, xmm5
	vpslldq xmm5, xmm5, 04h
	vpxor xmm0, xmm0, xmm5
	vpslldq xmm5, xmm5, 04h
	vpxor xmm0, xmm0, xmm5

	vpxor xmm0, xmm0, xmm4

	vpshufd xmm4, xmm0, 0ffh
	
	vpslldq xmm5, xmm1, 04h
	vpxor xmm1, xmm1, xmm5
	vpxor xmm1, xmm1, xmm4

	vmovdqu xmmword ptr [ecx], xmm0
	vmovdqu xmmword ptr [ecx+16], xmm1
	add ecx, 24
	pop edi									; I use pop and jmp, cause ret instruction in x86 mode here is
	jmp edi									; tries to return to other place (i don't know why, probably some secure behavior)
											; it's strange that in x64 mode everything works fine
; end of aux

decryptionRoundKeysSchedule:
	vmovdqa xmm0, xmmword ptr [ecx-24]
	vmovdqa xmmword ptr [edx+192], xmm0

	aesimc xmm0, xmmword ptr [ecx-40]
	vmovdqa xmmword ptr [edx+176], xmm0
	aesimc xmm0, xmmword ptr [ecx-56]
	vmovdqa xmmword ptr [edx+160], xmm0
	aesimc xmm0, xmmword ptr [ecx-72]
	vmovdqa xmmword ptr [edx+144], xmm0
	aesimc xmm0, xmmword ptr [ecx-88]
	vmovdqa xmmword ptr [edx+128], xmm0
	aesimc xmm0, xmmword ptr [ecx-104]
	vmovdqa xmmword ptr [edx+112], xmm0
	aesimc xmm0, xmmword ptr [ecx-120]
	vmovdqa xmmword ptr [edx+96], xmm0
	aesimc xmm0, xmmword ptr [ecx-136]
	vmovdqa xmmword ptr [edx+80], xmm0
	aesimc xmm0, xmmword ptr [ecx-152]
	vmovdqa xmmword ptr [edx+64], xmm0
	aesimc xmm0, xmmword ptr [ecx-168]
	vmovdqa xmmword ptr [edx+48], xmm0
	aesimc xmm0, xmmword ptr [ecx-184]
	vmovdqa xmmword ptr [edx+32], xmm0
	aesimc xmm0, xmmword ptr [ecx-200]
	vmovdqa xmmword ptr [edx+16], xmm0

	vmovdqa xmm0, xmmword ptr [ecx-216]
	vmovdqa xmmword ptr [edx], xmm0

; end of decryptionRoundKeysSchedule

	vmovdqa xmm5, xmmword ptr [ebp-64]
	vmovdqa xmm4, xmmword ptr [ebp-48]
	vmovdqa xmm1, xmmword ptr [ebp-32]
	vmovdqa xmm0, xmmword ptr [ebp-16]

	RestoreStack16BytesAligned ebx
	pop edi
	pop ebx
	leave
	ret
Aes192AvxKeySchedule ENDP

Aes256AvxKeySchedule PROC key: PTR, roundKeys: PTR, decryptionRoundKeys: PTR
	mov eax, key
	mov ecx, roundKeys
	mov edx, decryptionRoundKeys
	push ebx
	push esi
	push edi

	MakeStack16BytesAligned 64

	vmovdqa xmmword ptr [ebp-16], xmm0
	vmovdqa xmmword ptr [ebp-32], xmm1
	vmovdqa xmmword ptr [ebp-48], xmm4
	vmovdqa xmmword ptr [ebp-64], xmm5

	vmovdqu xmm0, xmmword ptr [eax]
	vmovdqu xmm1, xmmword ptr [eax+16]
	vmovdqa xmmword ptr [ecx], xmm0
	vmovdqa xmmword ptr [ecx+16], xmm1
	add ecx, 32

	mov si, 0
	aeskeygenassist xmm4, xmm1, RC1
	call aux
	aeskeygenassist xmm4, xmm1, RC2
	call aux
	aeskeygenassist xmm4, xmm1, RC3
	call aux
	aeskeygenassist xmm4, xmm1, RC4
	call aux
	aeskeygenassist xmm4, xmm1, RC5
	call aux
	aeskeygenassist xmm4, xmm1, RC6
	call aux
	aeskeygenassist xmm4, xmm1, RC7
	mov si, 1
	call aux

	jmp decryptionRoundKeysSchedule

aux:
	vpshufd xmm4, xmm4, 0ffh
	
	vpslldq xmm5, xmm0, 04h
	vpxor xmm0, xmm0, xmm5
	vpslldq xmm5, xmm5, 04h
	vpxor xmm0, xmm0, xmm5
	vpslldq xmm5, xmm5, 04h
	vpxor xmm0, xmm0, xmm5

	vpxor xmm0, xmm0, xmm4

	vmovdqu xmmword ptr [ecx], xmm0
	add ecx, 16

	cmp si, 1
	jz @f

	aeskeygenassist xmm5, xmm0, 0

	vpshufd xmm4, xmm5, 0aah

	vpslldq xmm5, xmm1, 04h
	vpxor xmm1, xmm1, xmm5
	vpslldq xmm5, xmm5, 04h
	vpxor xmm1, xmm1, xmm5
	vpslldq xmm5, xmm5, 04h
	vpxor xmm1, xmm1, xmm5

	vpxor xmm1, xmm1, xmm4

	vmovdqu xmmword ptr [ecx], xmm1
	add ecx, 16
@@:
	pop edi									; I use pop and jmp, cause ret instruction in x86 mode here is
	jmp edi									; tries to return to other place (i don't know why, probably some secure behavior)
											; it's strange that in x64 mode everything works fine
; end of aux

decryptionRoundKeysSchedule:
	vmovdqa xmm0, xmmword ptr [ecx-16]
	vmovdqa xmmword ptr [edx+224], xmm0

	aesimc xmm0, xmmword ptr [ecx-32]
	vmovdqa xmmword ptr [edx+208], xmm0
	aesimc xmm0, xmmword ptr [ecx-48]
	vmovdqa xmmword ptr [edx+192], xmm0
	aesimc xmm0, xmmword ptr [ecx-64]
	vmovdqa xmmword ptr [edx+176], xmm0
	aesimc xmm0, xmmword ptr [ecx-80]
	vmovdqa xmmword ptr [edx+160], xmm0
	aesimc xmm0, xmmword ptr [ecx-96]
	vmovdqa xmmword ptr [edx+144], xmm0
	aesimc xmm0, xmmword ptr [ecx-112]
	vmovdqa xmmword ptr [edx+128], xmm0
	aesimc xmm0, xmmword ptr [ecx-128]
	vmovdqa xmmword ptr [edx+112], xmm0
	aesimc xmm0, xmmword ptr [ecx-144]
	vmovdqa xmmword ptr [edx+96], xmm0
	aesimc xmm0, xmmword ptr [ecx-160]
	vmovdqa xmmword ptr [edx+80], xmm0
	aesimc xmm0, xmmword ptr [ecx-176]
	vmovdqa xmmword ptr [edx+64], xmm0
	aesimc xmm0, xmmword ptr [ecx-192]
	vmovdqa xmmword ptr [edx+48], xmm0
	aesimc xmm0, xmmword ptr [ecx-208]
	vmovdqa xmmword ptr [edx+32], xmm0
	aesimc xmm0, xmmword ptr [ecx-224]
	vmovdqa xmmword ptr [edx+16], xmm0

	vmovdqa xmm0, xmmword ptr [ecx-240]
	vmovdqa xmmword ptr [edx], xmm0

; end of decryptionRoundKeysSchedule
	
	vmovdqa xmm5, xmmword ptr [ebp-64]
	vmovdqa xmm4, xmmword ptr [ebp-48]
	vmovdqa xmm1, xmmword ptr [ebp-32]
	vmovdqa xmm0, xmmword ptr [ebp-16]

	RestoreStack16BytesAligned ebx
	pop edi
	pop esi
	pop ebx
	leave
	ret
Aes256AvxKeySchedule ENDP

Aes128NiKeySchedule PROC key: PTR, roundKeys: PTR, decryptionRoundKeys: PTR
	mov eax, key
	mov ecx, roundKeys
	mov edx, decryptionRoundKeys
	push ebx
	push edi
	
	MakeStack16BytesAligned 48

	movdqa xmmword ptr [ebp-16], xmm0
	movdqa xmmword ptr [ebp-48], xmm4
	movdqa xmmword ptr [ebp-64], xmm5

	movdqu xmm0, xmmword ptr [eax]
	movdqa xmmword ptr [ecx], xmm0
	add ecx, 16

	aeskeygenassist xmm4, xmm0, RC1
	call aux
	aeskeygenassist xmm4, xmm0, RC2
	call aux
	aeskeygenassist xmm4, xmm0, RC3
	call aux
	aeskeygenassist xmm4, xmm0, RC4
	call aux
	aeskeygenassist xmm4, xmm0, RC5
	call aux
	aeskeygenassist xmm4, xmm0, RC6
	call aux
	aeskeygenassist xmm4, xmm0, RC7
	call aux
	aeskeygenassist xmm4, xmm0, RC8
	call aux
	aeskeygenassist xmm4, xmm0, RC9
	call aux
	aeskeygenassist xmm4, xmm0, RC10
	call aux
	jmp decryptionRoundKeysSchedule

aux:
	pshufd xmm4, xmm4, 0ffh

	movdqa xmm5, xmm0
	pslldq xmm5, 04h
	pxor xmm0, xmm5
	pslldq xmm5, 04h
	pxor xmm0, xmm5
	pslldq xmm5, 04h
	pxor xmm0, xmm5

	pxor xmm0, xmm4

	movdqa xmmword ptr [ecx], xmm0
	add ecx, 16
	pop edi									; I use pop and jmp, cause ret instruction in x86 mode here is
	jmp edi									; tries to return to other place (i don't know why, probably some secure behavior)
											; it's strange that in x64 mode everything works fine
; end of aux

decryptionRoundKeysSchedule:
	movdqa xmm0, xmmword ptr [ecx-16]
	movdqa xmmword ptr [edx+160], xmm0

	aesimc xmm0, xmmword ptr [ecx-32]
	movdqa xmmword ptr [edx+144], xmm0
	aesimc xmm0, xmmword ptr [ecx-48]
	movdqa xmmword ptr [edx+128], xmm0
	aesimc xmm0, xmmword ptr [ecx-64]
	movdqa xmmword ptr [edx+112], xmm0
	aesimc xmm0, xmmword ptr [ecx-80]
	movdqa xmmword ptr [edx+96], xmm0
	aesimc xmm0, xmmword ptr [ecx-96]
	movdqa xmmword ptr [edx+80], xmm0
	aesimc xmm0, xmmword ptr [ecx-112]
	movdqa xmmword ptr [edx+64], xmm0
	aesimc xmm0, xmmword ptr [ecx-128]
	movdqa xmmword ptr [edx+48], xmm0
	aesimc xmm0, xmmword ptr [ecx-144]
	movdqa xmmword ptr [edx+32], xmm0
	aesimc xmm0, xmmword ptr [ecx-160]
	movdqa xmmword ptr [edx+16], xmm0

	movdqa xmm0, xmmword ptr [ecx-176]
	movdqa xmmword ptr [edx], xmm0

; end of decryptionRoundKeysSchedule
	
	movdqa xmm5, xmmword ptr [ebp-48]
	movdqa xmm4, xmmword ptr [ebp-32]
	movdqa xmm0, xmmword ptr [ebp-16]

	RestoreStack16BytesAligned ebx
	leave
	pop edi
	pop ebx
	ret
Aes128NiKeySchedule ENDP

Aes192NiKeySchedule PROC key: PTR, roundKeys: PTR, decryptionRoundKeys: PTR
	mov eax, key
	mov ecx, roundKeys
	mov edx, decryptionRoundKeys
	push ebx
	push edi

	MakeStack16BytesAligned 64

	movdqa xmmword ptr [ebp-16], xmm0
	movdqa xmmword ptr [ebp-32], xmm1
	movdqa xmmword ptr [ebp-48], xmm4
	movdqa xmmword ptr [ebp-64], xmm5

	movdqu xmm0, xmmword ptr [eax]
	movq xmm1, qword ptr [eax+16]
	movdqa xmmword ptr [ecx], xmm0
	movq qword ptr [ecx+16], xmm1
	add ecx, 24

	aeskeygenassist xmm4, xmm1, RC1
	call aux
	aeskeygenassist xmm4, xmm1, RC2
	call aux
	aeskeygenassist xmm4, xmm1, RC3
	call aux
	aeskeygenassist xmm4, xmm1, RC4
	call aux
	aeskeygenassist xmm4, xmm1, RC5
	call aux
	aeskeygenassist xmm4, xmm1, RC6
	call aux
	aeskeygenassist xmm4, xmm1, RC7
	call aux
	aeskeygenassist xmm4, xmm1, RC8
	call aux

	jmp decryptionRoundKeysSchedule

aux:
	pshufd xmm4, xmm4, 055h
	
	movdqa xmm5, xmm0
	pslldq xmm5, 04h
	pxor xmm0, xmm5
	pslldq xmm5, 04h
	pxor xmm0, xmm5
	pslldq xmm5, 04h
	pxor xmm0, xmm5

	pxor xmm0, xmm4

	pshufd xmm4, xmm0, 0ffh
	
	movdqa xmm5, xmm1
	pslldq xmm5, 04h
	pxor xmm1, xmm5
	pxor xmm1, xmm4

	movdqu xmmword ptr [ecx], xmm0
	movdqu xmmword ptr [ecx+16], xmm1
	add ecx, 24
	pop edi									; I use pop and jmp, cause ret instruction in x86 mode here is
	jmp edi									; tries to return to other place (i don't know why, probably some secure behavior)
											; it's strange that in x64 mode everything works fine
; end of aux

decryptionRoundKeysSchedule:
	movdqa xmm0, xmmword ptr [ecx-24]
	movdqa xmmword ptr [edx+192], xmm0

	aesimc xmm0, xmmword ptr [ecx-40]
	movdqa xmmword ptr [edx+176], xmm0
	aesimc xmm0, xmmword ptr [ecx-56]
	movdqa xmmword ptr [edx+160], xmm0
	aesimc xmm0, xmmword ptr [ecx-72]
	movdqa xmmword ptr [edx+144], xmm0
	aesimc xmm0, xmmword ptr [ecx-88]
	movdqa xmmword ptr [edx+128], xmm0
	aesimc xmm0, xmmword ptr [ecx-104]
	movdqa xmmword ptr [edx+112], xmm0
	aesimc xmm0, xmmword ptr [ecx-120]
	movdqa xmmword ptr [edx+96], xmm0
	aesimc xmm0, xmmword ptr [ecx-136]
	movdqa xmmword ptr [edx+80], xmm0
	aesimc xmm0, xmmword ptr [ecx-152]
	movdqa xmmword ptr [edx+64], xmm0
	aesimc xmm0, xmmword ptr [ecx-168]
	movdqa xmmword ptr [edx+48], xmm0
	aesimc xmm0, xmmword ptr [ecx-184]
	movdqa xmmword ptr [edx+32], xmm0
	aesimc xmm0, xmmword ptr [ecx-200]
	movdqa xmmword ptr [edx+16], xmm0

	movdqa xmm0, xmmword ptr [ecx-216]
	movdqa xmmword ptr [edx], xmm0

; end of decryptionRoundKeysSchedule

	movdqa xmm5, xmmword ptr [ebp-64]
	movdqa xmm4, xmmword ptr [ebp-48]
	movdqa xmm1, xmmword ptr [ebp-32]
	movdqa xmm0, xmmword ptr [ebp-16]

	RestoreStack16BytesAligned ebx
	pop edi
	pop ebx
	leave
	ret
Aes192NiKeySchedule ENDP

Aes256NiKeySchedule PROC key: PTR, roundKeys: PTR, decryptionRoundKeys: PTR
	mov eax, key
	mov ecx, roundKeys
	mov edx, decryptionRoundKeys
	push ebx
	push esi
	push edi

	MakeStack16BytesAligned 64

	movdqa xmmword ptr [ebp-16], xmm0
	movdqa xmmword ptr [ebp-32], xmm1
	movdqa xmmword ptr [ebp-48], xmm4
	movdqa xmmword ptr [ebp-64], xmm5

	movdqu xmm0, xmmword ptr [eax]
	movdqu xmm1, xmmword ptr [eax+16]
	movdqa xmmword ptr [ecx], xmm0
	movdqa xmmword ptr [ecx+16], xmm1
	add ecx, 32

	mov si, 0
	aeskeygenassist xmm4, xmm1, RC1
	call aux
	aeskeygenassist xmm4, xmm1, RC2
	call aux
	aeskeygenassist xmm4, xmm1, RC3
	call aux
	aeskeygenassist xmm4, xmm1, RC4
	call aux
	aeskeygenassist xmm4, xmm1, RC5
	call aux
	aeskeygenassist xmm4, xmm1, RC6
	call aux
	aeskeygenassist xmm4, xmm1, RC7
	mov si, 1
	call aux

	jmp decryptionRoundKeysSchedule

aux:
	pshufd xmm4, xmm4, 0ffh
	
	movdqa xmm5, xmm0
	pslldq xmm5, 04h
	pxor xmm0, xmm5
	pslldq xmm5, 04h
	pxor xmm0, xmm5
	pslldq xmm5, 04h
	pxor xmm0, xmm5

	pxor xmm0, xmm4

	movdqu xmmword ptr [ecx], xmm0
	add ecx, 16

	cmp si, 1
	jz @f

	aeskeygenassist xmm5, xmm0, 0

	pshufd xmm4, xmm5, 0aah

	movdqa xmm5, xmm1
	pslldq xmm5, 04h
	pxor xmm1, xmm5
	pslldq xmm5, 04h
	pxor xmm1, xmm5
	pslldq xmm5, 04h
	pxor xmm1, xmm5

	pxor xmm1, xmm4

	vmovdqu xmmword ptr [ecx], xmm1
	add ecx, 16
@@:
	pop edi									; I use pop and jmp, cause ret instruction in x86 mode here is
	jmp edi									; tries to return to other place (i don't know why, probably some secure behavior)
											; it's strange that in x64 mode everything works fine
; end of aux

decryptionRoundKeysSchedule:
	movdqa xmm0, xmmword ptr [ecx-16]
	movdqa xmmword ptr [edx+224], xmm0

	aesimc xmm0, xmmword ptr [ecx-32]
	movdqa xmmword ptr [edx+208], xmm0
	aesimc xmm0, xmmword ptr [ecx-48]
	movdqa xmmword ptr [edx+192], xmm0
	aesimc xmm0, xmmword ptr [ecx-64]
	movdqa xmmword ptr [edx+176], xmm0
	aesimc xmm0, xmmword ptr [ecx-80]
	movdqa xmmword ptr [edx+160], xmm0
	aesimc xmm0, xmmword ptr [ecx-96]
	movdqa xmmword ptr [edx+144], xmm0
	aesimc xmm0, xmmword ptr [ecx-112]
	movdqa xmmword ptr [edx+128], xmm0
	aesimc xmm0, xmmword ptr [ecx-128]
	movdqa xmmword ptr [edx+112], xmm0
	aesimc xmm0, xmmword ptr [ecx-144]
	movdqa xmmword ptr [edx+96], xmm0
	aesimc xmm0, xmmword ptr [ecx-160]
	movdqa xmmword ptr [edx+80], xmm0
	aesimc xmm0, xmmword ptr [ecx-176]
	movdqa xmmword ptr [edx+64], xmm0
	aesimc xmm0, xmmword ptr [ecx-192]
	movdqa xmmword ptr [edx+48], xmm0
	aesimc xmm0, xmmword ptr [ecx-208]
	movdqa xmmword ptr [edx+32], xmm0
	aesimc xmm0, xmmword ptr [ecx-224]
	movdqa xmmword ptr [edx+16], xmm0

	movdqa xmm0, xmmword ptr [ecx-240]
	movdqa xmmword ptr [edx], xmm0

; end of decryptionRoundKeysSchedule
	
	movdqa xmm5, xmmword ptr [ebp-64]
	movdqa xmm4, xmmword ptr [ebp-48]
	movdqa xmm1, xmmword ptr [ebp-32]
	movdqa xmm0, xmmword ptr [ebp-16]

	RestoreStack16BytesAligned ebx
	pop edi
	pop esi
	pop ebx
	leave
	ret
Aes256NiKeySchedule ENDP

; Because x86 does not support xmm8-xmm15 this function is almost the same as PrepareXmmRegistersForAesNi
; and cipherType argument is not in the case now. But not to make things too complicated
; no macro definitions in C code with bitness switch are applied.
; Instead we just keep current unused parameter and stay with little overhead.
PrepareXmmRegistersForAesAvx PROC roundKeys: PTR, cipherType: DWORD, xmmRegsBuffer: PTR
	mov ecx, dword ptr [esp+8]		; roundKeys
	mov edx, dword ptr [esp+16]		; xmmRegsBuffer

	vmovdqa xmmword ptr [edx], xmm0
	vmovdqa xmmword ptr [edx+16], xmm1
	vmovdqa xmmword ptr [edx+32], xmm2
	vmovdqa xmmword ptr [edx+48], xmm3
	vmovdqa xmmword ptr [edx+64], xmm4
	vmovdqa xmmword ptr [edx+80], xmm5
	vmovdqa xmmword ptr [edx+96], xmm6
	vmovdqa xmmword ptr [edx+112], xmm7
	
	vmovdqa xmm1, xmmword ptr [ecx]
	vmovdqa xmm2, xmmword ptr [ecx + 16]
	vmovdqa xmm3, xmmword ptr [ecx + 32]
	vmovdqa xmm4, xmmword ptr [ecx + 48]
	vmovdqa xmm5, xmmword ptr [ecx + 64]
	vmovdqa xmm6, xmmword ptr [ecx + 80]

	ret
PrepareXmmRegistersForAesAvx ENDP

PrepareXmmRegistersForAesNi PROC roundKeys: PTR, xmmRegsBuffer: PTR
	mov ecx, roundKeys
	mov edx, xmmRegsBuffer

	movdqa xmmword ptr [edx], xmm0
	movdqa xmmword ptr [edx+16], xmm1
	movdqa xmmword ptr [edx+32], xmm2
	movdqa xmmword ptr [edx+48], xmm3
	movdqa xmmword ptr [edx+64], xmm4
	movdqa xmmword ptr [edx+80], xmm5
	movdqa xmmword ptr [edx+96], xmm6
	movdqa xmmword ptr [edx+112], xmm7
	
	movdqa xmm1, xmmword ptr [ecx]
	movdqa xmm2, xmmword ptr [ecx + 16]
	movdqa xmm3, xmmword ptr [ecx + 32]
	movdqa xmm4, xmmword ptr [ecx + 48]
	movdqa xmm5, xmmword ptr [ecx + 64]
	movdqa xmm6, xmmword ptr [ecx + 80]

	ret
PrepareXmmRegistersForAesNi ENDP

RestoreXmmRegistersFromAesAvx PROC cipher: DWORD, xmmRegsBuffer: PTR
	mov edx, dword ptr [esp+12]	; xmmRegsBuffer

	vmovdqa xmm0, xmmword ptr [edx]
	vmovdqa xmm1, xmmword ptr [edx + 16]
	vmovdqa xmm2, xmmword ptr [edx + 32]
	vmovdqa xmm3, xmmword ptr [edx + 48]
	vmovdqa xmm4, xmmword ptr [edx + 64]
	vmovdqa xmm5, xmmword ptr [edx + 80]
	vmovdqa xmm6, xmmword ptr [edx + 96]
	vmovdqa xmm7, xmmword ptr [edx + 112]

	ret
RestoreXmmRegistersFromAesAvx ENDP

RestoreXmmRegistersFromAesNi PROC xmmRegsBuffer: PTR
	mov edx, xmmRegsBuffer

	movdqa xmm0, xmmword ptr [edx]
	movdqa xmm1, xmmword ptr [edx + 16]
	movdqa xmm2, xmmword ptr [edx + 32]
	movdqa xmm3, xmmword ptr [edx + 48]
	movdqa xmm4, xmmword ptr [edx + 64]
	movdqa xmm5, xmmword ptr [edx + 80]
	movdqa xmm6, xmmword ptr [edx + 96]
	movdqa xmm7, xmmword ptr [edx + 112]

	ret
RestoreXmmRegistersFromAesNi ENDP


Aes128AvxEncryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	vmovdqu xmm0, xmmword ptr [ecx]
	vxorps xmm0, xmm0, xmm1 ; input ^ roundKeys[0]
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	vmovdqa xmm7, xmmword ptr [eax+96]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+112]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+128]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+144]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+160]
	aesenclast xmm0, xmm7
	vmovdqu xmmword ptr [edx], xmm0

	ret
Aes128AvxEncryptBlock ENDP

Aes192AvxEncryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	vmovdqu xmm0, xmmword ptr [ecx]
	vxorps xmm0, xmm0, xmm1 ; input ^ roundKeys[0]
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	vmovdqa xmm7, xmmword ptr [eax+96]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+112]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+128]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+144]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+160]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+176]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+192]
	aesenclast xmm0, xmm7
	vmovdqu xmmword ptr [edx], xmm0

	ret
Aes192AvxEncryptBlock ENDP

Aes256AvxEncryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	vmovdqu xmm0, xmmword ptr [ecx]
	vxorps xmm0, xmm0, xmm1 ; input ^ roundKeys[0]
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	vmovdqa xmm7, xmmword ptr [eax+96]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+112]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+128]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+144]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+160]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+176]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+192]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+208]
	aesenc xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+224]
	aesenclast xmm0, xmm7
	vmovdqu xmmword ptr [edx], xmm0

	ret
Aes256AvxEncryptBlock ENDP

Aes128AvxDecryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	vmovdqu xmm0, xmmword ptr [ecx]
	vmovdqa xmm7, xmmword ptr [eax+160]
	vxorps xmm0, xmm0, xmm7 ; input ^ roundKeys[11]
	vmovdqa xmm7, xmmword ptr [eax+144]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+128]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+112]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+96]
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdeclast xmm0, xmm1
	vmovdqu xmmword ptr [edx], xmm0

	ret
Aes128AvxDecryptBlock ENDP

Aes192AvxDecryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	vmovdqu xmm0, xmmword ptr [ecx]
	vmovdqa xmm7, xmmword ptr [eax+192]
	vxorps xmm0, xmm0, xmm7 ; input ^ roundKeys[13]
	vmovdqa xmm7, xmmword ptr [eax+176]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+160]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+144]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+128]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+112]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+96]
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdeclast xmm0, xmm1
	vmovdqu xmmword ptr [edx], xmm0

	ret
Aes192AvxDecryptBlock ENDP

Aes256AvxDecryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	vmovdqu xmm0, xmmword ptr [ecx]
	vmovdqa xmm7, xmmword ptr [eax+224]
	vxorps xmm0, xmm0, xmm7 ; input ^ roundKeys[15]
	vmovdqa xmm7, xmmword ptr [eax+208]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+192]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+176]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+160]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+144]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+128]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+112]
	aesdec xmm0, xmm7
	vmovdqa xmm7, xmmword ptr [eax+96]
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdeclast xmm0, xmm1
	vmovdqu xmmword ptr [edx], xmm0

	ret
Aes256AvxDecryptBlock ENDP


Aes128NiEncryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	movdqu xmm0, xmmword ptr [ecx]
	xorps xmm0, xmm1 ; input ^ roundKeys[0]
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	movdqa xmm7, xmmword ptr [eax+96]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+112]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+128]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+144]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+160]
	aesenclast xmm0, xmm7
	movdqu xmmword ptr [edx], xmm0

	ret
Aes128NiEncryptBlock ENDP

Aes192NiEncryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	movdqu xmm0, xmmword ptr [ecx]
	xorps xmm0, xmm1 ; input ^ roundKeys[0]
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	movdqa xmm7, xmmword ptr [eax+96]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+112]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+128]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+144]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+160]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+176]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+192]
	aesenclast xmm0, xmm7
	movdqu xmmword ptr [edx], xmm0

	ret
Aes192NiEncryptBlock ENDP

Aes256NiEncryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	movdqu xmm0, xmmword ptr [ecx]
	xorps xmm0, xmm1 ; input ^ roundKeys[0]
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	movdqa xmm7, xmmword ptr [eax+96]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+112]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+128]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+144]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+160]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+176]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+192]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+208]
	aesenc xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+224]
	aesenclast xmm0, xmm7
	movdqu xmmword ptr [edx], xmm0

	ret
Aes256NiEncryptBlock ENDP

Aes128NiDecryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	movdqu xmm0, xmmword ptr [ecx]
	movdqa xmm7, xmmword ptr [eax+160]
	xorps xmm0, xmm7 ; input ^ roundKeys[11]
	movdqa xmm7, xmmword ptr [eax+144]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+128]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+112]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+96]
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdeclast xmm0, xmm1
	movdqu xmmword ptr [edx], xmm0

	ret
Aes128NiDecryptBlock ENDP

Aes192NiDecryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	movdqu xmm0, xmmword ptr [ecx]
	movdqa xmm7, xmmword ptr [eax+192]
	xorps xmm0, xmm7 ; input ^ roundKeys[13]
	movdqa xmm7, xmmword ptr [eax+176]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+160]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+144]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+128]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+112]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+96]
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdeclast xmm0, xmm1
	movdqu xmmword ptr [edx], xmm0

	ret
Aes192NiDecryptBlock ENDP

Aes256NiDecryptBlock PROC roundKeys: PTR, input: PTR, output: PTR
	mov eax, roundKeys
	mov ecx, input
	mov edx, output

	movdqu xmm0, xmmword ptr [ecx]
	movdqa xmm7, xmmword ptr [eax+224]
	xorps xmm0, xmm7 ; input ^ roundKeys[15]
	movdqa xmm7, xmmword ptr [eax+208]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+192]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+176]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+160]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+144]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+128]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+112]
	aesdec xmm0, xmm7
	movdqa xmm7, xmmword ptr [eax+96]
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdeclast xmm0, xmm1
	movdqu xmmword ptr [edx], xmm0

	ret
Aes256NiDecryptBlock ENDP

END
