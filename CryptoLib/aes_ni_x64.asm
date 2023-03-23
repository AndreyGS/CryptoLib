; @file aes_ni_x64.asm
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

.code
align 16

include macro_asm.inc

Aes128AvxKeySchedule PROC
; rcx: key: xmmword ptr
; rdx: roundKeys: xmmword ptr
; r8: decryptionRoundKeys : xmmword ptr

	vmovdqu xmm0, xmmword ptr [rcx]
	vmovdqa xmmword ptr [rdx], xmm0
	add rdx, 16

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

	vmovdqa xmmword ptr [rdx], xmm0
	add rdx, 16
	ret

; end of aux

decryptionRoundKeysSchedule:			; AES-NI not using raw round keys in decryption routines because of internal implementation
	vmovdqa xmm0, xmmword ptr [rdx-16]
	vmovdqa xmmword ptr [r8+160], xmm0

	aesimc xmm0, xmmword ptr [rdx-32]   ; From Intel® 64 and IA-32 Architectures Software Developer’s Manual Volume 2 (2A, 2B & 2C) (3-52 Vol. 2A):
	vmovdqa xmmword ptr [r8+144], xmm0  ; "AESIMC instruction should be applied to the expanded AES round keys (except for the first and last round key)
	aesimc xmm0, xmmword ptr [rdx-48]	; in order to prepare them for decryption using the “Equivalent Inverse Cipher” (defined in FIPS 197)."
	vmovdqa xmmword ptr [r8+128], xmm0
	aesimc xmm0, xmmword ptr [rdx-64]
	vmovdqa xmmword ptr [r8+112], xmm0
	aesimc xmm0, xmmword ptr [rdx-80]
	vmovdqa xmmword ptr [r8+96], xmm0
	aesimc xmm0, xmmword ptr [rdx-96]
	vmovdqa xmmword ptr [r8+80], xmm0
	aesimc xmm0, xmmword ptr [rdx-112]
	vmovdqa xmmword ptr [r8+64], xmm0
	aesimc xmm0, xmmword ptr [rdx-128]
	vmovdqa xmmword ptr [r8+48], xmm0
	aesimc xmm0, xmmword ptr [rdx-144]
	vmovdqa xmmword ptr [r8+32], xmm0
	aesimc xmm0, xmmword ptr [rdx-160]
	vmovdqa xmmword ptr [r8+16], xmm0

	vmovdqa xmm0, xmmword ptr [rdx-176]
	vmovdqa xmmword ptr [r8], xmm0

; end of decryptionRoundKeysSchedule
	
	vpxor xmm5, xmm5, xmm5				; secure clearing of registers
	vpxor xmm4, xmm4, xmm4
	vpxor xmm0, xmm0, xmm0
	xor rax, rax
	xor rcx, rcx
	xor rdx, rdx
	
	ret
Aes128AvxKeySchedule ENDP

Aes192AvxKeySchedule PROC
; rcx:  key: xmmword ptr
; rdx: roundKeys: xmmword ptr
; r8: decryptionRoundKeys : xmmword ptr

	vmovdqu xmm0, xmmword ptr [rcx]
	movq xmm1, qword ptr [rcx+16]
	vmovdqa xmmword ptr [rdx], xmm0
	movq qword ptr [rdx+16], xmm1
	add rdx, 24

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

	vmovdqu xmmword ptr [rdx], xmm0
	vmovdqu xmmword ptr [rdx+16], xmm1
	add rdx, 24
	ret

; end of aux

decryptionRoundKeysSchedule:
	vmovdqa xmm0, xmmword ptr [rdx-24]
	vmovdqa xmmword ptr [r8+192], xmm0

	aesimc xmm0, xmmword ptr [rdx-40]
	vmovdqa xmmword ptr [r8+176], xmm0
	aesimc xmm0, xmmword ptr [rdx-56]
	vmovdqa xmmword ptr [r8+160], xmm0
	aesimc xmm0, xmmword ptr [rdx-72]
	vmovdqa xmmword ptr [r8+144], xmm0
	aesimc xmm0, xmmword ptr [rdx-88]
	vmovdqa xmmword ptr [r8+128], xmm0
	aesimc xmm0, xmmword ptr [rdx-104]
	vmovdqa xmmword ptr [r8+112], xmm0
	aesimc xmm0, xmmword ptr [rdx-120]
	vmovdqa xmmword ptr [r8+96], xmm0
	aesimc xmm0, xmmword ptr [rdx-136]
	vmovdqa xmmword ptr [r8+80], xmm0
	aesimc xmm0, xmmword ptr [rdx-152]
	vmovdqa xmmword ptr [r8+64], xmm0
	aesimc xmm0, xmmword ptr [rdx-168]
	vmovdqa xmmword ptr [r8+48], xmm0
	aesimc xmm0, xmmword ptr [rdx-184]
	vmovdqa xmmword ptr [r8+32], xmm0
	aesimc xmm0, xmmword ptr [rdx-200]
	vmovdqa xmmword ptr [r8+16], xmm0

	vmovdqa xmm0, xmmword ptr [rdx-216]
	vmovdqa xmmword ptr [r8], xmm0

; end of decryptionRoundKeysSchedule

	vpxor xmm5, xmm5, xmm5				; secure clearing of registers
	vpxor xmm4, xmm4, xmm4
	vpxor xmm1, xmm1, xmm1
	vpxor xmm0, xmm0, xmm0
	xor rax, rax
	xor rcx, rcx
	xor rdx, rdx

	ret
Aes192AvxKeySchedule ENDP

Aes256AvxKeySchedule PROC
; rcx:  key: xmmword ptr
; rdx: roundKeys: xmmword ptr
; r8: decryptionRoundKeys : xmmword ptr

	vmovdqu xmm0, xmmword ptr [rcx]
	vmovdqu xmm1, xmmword ptr [rcx+16]
	vmovdqa xmmword ptr [rdx], xmm0
	vmovdqa xmmword ptr [rdx+16], xmm1
	add rdx, 32

	mov r9b, 0
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
	mov r9b, 1
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

	vmovdqu xmmword ptr [rdx], xmm0
	add rdx, 16

	cmp r9b, 1
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

	vmovdqu xmmword ptr [rdx], xmm1
	add rdx, 16
@@:
	ret

; end of aux

decryptionRoundKeysSchedule:
	vmovdqa xmm0, xmmword ptr [rdx-16]
	vmovdqa xmmword ptr [r8+224], xmm0

	aesimc xmm0, xmmword ptr [rdx-32]
	vmovdqa xmmword ptr [r8+208], xmm0
	aesimc xmm0, xmmword ptr [rdx-48]
	vmovdqa xmmword ptr [r8+192], xmm0
	aesimc xmm0, xmmword ptr [rdx-64]
	vmovdqa xmmword ptr [r8+176], xmm0
	aesimc xmm0, xmmword ptr [rdx-80]
	vmovdqa xmmword ptr [r8+160], xmm0
	aesimc xmm0, xmmword ptr [rdx-96]
	vmovdqa xmmword ptr [r8+144], xmm0
	aesimc xmm0, xmmword ptr [rdx-112]
	vmovdqa xmmword ptr [r8+128], xmm0
	aesimc xmm0, xmmword ptr [rdx-128]
	vmovdqa xmmword ptr [r8+112], xmm0
	aesimc xmm0, xmmword ptr [rdx-144]
	vmovdqa xmmword ptr [r8+96], xmm0
	aesimc xmm0, xmmword ptr [rdx-160]
	vmovdqa xmmword ptr [r8+80], xmm0
	aesimc xmm0, xmmword ptr [rdx-176]
	vmovdqa xmmword ptr [r8+64], xmm0
	aesimc xmm0, xmmword ptr [rdx-192]
	vmovdqa xmmword ptr [r8+48], xmm0
	aesimc xmm0, xmmword ptr [rdx-208]
	vmovdqa xmmword ptr [r8+32], xmm0
	aesimc xmm0, xmmword ptr [rdx-224]
	vmovdqa xmmword ptr [r8+16], xmm0

	vmovdqa xmm0, xmmword ptr [rdx-240]
	vmovdqa xmmword ptr [r8], xmm0

; end of decryptionRoundKeysSchedule

	vpxor xmm5, xmm5, xmm5				; secure clearing of registers
	vpxor xmm4, xmm4, xmm4
	vpxor xmm1, xmm1, xmm1
	vpxor xmm0, xmm0, xmm0
	xor rax, rax
	xor rcx, rcx
	xor rdx, rdx

	ret
Aes256AvxKeySchedule ENDP

Aes128NiKeySchedule PROC
; rcx:  key: xmmword ptr
; rdx: roundKeys: xmmword ptr
; r8: decryptionRoundKeys : xmmword ptr

	movdqu xmm0, xmmword ptr [rcx]
	movdqa xmmword ptr [rdx], xmm0
	add rdx, 16

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

	movdqa xmmword ptr [rdx], xmm0
	add rdx, 16
	ret

; end of aux

decryptionRoundKeysSchedule:
	movdqa xmm0, xmmword ptr [rdx-16]
	movdqa xmmword ptr [r8+160], xmm0

	aesimc xmm0, xmmword ptr [rdx-32]
	movdqa xmmword ptr [r8+144], xmm0
	aesimc xmm0, xmmword ptr [rdx-48]
	movdqa xmmword ptr [r8+128], xmm0
	aesimc xmm0, xmmword ptr [rdx-64]
	movdqa xmmword ptr [r8+112], xmm0
	aesimc xmm0, xmmword ptr [rdx-80]
	movdqa xmmword ptr [r8+96], xmm0
	aesimc xmm0, xmmword ptr [rdx-96]
	movdqa xmmword ptr [r8+80], xmm0
	aesimc xmm0, xmmword ptr [rdx-112]
	movdqa xmmword ptr [r8+64], xmm0
	aesimc xmm0, xmmword ptr [rdx-128]
	movdqa xmmword ptr [r8+48], xmm0
	aesimc xmm0, xmmword ptr [rdx-144]
	movdqa xmmword ptr [r8+32], xmm0
	aesimc xmm0, xmmword ptr [rdx-160]
	movdqa xmmword ptr [r8+16], xmm0

	movdqa xmm0, xmmword ptr [rdx-176]
	movdqa xmmword ptr [r8], xmm0

; end of decryptionRoundKeysSchedule

	pxor xmm5, xmm5					; secure clearing of registers
	pxor xmm4, xmm4
	pxor xmm0, xmm0
	xor rax, rax
	xor rcx, rcx
	xor rdx, rdx

	ret
Aes128NiKeySchedule ENDP

Aes192NiKeySchedule PROC
; rcx:  key: xmmword ptr
; rdx: roundKeys: xmmword ptr
; r8: decryptionRoundKeys : xmmword ptr

	movdqu xmm0, xmmword ptr [rcx]
	movq xmm1, qword ptr [rcx+16]
	movdqa xmmword ptr [rdx], xmm0
	movq qword ptr [rdx+16], xmm1
	add rdx, 24

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

	movdqu xmmword ptr [rdx], xmm0
	movdqu xmmword ptr [rdx+16], xmm1
	add rdx, 24
	ret

; end of aux

decryptionRoundKeysSchedule:
	movdqa xmm0, xmmword ptr [rdx-24]
	movdqa xmmword ptr [r8+192], xmm0

	aesimc xmm0, xmmword ptr [rdx-40]
	movdqa xmmword ptr [r8+176], xmm0
	aesimc xmm0, xmmword ptr [rdx-56]
	movdqa xmmword ptr [r8+160], xmm0
	aesimc xmm0, xmmword ptr [rdx-72]
	movdqa xmmword ptr [r8+144], xmm0
	aesimc xmm0, xmmword ptr [rdx-88]
	movdqa xmmword ptr [r8+128], xmm0
	aesimc xmm0, xmmword ptr [rdx-104]
	movdqa xmmword ptr [r8+112], xmm0
	aesimc xmm0, xmmword ptr [rdx-120]
	movdqa xmmword ptr [r8+96], xmm0
	aesimc xmm0, xmmword ptr [rdx-136]
	movdqa xmmword ptr [r8+80], xmm0
	aesimc xmm0, xmmword ptr [rdx-152]
	movdqa xmmword ptr [r8+64], xmm0
	aesimc xmm0, xmmword ptr [rdx-168]
	movdqa xmmword ptr [r8+48], xmm0
	aesimc xmm0, xmmword ptr [rdx-184]
	movdqa xmmword ptr [r8+32], xmm0
	aesimc xmm0, xmmword ptr [rdx-200]
	movdqa xmmword ptr [r8+16], xmm0

	movdqa xmm0, xmmword ptr [rdx-216]
	movdqa xmmword ptr [r8], xmm0

; end of decryptionRoundKeysSchedule

	pxor xmm5, xmm5					; secure clearing of registers
	pxor xmm4, xmm4
	pxor xmm1, xmm1
	pxor xmm0, xmm0
	xor rax, rax
	xor rcx, rcx
	xor rdx, rdx

	ret
Aes192NiKeySchedule ENDP

Aes256NiKeySchedule PROC
; rcx:  key: xmmword ptr
; rdx: roundKeys: xmmword ptr
; r8: decryptionRoundKeys : xmmword ptr

	movdqu xmm0, xmmword ptr [rcx]
	movdqu xmm1, xmmword ptr [rcx+16]
	movdqa xmmword ptr [rdx], xmm0
	movdqa xmmword ptr [rdx+16], xmm1
	add rdx, 32

	mov r9b, 0
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
	mov r9b, 1
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

	movdqu xmmword ptr [rdx], xmm0
	add rdx, 16

	cmp r9b, 1
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

	vmovdqu xmmword ptr [rdx], xmm1
	add rdx, 16
@@:
	ret

; end of aux

decryptionRoundKeysSchedule:
	movdqa xmm0, xmmword ptr [rdx-16]
	movdqa xmmword ptr [r8+224], xmm0

	aesimc xmm0, xmmword ptr [rdx-32]
	movdqa xmmword ptr [r8+208], xmm0
	aesimc xmm0, xmmword ptr [rdx-48]
	movdqa xmmword ptr [r8+192], xmm0
	aesimc xmm0, xmmword ptr [rdx-64]
	movdqa xmmword ptr [r8+176], xmm0
	aesimc xmm0, xmmword ptr [rdx-80]
	movdqa xmmword ptr [r8+160], xmm0
	aesimc xmm0, xmmword ptr [rdx-96]
	movdqa xmmword ptr [r8+144], xmm0
	aesimc xmm0, xmmword ptr [rdx-112]
	movdqa xmmword ptr [r8+128], xmm0
	aesimc xmm0, xmmword ptr [rdx-128]
	movdqa xmmword ptr [r8+112], xmm0
	aesimc xmm0, xmmword ptr [rdx-144]
	movdqa xmmword ptr [r8+96], xmm0
	aesimc xmm0, xmmword ptr [rdx-160]
	movdqa xmmword ptr [r8+80], xmm0
	aesimc xmm0, xmmword ptr [rdx-176]
	movdqa xmmword ptr [r8+64], xmm0
	aesimc xmm0, xmmword ptr [rdx-192]
	movdqa xmmword ptr [r8+48], xmm0
	aesimc xmm0, xmmword ptr [rdx-208]
	movdqa xmmword ptr [r8+32], xmm0
	aesimc xmm0, xmmword ptr [rdx-224]
	movdqa xmmword ptr [r8+16], xmm0

	movdqa xmm0, xmmword ptr [rdx-240]
	movdqa xmmword ptr [r8], xmm0

; end of decryptionRoundKeysSchedule

	pxor xmm5, xmm5					; secure clearing of registers
	pxor xmm4, xmm4
	pxor xmm4, xmm4
	pxor xmm0, xmm0
	xor rax, rax
	xor rcx, rcx
	xor rdx, rdx

	ret
Aes256NiKeySchedule ENDP

Aes128AvxEncryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	vmovdqu xmm0, xmmword ptr [rdx]
	vxorps xmm0, xmm0, xmmword ptr [rcx] ; input ^ roundKeys[0]
	aesenc xmm0, xmmword ptr [rcx + 16]
	aesenc xmm0, xmmword ptr [rcx + 32]
	aesenc xmm0, xmmword ptr [rcx + 48]
	aesenc xmm0, xmmword ptr [rcx + 64]
	aesenc xmm0, xmmword ptr [rcx + 80]
	aesenc xmm0, xmmword ptr [rcx + 96]
	aesenc xmm0, xmmword ptr [rcx + 112]
	aesenc xmm0, xmmword ptr [rcx + 128]
	aesenc xmm0, xmmword ptr [rcx + 144]
	aesenclast xmm0, xmmword ptr [rcx + 160]
	vmovdqu xmmword ptr [r8], xmm0

	ret
Aes128AvxEncryptBlock ENDP

Aes192AvxEncryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	vmovdqu xmm0, xmmword ptr [rdx]
	vxorps xmm0, xmm0, xmmword ptr [rcx] ; input ^ roundKeys[0]
	aesenc xmm0, xmmword ptr [rcx + 16]
	aesenc xmm0, xmmword ptr [rcx + 32]
	aesenc xmm0, xmmword ptr [rcx + 48]
	aesenc xmm0, xmmword ptr [rcx + 64]
	aesenc xmm0, xmmword ptr [rcx + 80]
	aesenc xmm0, xmmword ptr [rcx + 96]
	aesenc xmm0, xmmword ptr [rcx + 112]
	aesenc xmm0, xmmword ptr [rcx + 128]
	aesenc xmm0, xmmword ptr [rcx + 144]
	aesenc xmm0, xmmword ptr [rcx + 160]
	aesenc xmm0, xmmword ptr [rcx + 176]
	aesenclast xmm0, xmmword ptr [rcx + 192]
	vmovdqu xmmword ptr [r8], xmm0

	ret
Aes192AvxEncryptBlock ENDP

Aes256AvxEncryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	vmovdqu xmm0, xmmword ptr [rdx]
	vxorps xmm0, xmm0, xmmword ptr [rcx] ; input ^ roundKeys[0]
	aesenc xmm0, xmmword ptr [rcx + 16]
	aesenc xmm0, xmmword ptr [rcx + 32]
	aesenc xmm0, xmmword ptr [rcx + 48]
	aesenc xmm0, xmmword ptr [rcx + 64]
	aesenc xmm0, xmmword ptr [rcx + 80]
	aesenc xmm0, xmmword ptr [rcx + 96]
	aesenc xmm0, xmmword ptr [rcx + 112]
	aesenc xmm0, xmmword ptr [rcx + 128]
	aesenc xmm0, xmmword ptr [rcx + 144]
	aesenc xmm0, xmmword ptr [rcx + 160]
	aesenc xmm0, xmmword ptr [rcx + 176]
	aesenc xmm0, xmmword ptr [rcx + 192]
	aesenc xmm0, xmmword ptr [rcx + 208]
	aesenclast xmm0, xmmword ptr [rcx + 224]
	vmovdqu xmmword ptr [r8], xmm0

	ret
Aes256AvxEncryptBlock ENDP

Aes128AvxDecryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	vmovdqu xmm0, xmmword ptr [rdx]
	vxorps xmm0, xmm0, xmmword ptr [rcx + 160] ; input ^ roundKeys[11]
	aesdec xmm0, xmmword ptr [rcx + 144]
	aesdec xmm0, xmmword ptr [rcx + 128]
	aesdec xmm0, xmmword ptr [rcx + 112]
	aesdec xmm0, xmmword ptr [rcx + 96]
	aesdec xmm0, xmmword ptr [rcx + 80]
	aesdec xmm0, xmmword ptr [rcx + 64]
	aesdec xmm0, xmmword ptr [rcx + 48]
	aesdec xmm0, xmmword ptr [rcx + 32]
	aesdec xmm0, xmmword ptr [rcx + 16]
	aesdeclast xmm0, xmmword ptr [rcx]
	vmovdqu xmmword ptr [r8], xmm0

	ret
Aes128AvxDecryptBlock ENDP

Aes192AvxDecryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	vmovdqu xmm0, xmmword ptr [rdx]
	vxorps xmm0, xmm0, xmmword ptr [rcx + 192] ; input ^ roundKeys[13]
	aesdec xmm0, xmmword ptr [rcx + 176]
	aesdec xmm0, xmmword ptr [rcx + 160]
	aesdec xmm0, xmmword ptr [rcx + 144]
	aesdec xmm0, xmmword ptr [rcx + 128]
	aesdec xmm0, xmmword ptr [rcx + 112]
	aesdec xmm0, xmmword ptr [rcx + 96]
	aesdec xmm0, xmmword ptr [rcx + 80]
	aesdec xmm0, xmmword ptr [rcx + 64]
	aesdec xmm0, xmmword ptr [rcx + 48]
	aesdec xmm0, xmmword ptr [rcx + 32]
	aesdec xmm0, xmmword ptr [rcx + 16]
	aesdeclast xmm0, xmmword ptr [rcx]
	vmovdqu xmmword ptr [r8], xmm0

	ret
Aes192AvxDecryptBlock ENDP

Aes256AvxDecryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	vmovdqu xmm0, xmmword ptr [rdx]
	vxorps xmm0, xmm0, xmmword ptr [rcx + 224] ; input ^ roundKeys[15]
	aesdec xmm0, xmmword ptr [rcx + 208]
	aesdec xmm0, xmmword ptr [rcx + 192]
	aesdec xmm0, xmmword ptr [rcx + 176]
	aesdec xmm0, xmmword ptr [rcx + 160]
	aesdec xmm0, xmmword ptr [rcx + 144]
	aesdec xmm0, xmmword ptr [rcx + 128]
	aesdec xmm0, xmmword ptr [rcx + 112]
	aesdec xmm0, xmmword ptr [rcx + 96]
	aesdec xmm0, xmmword ptr [rcx + 80]
	aesdec xmm0, xmmword ptr [rcx + 64]
	aesdec xmm0, xmmword ptr [rcx + 48]
	aesdec xmm0, xmmword ptr [rcx + 32]
	aesdec xmm0, xmmword ptr [rcx + 16]
	aesdeclast xmm0, xmmword ptr [rcx]
	vmovdqu xmmword ptr [r8], xmm0

	ret
Aes256AvxDecryptBlock ENDP



Aes128NiEncryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	movdqu xmm0, xmmword ptr [rdx]
	xorps xmm0, xmmword ptr [rcx] ; input ^ roundKeys[0]
	aesenc xmm0, xmmword ptr [rcx + 16]
	aesenc xmm0, xmmword ptr [rcx + 32]
	aesenc xmm0, xmmword ptr [rcx + 48]
	aesenc xmm0, xmmword ptr [rcx + 64]
	aesenc xmm0, xmmword ptr [rcx + 80]
	aesenc xmm0, xmmword ptr [rcx + 96]
	aesenc xmm0, xmmword ptr [rcx + 112]
	aesenc xmm0, xmmword ptr [rcx + 128]
	aesenc xmm0, xmmword ptr [rcx + 144]
	aesenclast xmm0, xmmword ptr [rcx + 160]
	movdqu xmmword ptr [r8], xmm0

	ret
Aes128NiEncryptBlock ENDP

Aes192NiEncryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	movdqu xmm0, xmmword ptr [rdx]
	xorps xmm0, xmmword ptr [rcx] ; input ^ roundKeys[0]
	aesenc xmm0, xmmword ptr [rcx + 16]
	aesenc xmm0, xmmword ptr [rcx + 32]
	aesenc xmm0, xmmword ptr [rcx + 48]
	aesenc xmm0, xmmword ptr [rcx + 64]
	aesenc xmm0, xmmword ptr [rcx + 80]
	aesenc xmm0, xmmword ptr [rcx + 96]
	aesenc xmm0, xmmword ptr [rcx + 112]
	aesenc xmm0, xmmword ptr [rcx + 128]
	aesenc xmm0, xmmword ptr [rcx + 144]
	aesenc xmm0, xmmword ptr [rcx + 160]
	aesenc xmm0, xmmword ptr [rcx + 176]
	aesenclast xmm0, xmmword ptr [rcx + 192]
	movdqu xmmword ptr [r8], xmm0

	ret
Aes192NiEncryptBlock ENDP

Aes256NiEncryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	movdqu xmm0, xmmword ptr [rdx]
	xorps xmm0, xmmword ptr [rcx] ; input ^ roundKeys[0]
	aesenc xmm0, xmmword ptr [rcx + 16]
	aesenc xmm0, xmmword ptr [rcx + 32]
	aesenc xmm0, xmmword ptr [rcx + 48]
	aesenc xmm0, xmmword ptr [rcx + 64]
	aesenc xmm0, xmmword ptr [rcx + 80]
	aesenc xmm0, xmmword ptr [rcx + 96]
	aesenc xmm0, xmmword ptr [rcx + 112]
	aesenc xmm0, xmmword ptr [rcx + 128]
	aesenc xmm0, xmmword ptr [rcx + 144]
	aesenc xmm0, xmmword ptr [rcx + 160]
	aesenc xmm0, xmmword ptr [rcx + 176]
	aesenc xmm0, xmmword ptr [rcx + 192]
	aesenc xmm0, xmmword ptr [rcx + 208]
	aesenclast xmm0, xmmword ptr [rcx + 224]
	movdqu xmmword ptr [r8], xmm0

	ret
Aes256NiEncryptBlock ENDP


Aes128NiDecryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	movdqu xmm0, xmmword ptr [rdx]
	xorps xmm0, xmmword ptr [rcx + 160] ; input ^ roundKeys[11]
	aesdec xmm0, xmmword ptr [rcx + 144]
	aesdec xmm0, xmmword ptr [rcx + 128]
	aesdec xmm0, xmmword ptr [rcx + 112]
	aesdec xmm0, xmmword ptr [rcx + 96]
	aesdec xmm0, xmmword ptr [rcx + 80]
	aesdec xmm0, xmmword ptr [rcx + 64]
	aesdec xmm0, xmmword ptr [rcx + 48]
	aesdec xmm0, xmmword ptr [rcx + 32]
	aesdec xmm0, xmmword ptr [rcx + 16]
	aesdeclast xmm0, xmmword ptr [rcx]
	movdqu xmmword ptr [r8], xmm0

	ret
Aes128NiDecryptBlock ENDP

Aes192NiDecryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	movdqu xmm0, xmmword ptr [rdx]
	xorps xmm0, xmmword ptr [rcx + 192] ; input ^ roundKeys[13]
	aesdec xmm0, xmmword ptr [rcx + 176]
	aesdec xmm0, xmmword ptr [rcx + 160]
	aesdec xmm0, xmmword ptr [rcx + 144]
	aesdec xmm0, xmmword ptr [rcx + 128]
	aesdec xmm0, xmmword ptr [rcx + 112]
	aesdec xmm0, xmmword ptr [rcx + 96]
	aesdec xmm0, xmmword ptr [rcx + 80]
	aesdec xmm0, xmmword ptr [rcx + 64]
	aesdec xmm0, xmmword ptr [rcx + 48]
	aesdec xmm0, xmmword ptr [rcx + 32]
	aesdec xmm0, xmmword ptr [rcx + 16]
	aesdeclast xmm0, xmmword ptr [rcx]
	movdqu xmmword ptr [r8], xmm0

	ret
Aes192NiDecryptBlock ENDP

Aes256NiDecryptBlock PROC
; rcx: roundKeys: xmmword ptr
; rdx: input: xmmword ptr
; r8: output: xmmword ptr

	movdqu xmm0, xmmword ptr [rdx]
	xorps xmm0, xmmword ptr [rcx + 224] ; input ^ roundKeys[15]
	aesdec xmm0, xmmword ptr [rcx + 208]
	aesdec xmm0, xmmword ptr [rcx + 192]
	aesdec xmm0, xmmword ptr [rcx + 176]
	aesdec xmm0, xmmword ptr [rcx + 160]
	aesdec xmm0, xmmword ptr [rcx + 144]
	aesdec xmm0, xmmword ptr [rcx + 128]
	aesdec xmm0, xmmword ptr [rcx + 112]
	aesdec xmm0, xmmword ptr [rcx + 96]
	aesdec xmm0, xmmword ptr [rcx + 80]
	aesdec xmm0, xmmword ptr [rcx + 64]
	aesdec xmm0, xmmword ptr [rcx + 48]
	aesdec xmm0, xmmword ptr [rcx + 32]
	aesdec xmm0, xmmword ptr [rcx + 16]
	aesdeclast xmm0, xmmword ptr [rcx]
	movdqu xmmword ptr [r8], xmm0

	ret
Aes256NiDecryptBlock ENDP


SecureClearRegistersUsedInAes PROC
	call SecureClearXmm0
	call SecureClearRax
	ret
SecureClearRegistersUsedInAes ENDP

SecureClearXmm0:
	xorpd xmm0, xmm0
	ret

SecureClearRax:
	xor rax, rax
	ret

END
