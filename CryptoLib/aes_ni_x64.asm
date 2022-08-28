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

;state SEGMENT align(64) 'data'

;savedstate dq 1024 DUP(0)

;state ENDS

.data
align 16

xmmStorage dq 32 DUP(0)

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

PrepareXmmRegistersForAes PROC
; rcx: roundsKeys: ptr xmmword
; rdx: cipherType: dword
; r8:  encryptionMode: CryptoMode

movaps xmmword ptr [xmmStorage], xmm0
	movaps xmmword ptr [xmmStorage+16], xmm1
	movaps xmmword ptr [xmmStorage+32], xmm2
	movaps xmmword ptr [xmmStorage+48], xmm3
	movaps xmmword ptr [xmmStorage+64], xmm4
	movaps xmmword ptr [xmmStorage+80], xmm5
	movaps xmmword ptr [xmmStorage+96], xmm6
	movaps xmmword ptr [xmmStorage+112], xmm7
	movaps xmmword ptr [xmmStorage+128], xmm8
	movaps xmmword ptr [xmmStorage+144], xmm9
	movaps xmmword ptr [xmmStorage+160], xmm10
	movaps xmmword ptr [xmmStorage+176], xmm11
	cmp dl, 2									; 2 is AES128_cipher_type
	je @f
	movaps xmmword ptr [xmmStorage+192], xmm12
	movaps xmmword ptr [xmmStorage+208], xmm13
	cmp dl, 3									; 3 is AES192_cipher_type
	je @f
	movaps xmmword ptr [xmmStorage+224], xmm14
	movaps xmmword ptr [xmmStorage+240], xmm15
@@:
	movaps xmm1, xmmword ptr [rcx]
	movaps xmm2, xmmword ptr [rcx + 16]
	movaps xmm3, xmmword ptr [rcx + 32]
	movaps xmm4, xmmword ptr [rcx + 48]
	movaps xmm5, xmmword ptr [rcx + 64]
	movaps xmm6, xmmword ptr [rcx + 80]
	movaps xmm7, xmmword ptr [rcx + 96]
	movaps xmm8, xmmword ptr [rcx + 112]
	movaps xmm9, xmmword ptr [rcx + 128]
	movaps xmm10, xmmword ptr [rcx + 144]
	movaps xmm11, xmmword ptr [rcx + 160]
	cmp r8b, 0									; aesimc using only for decryption
	jz @f
	aesimc xmm2, xmm2							; the first and the last rounds keys should not be applied to aesmic
	aesimc xmm3, xmm3
	aesimc xmm4, xmm4
	aesimc xmm5, xmm5
	aesimc xmm6, xmm6
	aesimc xmm7, xmm7
	aesimc xmm8, xmm8
	aesimc xmm9, xmm9
	aesimc xmm10, xmm10
@@:
	cmp dl, 2									; 2 is AES128_cipher_type
	je @f
	movaps xmm12, xmmword ptr [rcx + 176]
	movaps xmm13, xmmword ptr [rcx + 192]
	cmp r8b, 0
	jz @f
	aesimc xmm11, xmm11
	aesimc xmm12, xmm12
@@:
	cmp dl, 3									; 3 is AES192_cipher_type
	je @f
	movaps xmm14, xmmword ptr [rcx + 208]
	movaps xmm15, xmmword ptr [rcx + 224]
	cmp r8b, 0
	jz @f
	aesimc xmm13, xmm13
	aesimc xmm14, xmm14
@@:
	ret
PrepareXmmRegistersForAes ENDP

RestoreXmmRegistersFromAes PROC, cipherType: dword
	movaps xmm0, xmmword ptr [xmmStorage]
	movaps xmm1, xmmword ptr [xmmStorage + 16]
	movaps xmm2, xmmword ptr [xmmStorage + 32]
	movaps xmm3, xmmword ptr [xmmStorage + 48]
	movaps xmm4, xmmword ptr [xmmStorage + 64]
	movaps xmm5, xmmword ptr [xmmStorage + 80]
	movaps xmm6, xmmword ptr [xmmStorage + 96]
	movaps xmm7, xmmword ptr [xmmStorage + 112]
	movaps xmm8, xmmword ptr [xmmStorage + 128]
	movaps xmm9, xmmword ptr [xmmStorage + 144]
	movaps xmm10, xmmword ptr [xmmStorage + 160]
	movaps xmm11, xmmword ptr [xmmStorage + 176]
	cmp cipherType, 2									; 2 is AES128_cipher_type
	je @f
	movaps xmm12, xmmword ptr [xmmStorage + 192]
	movaps xmm13, xmmword ptr [xmmStorage + 208]
	cmp cipherType, 3									; 3 is AES192_cipher_type
	je @f
	movaps xmm14, xmmword ptr [xmmStorage + 224]
	movaps xmm15, xmmword ptr [xmmStorage + 240]
@@:
	ret
RestoreXmmRegistersFromAes ENDP

Aes128EncryptBlockNi PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm1 ; input ^ roundsKeys[0]
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	aesenc xmm0, xmm7
	aesenc xmm0, xmm8
	aesenc xmm0, xmm9
	aesenc xmm0, xmm10
	aesenclast xmm0, xmm11
	movaps xmmword ptr [r8], xmm0
	ret
Aes128EncryptBlockNi ENDP

Aes192EncryptBlockNi PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm1 ; input ^ roundsKeys[0]
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	aesenc xmm0, xmm7
	aesenc xmm0, xmm8
	aesenc xmm0, xmm9
	aesenc xmm0, xmm10
	aesenc xmm0, xmm11
	aesenc xmm0, xmm12
	aesenclast xmm0, xmm13
	movaps xmmword ptr [r8], xmm0
	ret
Aes192EncryptBlockNi ENDP

Aes256EncryptBlockNi PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm1 ; input ^ roundsKeys[0]
	aesenc xmm0, xmm2
	aesenc xmm0, xmm3
	aesenc xmm0, xmm4
	aesenc xmm0, xmm5
	aesenc xmm0, xmm6
	aesenc xmm0, xmm7
	aesenc xmm0, xmm8
	aesenc xmm0, xmm9
	aesenc xmm0, xmm10
	aesenc xmm0, xmm11
	aesenc xmm0, xmm12
	aesenc xmm0, xmm13
	aesenc xmm0, xmm14
	aesenclast xmm0, xmm15
	movaps xmmword ptr [r8], xmm0
	ret
Aes256EncryptBlockNi ENDP

Aes128DecryptBlockNi PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm11 ; input ^ roundsKeys[11]
	aesdec xmm0, xmm10
	aesdec xmm0, xmm9
	aesdec xmm0, xmm8
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdeclast xmm0, xmm1
	movaps xmmword ptr [r8], xmm0
	ret
Aes128DecryptBlockNi ENDP

Aes192DecryptBlockNi PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm13 ; input ^ roundsKeys[13]
	aesdec xmm0, xmm12
	aesdec xmm0, xmm11
	aesdec xmm0, xmm10
	aesdec xmm0, xmm9
	aesdec xmm0, xmm8
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdeclast xmm0, xmm1
	movaps xmmword ptr [r8], xmm0
	ret
Aes192DecryptBlockNi ENDP

Aes256DecryptBlockNi PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm15 ; input ^ roundsKeys[15]
	aesdec xmm0, xmm14
	aesdec xmm0, xmm13
	aesdec xmm0, xmm12
	aesdec xmm0, xmm11
	aesdec xmm0, xmm10
	aesdec xmm0, xmm9
	aesdec xmm0, xmm8
	aesdec xmm0, xmm7
	aesdec xmm0, xmm6
	aesdec xmm0, xmm5
	aesdec xmm0, xmm4
	aesdec xmm0, xmm3
	aesdec xmm0, xmm2
	aesdeclast xmm0, xmm1
	movaps xmmword ptr [r8], xmm0
	ret
Aes256DecryptBlockNi ENDP

END
