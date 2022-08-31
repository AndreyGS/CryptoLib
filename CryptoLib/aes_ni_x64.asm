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

PrepareXmmRegistersForAesAvx PROC
; rcx: roundKeys: ptr xmmword
; rdx: cipherType: dword
; r8:  encryptionMode: CryptoMode
; r9:  xmmRegsBuffer: ptr xmmword
	movaps xmmword ptr [r9], xmm0
	movaps xmmword ptr [r9+16], xmm1
	movaps xmmword ptr [r9+32], xmm2
	movaps xmmword ptr [r9+48], xmm3
	movaps xmmword ptr [r9+64], xmm4
	movaps xmmword ptr [r9+80], xmm5
	movaps xmmword ptr [r9+96], xmm6
	movaps xmmword ptr [r9+112], xmm7
	movaps xmmword ptr [r9+128], xmm8
	movaps xmmword ptr [r9+144], xmm9
	movaps xmmword ptr [r9+160], xmm10
	movaps xmmword ptr [r9+176], xmm11
	cmp dl, 2									; 2 is AES128_cipher_type
	je @f
	movaps xmmword ptr [r9+192], xmm12
	movaps xmmword ptr [r9+208], xmm13
	cmp dl, 3									; 3 is AES192_cipher_type
	je @f
	movaps xmmword ptr [r9+224], xmm14
	movaps xmmword ptr [r9+240], xmm15
@@:
	movaps xmm1, xmmword ptr [rcx]
	cmp r8b, 1                                  ; if decryption jump forward
	jz @f
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
@@:
	cmp r8b, 0                                  ; if encryption jump forward
	jz @f
	aesimc xmm2, xmmword ptr [rcx + 16]         ; the first and the last rounds keys should not be applied to aesmic
	aesimc xmm3, xmmword ptr [rcx + 32]
	aesimc xmm4, xmmword ptr [rcx + 48]
	aesimc xmm5, xmmword ptr [rcx + 64]
	aesimc xmm6, xmmword ptr [rcx + 80]
	aesimc xmm7, xmmword ptr [rcx + 96]
	aesimc xmm8, xmmword ptr [rcx + 112]
	aesimc xmm9, xmmword ptr [rcx + 128]
	aesimc xmm10, xmmword ptr [rcx + 144]
@@:
	cmp dl, 2									; 2 is AES128_cipher_type
	je finalregister
	cmp r8b, 1
	jz @f
	movaps xmm12, xmmword ptr [rcx + 176]
	movaps xmm13, xmmword ptr [rcx + 192]
@@:
	cmp r8b, 0
	jz @f
	aesimc xmm11, xmmword ptr [rcx + 160]
	aesimc xmm12, xmmword ptr [rcx + 176]
@@:
	cmp dl, 3									; 3 is AES192_cipher_type
	je finalregister
	cmp r8b, 1
	jz @f
	movaps xmm14, xmmword ptr [rcx + 208]
	movaps xmm15, xmmword ptr [rcx + 224]
@@:
	cmp r8b, 0
	jz finalregister
	aesimc xmm13, xmmword ptr [rcx + 192]
	aesimc xmm14, xmmword ptr [rcx + 208]
finalregister:
	cmp r8b, 0                                  ; if encryption - jump to exit
	jz exit
	cmp dl, 2                                   ; if not AES128 - jump forward
	jnz @f
	movaps xmm11, xmmword ptr [rcx + 160]
	jmp exit
@@:
	cmp dl, 3                                   ; if not AES192 - jump forward
	jnz @f
	movaps xmm13, xmmword ptr [rcx + 192]
	jmp exit
@@:
	movaps xmm15, xmmword ptr [rcx + 224]
exit:
	ret
PrepareXmmRegistersForAesAvx ENDP

RestoreXmmRegistersFromAesAvx PROC
; rcx: cipherType: dword
; rdx: xmmRegsBuffer: ptr xmmword
	movaps xmm0, xmmword ptr [rdx]
	movaps xmm1, xmmword ptr [rdx + 16]
	movaps xmm2, xmmword ptr [rdx + 32]
	movaps xmm3, xmmword ptr [rdx + 48]
	movaps xmm4, xmmword ptr [rdx + 64]
	movaps xmm5, xmmword ptr [rdx + 80]
	movaps xmm6, xmmword ptr [rdx + 96]
	movaps xmm7, xmmword ptr [rdx + 112]
	movaps xmm8, xmmword ptr [rdx + 128]
	movaps xmm9, xmmword ptr [rdx + 144]
	movaps xmm10, xmmword ptr [rdx + 160]
	movaps xmm11, xmmword ptr [rdx + 176]
	cmp rcx, 2									; 2 is AES128_cipher_type
	je @f
	movaps xmm12, xmmword ptr [rdx + 192]
	movaps xmm13, xmmword ptr [rdx + 208]
	cmp rcx, 3									; 3 is AES192_cipher_type
	je @f
	movaps xmm14, xmmword ptr [rdx + 224]
	movaps xmm15, xmmword ptr [rdx + 240]
@@:
	ret
RestoreXmmRegistersFromAesAvx ENDP

PrepareXmmRegistersForAesNiOnly PROC
; rcx: roundKeys: ptr xmmword
; rdx: cipherType: dword
; r8:  encryptionMode: CryptoMode
; r9:  xmmRegsBuffer: ptr xmmword
	movaps xmmword ptr [r9], xmm0
	movaps xmmword ptr [r9+16], xmm1
	movaps xmmword ptr [r9+32], xmm2
	movaps xmmword ptr [r9+48], xmm3
	movaps xmmword ptr [r9+64], xmm4
	movaps xmmword ptr [r9+80], xmm5
	movaps xmmword ptr [r9+96], xmm6
	movaps xmmword ptr [r9+112], xmm7

	movaps xmm1, xmmword ptr [rcx]
	movaps xmm2, xmmword ptr [rcx + 16]
	movaps xmm3, xmmword ptr [rcx + 32]
	movaps xmm4, xmmword ptr [rcx + 48]
	movaps xmm5, xmmword ptr [rcx + 64]
	movaps xmm6, xmmword ptr [rcx + 80]
	movaps xmm7, xmmword ptr [rcx + 96]

	cmp r8b, 0									; aesimc using only for decryption
	jz @f
	aesimc xmm2, xmm2							; the first and the last rounds keys should not be applied to aesmic
	aesimc xmm3, xmm3
	aesimc xmm4, xmm4
	aesimc xmm5, xmm5
	aesimc xmm6, xmm6
	aesimc xmm7, xmm7
	movaps xmmword ptr [r9+240], xmm7
	aesimc xmm8, xmmword ptr [rcx + 112]
	movaps xmmword ptr [r9+128], xmm7
	aesimc xmm9, xmmword ptr [rcx + 128]
	movaps xmmword ptr [r9+144], xmm7
	aesimc xmm10, xmmword ptr [rcx + 144]
	movaps xmmword ptr [r9+160], xmm7

@@:
	cmp dl, 2									; 2 is AES128_cipher_type
	je exit
	movaps xmm12, xmmword ptr [rcx + 176]
	movaps xmm13, xmmword ptr [rcx + 192]
	cmp r8b, 0
	jz @f
	aesimc xmm11, xmm11
	aesimc xmm12, xmm12
@@:
	cmp dl, 3									; 3 is AES192_cipher_type
	je exit
	movaps xmm14, xmmword ptr [rcx + 208]
	movaps xmm15, xmmword ptr [rcx + 224]
	cmp r8b, 0
	jz exit
	aesimc xmm13, xmm13
	aesimc xmm14, xmm14
exit:
	ret
PrepareXmmRegistersForAesNiOnly ENDP

Aes128AvxEncryptBlock PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm1 ; input ^ roundKeys[0]
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
Aes128AvxEncryptBlock ENDP

Aes192AvxEncryptBlock PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm1 ; input ^ roundKeys[0]
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
Aes192AvxEncryptBlock ENDP

Aes256AvxEncryptBlock PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm1 ; input ^ roundKeys[0]
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
Aes256AvxEncryptBlock ENDP

Aes128AvxDecryptBlock PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm11 ; input ^ roundKeys[11]
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
Aes128AvxDecryptBlock ENDP

Aes192AvxDecryptBlock PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm13 ; input ^ roundKeys[13]
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
Aes192AvxDecryptBlock ENDP

Aes256AvxDecryptBlock PROC
; rcx: stub
; rdx: input: ptr xmmword
; r8: output: ptr xmmword

	movaps xmm0, xmmword ptr [rdx]
	xorps xmm0, xmm15 ; input ^ roundKeys[15]
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
Aes256AvxDecryptBlock ENDP



Aes128NiEncryptBlock PROC
	ret
Aes128NiEncryptBlock ENDP

Aes192NiEncryptBlock PROC
	ret
Aes192NiEncryptBlock ENDP

Aes256NiEncryptBlock PROC
	ret
Aes256NiEncryptBlock ENDP


Aes128NiDecryptBlock PROC
	ret
Aes128NiDecryptBlock ENDP

Aes192NiDecryptBlock PROC
	ret
Aes192NiDecryptBlock ENDP

Aes256NiDecryptBlock PROC
	ret
Aes256NiDecryptBlock ENDP

END
