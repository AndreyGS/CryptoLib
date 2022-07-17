# Crypto library

Current library is build on pure C.
At the moment it under development.
For now it includes several types of symmetric ciphers, hashing functions, XOF's, PRF's (HMAC only) and KDF (PBKDF2 only).

#### Full list of currently supported algorithms:
* Block ciphers (list of operation modes - ECB, CBC, CFB, OFB, CTR):
	DES,\
	3DES,\
	AES128,\
	AES192,\
	AES256
* Hash functions:
	SHA1,\
	SHA_224,\
	SHA_256,\
	SHA_384,\
	SHA_512_224,\
	SHA_512_256,\
	SHA_512,\
	SHA3_224,\
	SHA3_256,\
	SHA3_384,\
	SHA3_512
* XOF's:
	SHAKE128,\
	SHAKE256
* PRF's:
	HMAC_SHA1,\
	HMAC_SHA_224,\
	HMAC_SHA_256,\
	HMAC_SHA_384,\
	HMAC_SHA_512_224,\
	HMAC_SHA_512_256,\
	HMAC_SHA_512,\
	HMAC_SHA3_224,\
	HMAC_SHA3_256,\
	HMAC_SHA3_384,\
	HMAC_SHA3_512
* KDF
	PBKDF2_HMAC_SHA1,\
	PBKDF2_HMAC_SHA_224,\
	PBKDF2_HMAC_SHA_256,\
	PBKDF2_HMAC_SHA_384,\
	PBKDF2_HMAC_SHA_512_224,\
	PBKDF2_HMAC_SHA_512_256,\
	PBKDF2_HMAC_SHA_512,\
	PBKDF2_HMAC_SHA3_224,\
	PBKDF2_HMAC_SHA3_256,\
	PBKDF2_HMAC_SHA3_384,\
	PBKDF2_HMAC_SHA3_512
		
Public interface is located in crypto.h.
All functions grouped by categories.

For block ciphers, hashing, XOF and PRF you should call functions with Init prefix first, to allocate state.
Then you should call ProcessingByBlockCipher for block ciphers, and GetHash/GetXof/GetPrf for hashing, XOF and PRF respectively as many times as it takes.
Final processing input is marked with finalize flag.
If you wish to reinitialize one or the other state parameters you should call Reset prefixed functions.
At the very end you call Free prefixed functions to secure clear and free current state.

GetPbkdf2 and AddPadding functions are using without any required additional actions.

There is a Doxygen comments in crypto.h for all of them.
The full example of using can be found in unit tests.
You can test it by yourself if you wish.

## What can be done next?
- Optimization for AES with AES-NI support implementing.
- RSA module.
- Specialized functions for ciphers keys generation.

## License

Copyright (c) 2020 Andrey Grabov-Smetankin

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.