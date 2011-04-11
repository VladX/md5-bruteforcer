/*
 * Copyright (c) 2010 http://vladx.net/
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#if defined(__i386) || defined(__i386__) || defined(_M_IX86)
 #define md5_block_asm md5_block_asm_i586
#elif defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
 #define md5_block_asm md5_block_asm_x86_64
#elif defined(__ia64) || defined(__ia64__) || defined(_M_IA64)
 #define md5_block_asm md5_block_asm_ia64
#else
 #error "Unsupported arch"
#endif

typedef struct
{
	unsigned int a, b, c, d;
} md5_asm_c;

void md5_block_asm (md5_asm_c * c, void * data, size_t num);
