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

#include <stdio.h>
#include <cuda.h>

#include "config.h"


__constant__ uint target[4];
__constant__ uint k[64];
__constant__ uint rconst[16];


static const uint k_cpu[64] =
{
	0xd76aa478,	0xe8c7b756,	0x242070db,	0xc1bdceee,
	0xf57c0faf,	0x4787c62a,	0xa8304613,	0xfd469501,
	0x698098d8,	0x8b44f7af,	0xffff5bb1,	0x895cd7be,
	0x6b901122,	0xfd987193,	0xa679438e,	0x49b40821,

	0xf61e2562,	0xc040b340,	0x265e5a51,	0xe9b6c7aa,
	0xd62f105d,	0x2441453,	0xd8a1e681,	0xe7d3fbc8,
	0x21e1cde6,	0xc33707d6,	0xf4d50d87,	0x455a14ed,
	0xa9e3e905,	0xfcefa3f8,	0x676f02d9,	0x8d2a4c8a,

	0xfffa3942,	0x8771f681,	0x6d9d6122,	0xfde5380c,
	0xa4beea44,	0x4bdecfa9,	0xf6bb4b60,	0xbebfbc70,
	0x289b7ec6,	0xeaa127fa,	0xd4ef3085,	0x4881d05,
	0xd9d4d039,	0xe6db99e5,	0x1fa27cf8,	0xc4ac5665,

	0xf4292244,	0x432aff97,	0xab9423a7,	0xfc93a039,
	0x655b59c3,	0x8f0ccc92,	0xffeff47d,	0x85845dd1,
	0x6fa87e4f,	0xfe2ce6e0,	0xa3014314,	0x4e0811a1,
	0xf7537e82,	0xbd3af235,	0x2ad7d2bb,	0xeb86d391,
};

static const uint rconst_cpu[16] = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};


__device__ inline uint leftrotate (uint x, uint c)
{
	return (x << c) | (x >> (32-c));
}

__device__ inline void step (const uint i, const uint f, const uint g, uint &a, uint &b, uint &c, uint &d, const uint *w)
{
	uint temp = d;
	d = c;
	c = b;
	b = b + leftrotate((a + f + k[i] + w[g]), rconst[(i / 16) * 4 + i % 4]);
	a = temp;
}

__device__ inline void md5 (const uint * w, uint &a, uint &b, uint &c, uint &d)
{
	const uint a0 = 0x67452301;
	const uint b0 = 0xEFCDAB89;
	const uint c0 = 0x98BADCFE;
	const uint d0 = 0x10325476;
	
	a = a0;
	b = b0;
	c = c0;
	d = d0;
	
	uint f, g, i = 0;
	for(; i != 16; i++)
	{
		f = (b & c) | ((~b) & d);
		g = i;
		step(i, f, g, a, b, c, d, w);
	}
	
	for(; i != 32; i++)
	{
		f = (d & b) | ((~d) & c);
		g = (5*i + 1) % 16;
		step(i, f, g, a, b, c, d, w);
	}
	
	for(; i != 48; i++)
	{
		f = b ^ c ^ d;
		g = (3*i + 5) % 16;
		step(i, f, g, a, b, c, d, w);
	}
	
	for(; i != 64; i++)
	{
		f = c ^ (b | (~d));
		g = (7*i) % 16;
		step(i, f, g, a, b, c, d, w);
	}
	
	a += a0;
	b += b0;
	c += c0;
	d += d0;
}

__device__ inline void mdset_f (uint &a, uint &b, uint &c, uint &d, const uint x, const uint s, const uint ac)
{
	a += (((b) & (c)) | ((~b) & (d))) + x + ac;
	a = (a << s) | (a >> (32 - s));
	a += b;
}

__device__ inline void mdset_g (uint &a, uint &b, uint &c, uint &d, const uint x, const uint s, const uint ac)
{
	a += (((b) & (d)) | ((c) & (~d))) + x + ac;
	a = (a << s) | (a >> (32 - s));
	a += b;
}

__device__ inline void mdset_h (uint &a, uint &b, uint &c, uint &d, const uint x, const uint s, const uint ac)
{
	a += ((b) ^ (c) ^ (d)) + x + ac;
	a = (a << s) | (a >> (32 - s));
	a += b;
}

__device__ inline void mdset_i (uint &a, uint &b, uint &c, uint &d, const uint x, const uint s, const uint ac)
{
	a += ((c) ^ ((b) | (~d))) + x + ac;
	a = (a << s) | (a >> (32 - s));
	a += b;
}

__device__ inline void md5v2 (const uint * in, uint &a, uint &b, uint &c, uint &d)
{
	const uint a0 = 0x67452301;
	const uint b0 = 0xEFCDAB89;
	const uint c0 = 0x98BADCFE;
	const uint d0 = 0x10325476;
	
	a = a0;
	b = b0;
	c = c0;
	d = d0;
	
	mdset_f(a, b, c, d, in[0],  rconst[0], k[0]);
	mdset_f(d, a, b, c, in[1],  rconst[1], k[1]);
	mdset_f(c, d, a, b, in[2],  rconst[2], k[2]);
	mdset_f(b, c, d, a, in[3],  rconst[3], k[3]);
	mdset_f(a, b, c, d, in[4],  rconst[0], k[4]);
	mdset_f(d, a, b, c, in[5],  rconst[1], k[5]);
	mdset_f(c, d, a, b, in[6],  rconst[2], k[6]);
	mdset_f(b, c, d, a, in[7],  rconst[3], k[7]);
	mdset_f(a, b, c, d, in[8],  rconst[0], k[8]);
	mdset_f(d, a, b, c, in[9],  rconst[1], k[9]);
	mdset_f(c, d, a, b, in[10], rconst[2], k[10]);
	mdset_f(b, c, d, a, in[11], rconst[3], k[11]);
	mdset_f(a, b, c, d, in[12], rconst[0], k[12]);
	mdset_f(d, a, b, c, in[13], rconst[1], k[13]);
	mdset_f(c, d, a, b, in[14], rconst[2], k[14]);
	mdset_f(b, c, d, a, in[15], rconst[3], k[15]);
	
	mdset_g(a, b, c, d, in[1],  rconst[4], k[16]);
	mdset_g(d, a, b, c, in[6],  rconst[5], k[17]);
	mdset_g(c, d, a, b, in[11], rconst[6], k[18]);
	mdset_g(b, c, d, a, in[0],  rconst[7], k[19]);
	mdset_g(a, b, c, d, in[5],  rconst[4], k[20]);
	mdset_g(d, a, b, c, in[10], rconst[5], k[21]);
	mdset_g(c, d, a, b, in[15], rconst[6], k[22]);
	mdset_g(b, c, d, a, in[4],  rconst[7], k[23]);
	mdset_g(a, b, c, d, in[9],  rconst[4], k[24]);
	mdset_g(d, a, b, c, in[14], rconst[5], k[25]);
	mdset_g(c, d, a, b, in[3],  rconst[6], k[26]);
	mdset_g(b, c, d, a, in[8],  rconst[7], k[27]);
	mdset_g(a, b, c, d, in[13], rconst[4], k[28]);
	mdset_g(d, a, b, c, in[2],  rconst[5], k[29]);
	mdset_g(c, d, a, b, in[7],  rconst[6], k[30]);
	mdset_g(b, c, d, a, in[12], rconst[7], k[31]);
	
	mdset_h(a, b, c, d, in[5],  rconst[8], k[32]);
	mdset_h(d, a, b, c, in[8],  rconst[9], k[33]);
	mdset_h(c, d, a, b, in[11], rconst[10], k[34]);
	mdset_h(b, c, d, a, in[14], rconst[11], k[35]);
	mdset_h(a, b, c, d, in[1],  rconst[8], k[36]);
	mdset_h(d, a, b, c, in[4],  rconst[9], k[37]);
	mdset_h(c, d, a, b, in[7],  rconst[10], k[38]);
	mdset_h(b, c, d, a, in[10], rconst[11], k[39]);
	mdset_h(a, b, c, d, in[13], rconst[8], k[40]);
	mdset_h(d, a, b, c, in[0],  rconst[9], k[41]);
	mdset_h(c, d, a, b, in[3],  rconst[10], k[42]);
	mdset_h(b, c, d, a, in[6],  rconst[11], k[43]);
	mdset_h(a, b, c, d, in[9],  rconst[8], k[44]);
	mdset_h(d, a, b, c, in[12], rconst[9], k[45]);
	mdset_h(c, d, a, b, in[15], rconst[10], k[46]);
	mdset_h(b, c, d, a, in[2],  rconst[11], k[47]);
	
	mdset_i(a, b, c, d, in[0],  rconst[12], k[48]);
	mdset_i(d, a, b, c, in[7],  rconst[13], k[49]);
	mdset_i(c, d, a, b, in[14], rconst[14], k[50]);
	mdset_i(b, c, d, a, in[5],  rconst[15], k[51]);
	mdset_i(a, b, c, d, in[12], rconst[12], k[52]);
	mdset_i(d, a, b, c, in[3],  rconst[13], k[53]);
	mdset_i(c, d, a, b, in[10], rconst[14], k[54]);
	mdset_i(b, c, d, a, in[1],  rconst[15], k[55]);
	mdset_i(a, b, c, d, in[8],  rconst[12], k[56]);
	mdset_i(d, a, b, c, in[15], rconst[13], k[57]);
	mdset_i(c, d, a, b, in[6],  rconst[14], k[58]);
	mdset_i(b, c, d, a, in[13], rconst[15], k[59]);
	mdset_i(a, b, c, d, in[4],  rconst[12], k[60]);
	mdset_i(d, a, b, c, in[11], rconst[13], k[61]);
	mdset_i(c, d, a, b, in[2],  rconst[14],  k[62]);
	mdset_i(b, c, d, a, in[9],  rconst[15], k[63]);
	
	a += a0;
	b += b0;
	c += c0;
	d += d0;
}

__global__ void _gpu_md5_bruteforce (uint * words, int * res)
{
	int idx = blockIdx.x * blockDim.x + threadIdx.x;
	uint a, b, c, d, in[16];
	int i;
	
	for (i = 0; i < 16; i++)
		in[i] = words[idx * 16 + i];
	
	md5(in, a, b, c, d);
	
	if (target[0] == a && target[1] == b && target[2] == c && target[3] == d)
		(* res) = idx;
}

extern "C"
{
void get_gpu_props (int * prop)
{
	cudaDeviceProp deviceProp;
	int nDevCount;
	
	cudaGetDeviceCount(&nDevCount);
	prop[0] = nDevCount;
	if (nDevCount > 0)
	{
		if (cudaSuccess != cudaGetDeviceProperties(&deviceProp, 0))
		{
			prop[1] = 64;
			prop[2] = 128;
			return;
		}
		prop[1] = deviceProp.multiProcessorCount;
		prop[2] = deviceProp.maxThreadsPerBlock;
	}
}

int * d_res;
uint * d_words;

void gpu_init (unsigned int * abcd, unsigned int dsize)
{
	cudaMemcpyToSymbol(target, abcd, sizeof(target));
	cudaMemcpyToSymbol(k, k_cpu, sizeof(k_cpu));
	cudaMemcpyToSymbol(rconst, rconst_cpu, sizeof(rconst_cpu));
	cudaMalloc((void **) &d_res, sizeof(* d_res));
	cudaMalloc((void **) &d_words, dsize);
}

int gpu_md5_bruteforce (uint * words, int * prop, unsigned int dsize)
{
	int blocks, threads_per_block, res;
	
	cudaMemcpy(d_words, words, dsize, cudaMemcpyHostToDevice);
	
	res = -1;
	cudaMemcpy(d_res, &res, sizeof(res), cudaMemcpyHostToDevice);
	
	blocks = prop[1];
	threads_per_block = prop[2];
	_gpu_md5_bruteforce <<<blocks, threads_per_block>>> (d_words, d_res);
	cudaThreadSynchronize();
	cudaMemcpy(&res, d_res, sizeof(res), cudaMemcpyDeviceToHost);
	
	return res;
}
}
