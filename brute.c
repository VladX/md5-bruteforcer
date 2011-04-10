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
#include <stdlib.h>
#include <pthread.h>
#include <strings.h>
#include <string.h>

#include "config.h"

#ifdef OPENSSL_MD5
 #include <openssl/md5.h>
#else
 #include "md5.h"
#endif


typedef struct
{
	unsigned char thread_id;
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;
} thread_args;

void inc_iter (unsigned char * i, unsigned int * l)
{
	unsigned int len = * l, n, c;
	
	for (n = len - 1;; n--)
	{
		if ((i[n] > 47 && i[n] < 57) || (i[n] > 64 && i[n] < 90) || (i[n] > 96 && i[n] < 122))
		{
			i[n]++;
			break;
		}
		else if (i[n] == 57)
		{
			i[n] = 'A';
			break;
		}
		else if (i[n] == 90)
		{
			i[n] = 'a';
			break;
		}
		else if (i[n] == 122)
		{
			i[n] = '0';
			if (n == 0)
			{
				i[len+1] = '\0';
				for (c = 0; c < len; c++)
					i[len-c] = i[len-c-1];
				i[0] = '0';
				(* l)++;
				break;
			}
		}
	}
}

void print_res (const char * pass)
{
	printf("-------------\nPass - %s\n-------------\n", pass);
	exit(0);
}

#if GPU_THREADS
void * bruteforce_gpu (void * args)
{
	unsigned char i[I_SIZE];
	unsigned int * words, * tmp;
	unsigned long counter;
	unsigned long long iters_total;
	unsigned int abcd[4], i_len, it, size, dsize;
	int prop[3], res;
	
	abcd[0] = ((thread_args *) args)->a;
	abcd[1] = ((thread_args *) args)->b;
	abcd[2] = ((thread_args *) args)->c;
	abcd[3] = ((thread_args *) args)->d;
	
	get_gpu_props(prop);
	
	if (prop[0] < 1)
	{
		puts("Не найдено ни одного ускорителя с поддержкой CUDA!");
		exit(1);
	}
	else
		printf("=================\nCUDA Devices: %d\n=================\n", prop[0]);
	
	size = prop[1] * prop[2];
	dsize = size * 16 * sizeof(unsigned int);
	
	gpu_init(abcd, dsize);
	
	words = (unsigned int *) malloc(dsize);
	memset(words, 0, dsize);
	
	for (it = 0; it < ((thread_args *) args)->thread_id; it++)
		i[it] = '0';
	i[it] = '\0';
	
	i_len = strlen((const char *) i);
	
	iters_total = 0;
	
	while (1)
	{
		for (counter = 0, tmp = words; counter < size; counter++, tmp += 16)
		{
			memcpy(tmp, i, i_len);
			((unsigned char *) tmp)[i_len] = 0x80;
			tmp[14] = i_len * 8;
			inc_iter(i, &i_len);
			for (it = 0; it < i_len; it++)
				if (i[it] != '0')
					break;
			
		}
		if (iters_total % 2000 == 0)
			puts(i);
		res = gpu_md5_bruteforce(words, prop, dsize);
		if (res != -1)
		{
			unsigned char * cw = (unsigned char *) words + res * 64;
			while (* cw != 0x80)
				cw++;
			* cw = '\0';
			cw = (char *) words + res * 64;
			print_res(cw);
		}
		iters_total++;
	}
}
#endif

static unsigned int print_freq = 1000000;

void * bruteforce (void * args)
{
	unsigned char i[I_SIZE];
	unsigned int a = ((thread_args *) args)->a;
	unsigned int b = ((thread_args *) args)->b;
	unsigned int c = ((thread_args *) args)->c;
	unsigned int d = ((thread_args *) args)->d;
	#ifdef OPENSSL_MD5
	MD5_CTX md_ctx;
	unsigned char hash[16];
	#else
	unsigned char pw[64];
	unsigned int * in = (unsigned int *) pw, ai, bi, ci, di;
	memset(pw, 0, sizeof(pw));
	a -= 0x67452301;
	b -= 0xEFCDAB89;
	c -= 0x98BADCFE;
	d -= 0x10325476;
	#endif
	unsigned long counter;
	unsigned int i_len, it;
	
	for (it = 0; it < ((thread_args *) args)->thread_id; it++)
		i[it] = '0';
	i[it] = '\0';
	
	i_len = strlen((const char *) i);
	
	for (counter = 1;; counter++)
	{
		#ifdef OPENSSL_MD5
		MD5_Init(&md_ctx);
		MD5_Update(&md_ctx, i, i_len);
		MD5_Final(hash, &md_ctx);
		if (a == md_ctx.A && b == md_ctx.B && c == md_ctx.C && d == md_ctx.D)
			print_res((const char *) i);
		#else
		memcpy(pw, i, i_len);
		pw[i_len] = 0x80;
		in[14] = i_len * 8;
		
		/* Ron Rivest's MD5 C Implementation */
		
		ai = 0x67452301;
		bi = 0xEFCDAB89;
		ci = 0x98BADCFE;
		di = 0x10325476;
		
		FF ( ai, bi, ci, di, in[0], S11, 3614090360);
		FF ( di, ai, bi, ci, in[1], S12, 3905402710);
		FF ( ci, di, ai, bi, in[2], S13, 606105819);
		FF ( bi, ci, di, ai, in[3], S14, 3250441966);
		FF ( ai, bi, ci, di, in[4], S11, 4118548399);
		FF ( di, ai, bi, ci, in[5], S12, 1200080426);
		FF ( ci, di, ai, bi, in[6], S13, 2821735955);
		FF ( bi, ci, di, ai, in[7], S14, 4249261313);
		FF ( ai, bi, ci, di, in[8], S11, 1770035416);
		FF ( di, ai, bi, ci, in[9], S12, 2336552879);
		FF ( ci, di, ai, bi, in[10], S13, 4294925233);
		FF ( bi, ci, di, ai, in[11], S14, 2304563134);
		FF ( ai, bi, ci, di, in[12], S11, 1804603682);
		FF ( di, ai, bi, ci, in[13], S12, 4254626195);
		FF ( ci, di, ai, bi, in[14], S13, 2792965006);
		FF ( bi, ci, di, ai, in[15], S14, 1236535329);
		
		GG ( ai, bi, ci, di, in[1], S21, 4129170786);
		GG ( di, ai, bi, ci, in[6], S22, 3225465664);
		GG ( ci, di, ai, bi, in[11], S23, 643717713);
		GG ( bi, ci, di, ai, in[0], S24, 3921069994);
		GG ( ai, bi, ci, di, in[5], S21, 3593408605);
		GG ( di, ai, bi, ci, in[10], S22, 38016083);
		GG ( ci, di, ai, bi, in[15], S23, 3634488961);
		GG ( bi, ci, di, ai, in[4], S24, 3889429448);
		GG ( ai, bi, ci, di, in[9], S21, 568446438);
		GG ( di, ai, bi, ci, in[14], S22, 3275163606);
		GG ( ci, di, ai, bi, in[3], S23, 4107603335);
		GG ( bi, ci, di, ai, in[8], S24, 1163531501);
		GG ( ai, bi, ci, di, in[13], S21, 2850285829);
		GG ( di, ai, bi, ci, in[2], S22, 4243563512);
		GG ( ci, di, ai, bi, in[7], S23, 1735328473);
		GG ( bi, ci, di, ai, in[12], S24, 2368359562);
		
		HH ( ai, bi, ci, di, in[5], S31, 4294588738);
		HH ( di, ai, bi, ci, in[8], S32, 2272392833);
		HH ( ci, di, ai, bi, in[11], S33, 1839030562);
		HH ( bi, ci, di, ai, in[14], S34, 4259657740);
		HH ( ai, bi, ci, di, in[1], S31, 2763975236);
		HH ( di, ai, bi, ci, in[4], S32, 1272893353);
		HH ( ci, di, ai, bi, in[7], S33, 4139469664);
		HH ( bi, ci, di, ai, in[10], S34, 3200236656);
		HH ( ai, bi, ci, di, in[13], S31, 681279174);
		HH ( di, ai, bi, ci, in[0], S32, 3936430074);
		HH ( ci, di, ai, bi, in[3], S33, 3572445317);
		HH ( bi, ci, di, ai, in[6], S34, 76029189);
		HH ( ai, bi, ci, di, in[9], S31, 3654602809);
		HH ( di, ai, bi, ci, in[12], S32, 3873151461);
		HH ( ci, di, ai, bi, in[15], S33, 530742520);
		HH ( bi, ci, di, ai, in[2], S34, 3299628645);
		
		II ( ai, bi, ci, di, in[0], S41, 4096336452);
		II ( di, ai, bi, ci, in[7], S42, 1126891415);
		II ( ci, di, ai, bi, in[14], S43, 2878612391);
		II ( bi, ci, di, ai, in[5], S44, 4237533241);
		II ( ai, bi, ci, di, in[12], S41, 1700485571);
		II ( di, ai, bi, ci, in[3], S42, 2399980690);
		II ( ci, di, ai, bi, in[10], S43, 4293915773);
		II ( bi, ci, di, ai, in[1], S44, 2240044497);
		II ( ai, bi, ci, di, in[8], S41, 1873313359);
		II ( di, ai, bi, ci, in[15], S42, 4264355552);
		II ( ci, di, ai, bi, in[6], S43, 2734768916);
		II ( bi, ci, di, ai, in[13], S44, 1309151649);
		II ( ai, bi, ci, di, in[4], S41, 4149444226);
		/* 'a' больше меняться не будет. Если сейчас она не равна исходному значению - считать дальше нет смысла. */
		if (a == ai)
		{
			II ( di, ai, bi, ci, in[11], S42, 3174756917);
			II ( ci, di, ai, bi, in[2], S43, 718787259);
			II ( bi, ci, di, ai, in[9], S44, 3951481745);
			if (b == bi && c == ci && d == di)
				print_res((const char *) i);
		}
		#endif
		if (counter % print_freq == 0)
			puts((const char *) i);
		inc_iter(i, &i_len);
		#if THREADS > 1
		for (it = 0; it < i_len; it++)
			if (i[it] != '0')
				break;
		if (it == i_len)
		{
			while (it < i_len + THREADS - 1)
			{
				i[it] = '0';
				it++;
			}
			i[it] = '\0';
			i_len += THREADS - 1;
		}
		#endif
	}
}

void init (char * hashedpass)
{
	pthread_t threads[THREADS];
	thread_args args[THREADS];
	unsigned char srchash[16], it;
	char c1, c2;
	
	for (it = 0; it < 32; it += 2)
	{
		c1 = hashedpass[it] - '0';
		if (c1 > 9)
			c1 = hashedpass[it] - 'a' + 10;
		c2 = hashedpass[it + 1] - '0';
		if (c2 > 9)
			c2 = hashedpass[it + 1] - 'a' + 10;
		srchash[it / 2] = c1 * 16 + c2;
	}
	
	print_freq = print_freq * THREADS;
	
	for (it = 0; it < THREADS; it++)
	{
		args[it].thread_id = it + 1;
		args[it].a = ((unsigned int *) &srchash)[0];
		args[it].b = ((unsigned int *) &srchash)[1];
		args[it].c = ((unsigned int *) &srchash)[2];
		args[it].d = ((unsigned int *) &srchash)[3];
		#if GPU_THREADS
		if (it == THREADS - GPU_THREADS)
		{
			pthread_create(&threads[it], NULL, bruteforce_gpu, (void *) &args[it]);
			break;
		}
		else
		#endif
		pthread_create(&threads[it], NULL, bruteforce, (void *) &args[it]);
	}
	
	pthread_join(threads[0], NULL);
}

int main (int argc, char ** argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "Использование: %s MD5-хэш\nUsage: %s MD5-hash\n", argv[0], argv[0]);
		return 1;
	}
	
	if (strlen(argv[1]) != 32)
	{
		fprintf(stderr, "Ошибка: Хэш должен быть длиной 32 символа!\nError: MD5 hexdecimal hash should be no longer than 32 characters!\n");
		return 1;
	}
	
	init(argv[1]);
	return 0;
}
