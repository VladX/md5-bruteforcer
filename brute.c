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
#include <sys/time.h>

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

static unsigned long long total_computed_hashes = 0, start_time_usec = 0;

static unsigned char chars_table_09AZaz[256] = {
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', '0', '0', '0', '0', '0', '0',
'0', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', '0', '0', '0', '0', '0',
'0', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '0', '0', '0', '0', '0'
};

static unsigned char chars_table_09AZ[256] = {
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', '0', '0', '0', '0', '0', '0',
'0', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '0', '0', '0', '0', '0',
'0', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '0', '0', '0', '0', '0'
};

static unsigned char chars_table_09az[256] = {
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', '0', '0', '0', '0', '0', '0',
'0', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', '0', '0', '0', '0', '0',
'0', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '0', '0', '0', '0', '0'
};

static unsigned char chars_table_09[256] = {
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '0', '0', '0', '0', '0', '0',
'0', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', '0', '0', '0', '0', '0',
'0', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '0', '0', '0', '0', '0'
};

static unsigned char * chars_table;

void inc_iter (unsigned char ** ptr_i, unsigned int * l)
{
	register unsigned int len = * l, n;
	register unsigned char * i = * ptr_i;
	
	for (n = len - 1;; n--)
	{
		i[n] = chars_table[i[n]];
		if (i[n] != '0')
			break;
		if (n == 0)
		{
			(* ptr_i)--;
			(* ptr_i)[0] = '0';
			(* l)++;
			break;
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
	unsigned char __i[I_SIZE];
	unsigned char * i = __i + (sizeof(__i) - (((thread_args *) args)->thread_id + 1));
	unsigned int * words, * tmp;
	register unsigned long counter;
	register unsigned long long iters_total;
	unsigned int abcd[4], i_len, it, size, dsize;
	int prop[3], res;
	struct timeval ttv;
	
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
			inc_iter(&i, &i_len);
			for (it = 0; it < i_len; it++)
				if (i[it] != '0')
					break;
			if (it == i_len)
			{
				i -= THREADS - 1;
				i_len += THREADS - 1;
				memset(i, '0', i_len);
				i[i_len] = '\0';
			}
		}
		if (iters_total % 2000 == 0)
		{
			(void) gettimeofday(&ttv, NULL);
			printf("%s, speed=%llu\n", (const char *) i, (total_computed_hashes / ((ttv.tv_sec * 1000000L + ttv.tv_usec) - start_time_usec)));
		}
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
		total_computed_hashes += size;
	}
}
#endif

static unsigned int print_freq = 1000000;

void * bruteforce (void * args)
{
	unsigned char __i[I_SIZE];
	unsigned char * i = __i + (sizeof(__i) - (((thread_args *) args)->thread_id + 1));
	unsigned int a = ((thread_args *) args)->a;
	unsigned int b = ((thread_args *) args)->b;
	unsigned int c = ((thread_args *) args)->c;
	unsigned int d = ((thread_args *) args)->d;
	#ifdef OPENSSL_MD5
	MD5_CTX md_ctx;
	unsigned char hash[16];
	#else
	md5_asm_c md5asmc;
	unsigned char pw[64];
	unsigned int * in = (unsigned int *) pw;
	memset(pw, 0, sizeof(pw));
	#endif
	register unsigned long counter;
	unsigned int i_len, it;
	struct timeval ttv;
	
	for (it = 0; it < ((thread_args *) args)->thread_id; it++)
		i[it] = '0';
	i[it] = '\0';
	
	i_len = strlen((const char *) i);
	
	for (counter = 1;; counter++, total_computed_hashes++)
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
		
		md5asmc.a = 0x67452301;
		md5asmc.b = 0xEFCDAB89;
		md5asmc.c = 0x98BADCFE;
		md5asmc.d = 0x10325476;
		md5_block_asm(&md5asmc, pw, 1);
		if (md5asmc.a == a && md5asmc.b == b && md5asmc.c == c && md5asmc.d == d)
			print_res((const char *) i);
		#endif
		if (counter % print_freq == 0)
		{
			(void) gettimeofday(&ttv, NULL);
			printf("%s, speed=%llu\n", (const char *) i, (total_computed_hashes / ((ttv.tv_sec * 1000000L + ttv.tv_usec) - start_time_usec)));
		}
		inc_iter(&i, &i_len);
		#if THREADS > 1
		for (it = 0; it < i_len; it++)
			if (i[it] != '0')
				break;
		if (it == i_len)
		{
			i -= THREADS - 1;
			i_len += THREADS - 1;
			memset(i, '0', i_len);
			i[i_len] = '\0';
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
	struct timeval tv;
	(void) gettimeofday(&tv, NULL);
	start_time_usec = tv.tv_sec * 1000000L + tv.tv_usec;
	
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
	char * hash = NULL, * charset = NULL;
	
	if (argc < 2 || argc == 3)
	{
		fprintf(stderr, "Usage: %s [-c charset number] MD5-hash\nExample: %s -c 1 827ccb0eea8a706c4c34a16891f84e7b\n", argv[0], argv[0]);
		return 1;
	}
	
	int i;
	
	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-c") == 0)
		{
			i++;
			charset = argv[i];
		}
		else
			hash = argv[i];
	}
	
	if (charset)
	{
		int ch = atoi(charset);
		if (ch < 1)
		{
			fprintf(stderr, "Error: Invalid charset number!\n");
			return 1;
		}
		switch (ch)
		{
			case 1:
				chars_table = chars_table_09;
				break;
			case 2:
				chars_table = chars_table_09az;
				break;
			case 3:
				chars_table = chars_table_09AZ;
				break;
			case 4:
				chars_table = chars_table_09AZaz;
				break;
			default:
				fprintf(stderr, "Error: Unknown charset number - %d!\n", ch);
				return 1;
		}
	}
	else
		chars_table = chars_table_09AZaz;
	
	if (strlen(hash) != 32)
	{
		fprintf(stderr, "Ошибка: Хэш должен быть длиной 32 символа!\nError: MD5 hexdecimal hash should be no longer than 32 characters!\n");
		return 1;
	}
	
	init(hash);
	return 0;
}
