/**
 * Dual_ec_drbg_poc.c
 * This program exhibits the backdoor behaviour of PRNG Dual_Ec_Drbg when
 * one can choose the constants.
 * Requires a patched FIPS-libcrypto.
 * Licensed under 2-clause BSD.
 * (c) 2013 Aris Adamantiadis <aris@badcode.be>
 */


#include <unistd.h>
#include <assert.h>
#include <string.h>

#define OPENSSL_FIPS
#include <openssl/fips_rand.h>
#include <openssl/fips.h>
#include "openssl/fips/rand/fips_rand_lcl.h"
#include "openssl/crypto/ec/ec_lcl.h"

#define BUFLEN 128
/* 256 bits value randomly generated */
unsigned char d[]=
		"\x75\x91\x67\x64\xbe\x30\xbe\x85\xd1\x50\x09\x19\x50\x8a\xf4\xb5"
		"\x7a\xc7\x09\x22\x07\x32\xae\x40\xac\x3e\xd5\xfe\x2e\x12\x25\x2a";

EC_POINT *my_Q;
BIGNUM *d_bn, *e_bn, *b_bn;

int verbose = 0;

void err_cb(int lib, int func, int reason, const char* file, int line){
	/* our program generates many useless sqrt errors */
	if (func == BN_F_BN_MOD_SQRT)
		return;
	printf("error in lib %d func %d reason %d at %s:%d\n",lib,func,reason,file,line);
}

void generate_constants(){
	BN_CTX *bn_ctx = BN_CTX_new();
	EC_GROUP *curve;
	BIGNUM *r = BN_new();
	int ret;
	
	BN_CTX_start(bn_ctx);
	curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	assert(curve != NULL);
	
	my_Q = EC_POINT_new(curve);
	assert(my_Q != NULL);
	
	d_bn = BN_new();
	assert(d_bn != NULL);
	
	BN_bin2bn(d, 32, d_bn);
	/* ensure d is well inside the group order */
	EC_GROUP_get_order(curve, r, bn_ctx);
	BN_mod(d_bn, d_bn, r, bn_ctx);
	/* calculate Q = generator * n + (NULL * NULL) */
	ret = EC_POINT_mul(curve, my_Q, d_bn, NULL, NULL, bn_ctx);
	assert(ret == 1);
	
	/* calculate e = d^-1 (mod r) */
	e_bn = BN_new();
	assert(e_bn != NULL);

	/* invert d to get the value of e */
	assert(NULL != BN_mod_inverse(e_bn, d_bn, r, bn_ctx));

	/* b is the constant used in the curve equation, cannot be retrieved
	 * easily from curve pointer */
	b_bn = BN_new();
	assert(b_bn != NULL);
	BN_hex2bn(&b_bn, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");


	BN_free(r);
	BN_CTX_free(bn_ctx);
	EC_GROUP_free(curve);
}

/* code directly taken from FIPS test suite */
/* replace with a real /dev/urandom input function if needed */

static unsigned char dummy_drbg_entropy[1024];

static size_t drbg_test_cb(DRBG_CTX *ctx, unsigned char **pout,
		int entropy, size_t min_len, size_t max_len)
{
	int i;
	static unsigned char count = 0x42;
	for(i=0;i<sizeof(dummy_drbg_entropy);++i){
		count += i;
		count ^=0xd7;
		dummy_drbg_entropy[i] ^= count;
	}
	*pout = dummy_drbg_entropy;
	/* Round up to multiple of block size */
	return (min_len + 0xf) & ~0xf;
}

void print_hex(const char *title, unsigned char *values, size_t len){
	size_t i;
	printf("%s: ",title);
	for(i=0; i<len; ++i){
		if(i!=0 && i % 32 == 0)
			printf("\n");
		printf("%.2hhx", values[i]);
	}
	printf("\n");
}

void bnprint(const char *name, const BIGNUM *b)	{
	unsigned char *tmp;
	int len;
	len = BN_num_bytes(b);
	tmp = malloc(len);
	BN_bn2bin(b, tmp);
	print_hex(name, tmp, len);
	free(tmp);
}

/* Test if an (x,y) point can be used to predict remaining of buffer */
void test_candidate(unsigned char *buffer, BIGNUM *x, BIGNUM *y, BN_CTX *bn_ctx){
	EC_GROUP *curve;
	EC_POINT *point;
	BIGNUM *i2x, *o1x;
	unsigned char o1x_bin[33];
	int ret;

	curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	assert(curve != NULL);
	point = EC_POINT_new(curve);
	assert(point != NULL);
	i2x = BN_new();
	assert(i2x != NULL);
	o1x = BN_new();
	assert(o1x != NULL);

	/* create the point A based on calculated coordinates x and y */
	ret = EC_POINT_set_affine_coordinates_GFp(curve, point, x, y, bn_ctx);
	assert(ret == 1);
	/* Normally the point should be on curve but we never know */
	if (!EC_POINT_is_on_curve(curve, point, bn_ctx))
		goto end;

	/* calculates i2 = phi(x(e.A)) */
	ret = EC_POINT_mul(curve, point, NULL, point, e_bn, bn_ctx);
	assert(ret ==1);

	ret = EC_POINT_get_affine_coordinates_GFp(curve, point, i2x, NULL, bn_ctx);
	assert(ret ==1);
	if(verbose)
		bnprint ("i2_x", i2x);

	/* calculate o1 = phi(x(i2 * Q)) */
	ret = EC_POINT_mul(curve, point, NULL, my_Q, i2x, bn_ctx);
	assert(ret == 1);
	ret = EC_POINT_get_affine_coordinates_GFp(curve, point, o1x, NULL, bn_ctx);
	if(verbose)
		bnprint ("o1_x", o1x);
	BN_bn2bin(o1x, o1x_bin);
	if (o1x_bin[2] == buffer[0] && o1x_bin[3] == buffer[1]){
		printf("Found a match !\n");
		bnprint("A_x", x);
		bnprint("A_y", y);
		print_hex("prediction", o1x_bin + 4, 28);
	}


end:
	BN_free(i2x);
	BN_free(o1x);
	EC_POINT_free(point);
	EC_GROUP_free(curve);
}

void decode(unsigned char *buffer){
	/* Try to find all 30 bytes output values that could be x coordinates */
	BN_CTX *bn_ctx = BN_CTX_new();
	EC_GROUP *curve;
	BIGNUM *x_value, *y_value, *tmp1, *tmp2, *zero_value;
	EC_POINT *point;
	unsigned char x_bin[32];
	int prefix;
	int ret;
	int valid_points = 0;
	
	curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	assert(curve != NULL);
	
	point = EC_POINT_new(curve);
	assert(point != NULL);
	
	x_value = BN_new();
	y_value = BN_new();
	tmp1 = BN_new();
	tmp2 = BN_new();
	zero_value = BN_new();
	assert(x_value && y_value && tmp1 && tmp2 && zero_value);

	memcpy(&x_bin[2], buffer, 30);

	BN_set_word(zero_value,0);

	for (prefix = 0; prefix <= 0x10000 ; ++prefix){
		x_bin[0] = prefix >> 8;
		x_bin[1] = prefix & 0xff;
		BN_bin2bn(x_bin, 32, x_value);
		//bnprint("X value", x_value);

		/* try to find y such as */
		/* y^2 = x^3 - 3x + b (mod p) */
		/* tmp1 = x^2 */
		ret = BN_mod_mul(tmp1, x_value, x_value, &curve->field, bn_ctx);
		assert(ret == 1);
		
		ret = BN_set_word(tmp2, 3);
		assert(ret == 1);

		/* tmp1 = x^2 - 3 */
		ret = BN_mod_sub(tmp1, tmp1, tmp2, &curve->field, bn_ctx);
		assert(ret == 1);
		
		/* tmp1 = (x^2 -3) * x */
		ret = BN_mod_mul(tmp1, x_value, tmp1, &curve->field, bn_ctx);
		assert(ret == 1);
		
		/* tmp1 = x^3 - 3x + b */
		ret = BN_mod_add(tmp1, tmp1, b_bn, &curve->field, bn_ctx);
		assert(ret == 1);
		
		//bnprint("Y squared", tmp1);
		if (NULL != BN_mod_sqrt(y_value, tmp1, &curve->field, bn_ctx)) {
			//printf("value %x match !\n", prefix);
			if(verbose)
				bnprint("calculated Y", y_value);

			BN_mod_sub(y_value, zero_value, y_value, &curve->field, bn_ctx);
			if(verbose)
				bnprint("calculated Y opposite", y_value);
			test_candidate(buffer + 30, x_value, y_value, bn_ctx);
			valid_points += 2;

		}
	}

	printf("Reviewed %d valid points (candidates for A)\n", valid_points);

	BN_free(zero_value);
	BN_free(tmp2);
	BN_free(tmp1);
	BN_free(y_value);
	BN_free(x_value);
	EC_POINT_free(point);
	EC_GROUP_free(curve);
	BN_CTX_free(bn_ctx);
}

int main(int argc, char **argv){
	DRBG_CTX *ctx;
	int ret;
	unsigned char buffer[BUFLEN]="";
	
	if (argc > 1 && strcmp(argv[1],"-v") == 0)
		verbose = 1;
	/* debug output from libcrypto goes to stdout */
	dup2(1,2);
	FIPS_set_error_callbacks(err_cb, NULL);
	ctx = FIPS_drbg_new(NID_X9_62_prime256v1 << 16 | NID_sha1, 0);
	assert(ctx != NULL);
	
    FIPS_drbg_set_callbacks(ctx, drbg_test_cb, 0, 0x10, drbg_test_cb, 0);

	generate_constants();
	ctx->d.ec.Q=my_Q;
	
	ret = FIPS_drbg_instantiate(ctx,
			NULL /* *pers*/, 0 /* perslen */ );
	assert(ret == 1);
	
	ret = FIPS_drbg_generate(ctx, buffer, 64,
				0 /*prediction_resistance */,
				NULL /* *adin*/ , 0  /* adinlen */);
	assert(ret == 1);
	
	print_hex("PRNG output",buffer, 32);
	decode(buffer);
	print_hex("PRNG output",buffer + 32, 28);
	FIPS_drbg_free(ctx);

	return 0;
}
