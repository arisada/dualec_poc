CFLAGS= -Wall -g

dual_ec_drbg_poc: dual_ec_drbg_poc.c openssl/fips/fipscanister.o
	gcc $(CFLAGS) -o dual_ec_drbg_poc dual_ec_drbg_poc.c -Iopenssl/include/ openssl/fips/fipscanister.o

