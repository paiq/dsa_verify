#-------------------------------------------------------------------------------
#	Makefile for dsa_verify
#-------------------------------------------------------------------------------
CC = gcc
CFLAGS = -Wall -Werror -ggdb -DTEST

dsa_verify:	dsa_verify.o sha1.o mp_math.o pub_key_2.o

test_sha1:	test_sha1.o sha1.o

clean:
	$(RM) *.o
	$(RM) test_sha1.exe
	$(RM) dsa_verify.exe
	