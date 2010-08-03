default: dsa_verify.o mp_math.o sha1.o
	
%.o: %.c
	gcc -c $< -O2 -o $@
