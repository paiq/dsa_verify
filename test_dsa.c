#include <stdint.h>
#include <stdbool.h>

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "mp_math.h"
#include "sha1.h"

#include "dsa_verify.h"

extern const uint8_t public_key[];
extern const char*   r_sig;
extern const char*   s_sig;

char msg[256];

int main()
{
	int dsa_status;
	int msg_len;
	FILE* f_in;

	memset(msg, 0, sizeof(msg));

	f_in = fopen("message.txt", "rb");
	if (f_in == NULL) {
		printf("fopen failed: %s\n", strerror(errno));
	} else {
		msg_len = fread(msg, 1, 256, f_in);
		fclose(f_in);
	}

	dsa_status = dsa_verify_blob(msg, msg_len, public_key, r_sig, s_sig);
	printf("dsa status: %d\n", dsa_status);
}
