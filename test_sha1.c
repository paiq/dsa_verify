#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "sha1.h"
#include "dsa_verify.h"

//------------------------------------------------------------------------------
//	SRM message test message given by the DPORT VESA group
//------------------------------------------------------------------------------
unsigned char srm_msg[] = {
  0x80, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x36,
  0x02, 0x51, 0x1e, 0xf2, 0x1a, 0xcd, 0xe7, 0x26,
  0x97, 0xf4, 0x01
};
unsigned int srm_msg_len = 19;

static uint8_t		sha1_digest[SHA1HashSize];
static SHA1Context	ctx;

//------------------------------------------------------------------------------
//	displays formatted hex data on stdout
//------------------------------------------------------------------------------
void dd_hex_stdout(uint8_t* p, uint32_t sz)
{
	uint32_t i;

	printf("data block size: %d\n", sz);
	printf("      00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");
	for (i = 0; i < sz; i++) {
		if ((i % 16) == 0) printf("\n%04x: ", i);
		printf("%02x ", *p++);
	}
	printf("\n");
}

//------------------------------------------------------------------------------
//	main application: simple driver for SHA1 and DSA verify
//------------------------------------------------------------------------------
int main(void)
{
	printf("SHA-1 digest calculation\ninput message:\n");
	dd_hex_stdout(srm_msg, srm_msg_len);
	SHA1Reset(&ctx);
	SHA1Input(&ctx, srm_msg, srm_msg_len);
	SHA1Result(&ctx, sha1_digest);
	printf("output sha-1 digest:\n");
	dd_hex_stdout(sha1_digest, SHA1HashSize);
	printf("\n\n");

	return 0;
}
