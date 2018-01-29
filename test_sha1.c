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

//------------------------------------------------------------------------------
//	Public key
//	Note:	This public key is only for the srm_msg noted above.
//			The true public key is noted elsewhere in the specification.
//------------------------------------------------------------------------------
unsigned char pub_key[] = {
  0x8d, 0x13, 0xe1, 0x9f, 0x34, 0x0e, 0x11, 0xce,
  0xb0, 0xdb, 0x95, 0xeb, 0x3e, 0xb0, 0x74, 0x31,
  0x95, 0xdf, 0xc4, 0x02, 0xb7, 0xdc, 0x8c, 0xaa,
  0xc7, 0x75, 0x2e, 0x47, 0xde, 0xd8, 0xe8, 0xc0,
  0x0b, 0x11, 0x5f, 0x8e, 0x5e, 0x08, 0xc7, 0xa6,
  0x64, 0xcb, 0xbb, 0xa3, 0x97, 0x86, 0xef, 0xd7,
  0x1c, 0x01, 0x2e, 0x83, 0x94, 0xaf, 0x79, 0xcd,
  0x01, 0xf7, 0x22, 0xa0, 0x92, 0x69, 0x52, 0xe8,
  0xde, 0x85, 0x7c, 0xbd, 0x2e, 0x72, 0x95, 0xe6,
  0xb1, 0xd8, 0x8c, 0xc0, 0xff, 0x5d, 0xcc, 0x0a,
  0xb1, 0x6d, 0x14, 0xfa, 0x11, 0xa4, 0x8e, 0xb5,
  0x0f, 0xca, 0x83, 0xa3, 0x7e, 0xd1, 0x8d, 0xe1,
  0x6d, 0x97, 0x35, 0x65, 0xdf, 0x8a, 0x78, 0x4e,
  0x85, 0x42, 0x96, 0xac, 0x70, 0x0b, 0x2e, 0x03,
  0x0f, 0xd2, 0xa9, 0x81, 0x83, 0xaa, 0x7b, 0x22,
  0xa6, 0x3b, 0x57, 0xbe, 0xe5, 0xc2, 0xb9, 0x46
};
unsigned int pub_key_len = 128;

//------------------------------------------------------------------------------
//	S part of message signature
//------------------------------------------------------------------------------
unsigned char srm_msg_s[] = {                  
  0x5b, 0x24, 0xb3, 0x36, 0x84, 0x94, 0x75, 0x34,
  0xdb, 0x10, 0x9e, 0x3b, 0x23, 0x13, 0xd8, 0x7a,
  0xc2, 0x30, 0x79, 0x84                         
};                                               
unsigned int srm_msg_s_len = 20;               

//------------------------------------------------------------------------------
//	R part of message signature
//------------------------------------------------------------------------------
unsigned char srm_msg_r[] = {                  
  0x97, 0x10, 0x19, 0x92, 0x53, 0xe9, 0xf0, 0x59,
  0x95, 0xa3, 0x7a, 0x3b, 0xfe, 0xe0, 0x9c, 0x76,
  0xdd, 0x83, 0xaa, 0xc2                         
};                                               
unsigned int srm_msg_r_len = 20;               


static uint8_t sha1_digest[SHA1HashSize];
static SHA1Context ctx;

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
	printf("SHA-1 digest calculation\ninput:\n");
	printf("message:\n");
	dd_hex_stdout(srm_msg, srm_msg_len);
	SHA1Reset(&ctx);
	SHA1Input(&ctx, srm_msg, srm_msg_len);
	SHA1Result(&ctx, sha1_digest);
	printf("output:\n");
	printf("sha-1 digest:\n");
	dd_hex_stdout(sha1_digest, SHA1HashSize);
	printf("\n\n");

	printf("DSA verification calculation\ninput:\n");
	printf("sha-1 digest:\n");
	dd_hex_stdout(sha1_digest, SHA1HashSize);
	printf("public key:\n");
	dd_hex_stdout(pub_key, pub_key_len);
	printf("S part of signature:\n");
	dd_hex_stdout(srm_msg_s, srm_msg_s_len);
	printf("R part of signature:\n");
	dd_hex_stdout(srm_msg_r, srm_msg_r_len);
	
	//dsa_verify_blob(sha1_digest, SHA1HashSize, pub_key, srm_msg_r, srm_msg_s);

	return 0;
}
