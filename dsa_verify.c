/*
 * dsa_verify - http://opensource.implicit-link.com/
 * Copyright (c) 2010 Implicit Link
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "mp_math.h"
#include "sha1.h"

#include "dsa_verify.h"

#define MP_OP(op) if ((ret = (op)) != MP_OKAY) goto error;

/*char *debugMp (mp_int *d)
{
	char *ret = malloc(1024); // leak leak
	mp_tohex(d, ret);
	return ret;
}*/

int _dsa_verify_hash (mp_int *r, mp_int *s, mp_int *hash,
		mp_int *keyG, mp_int *keyP, mp_int *keyQ, mp_int *keyY)
{
	mp_int w, v, u1, u2;
	int ret;
	
	MP_OP(mp_init_multi(&w, &v, &u1, &u2, NULL));
	
	// neither r or s can be 0 or >q
	if (mp_iszero(r) == MP_YES || mp_iszero(s) == MP_YES || mp_cmp(r, keyQ) != MP_LT || mp_cmp(s, keyQ) != MP_LT) {
	   ret = -1;
	   goto error;
	}
	
	// w = 1/s mod q
	MP_OP(mp_invmod(s, keyQ, &w));
	
	// u1 = m * w mod q
	MP_OP(mp_mulmod(hash, &w, keyQ, &u1));
	
	// u2 = r*w mod q
	MP_OP(mp_mulmod(r, &w, keyQ, &u2));
	
	// v = g^u1 * y^u2 mod p mod q
	MP_OP(mp_exptmod(keyG, &u1, keyP, &u1));
	MP_OP(mp_exptmod(keyY, &u2, keyP, &u2));
	MP_OP(mp_mulmod(&u1, &u2, keyP, &v));
	MP_OP(mp_mod(&v, keyQ, &v));
	
	// if r = v then we're set
	ret = 0;
	if (mp_cmp(r, &v) == MP_EQ) ret = 1;
	
error:
	mp_clear_multi(&w, &v, &u1, &u2, NULL);
	return ret;
}

const unsigned char *read_key(mp_int* keyPart, const unsigned char* keyData)
{
	int len = keyData[0]*256 + keyData[1];
	mp_read_unsigned_bin(keyPart, keyData+2, len);
	return keyData+len+2;
}

int dsa_verify_blob(const char *data, int dataLen, const unsigned char* keyData, const char* sigR, const char* sigS)
{
	// dss1 hashing algorithm is actually sha1
	SHA1Context sha1;
	uint8_t sha1sum[SHA1HashSize];
	SHA1Reset(&sha1);

	SHA1Input(&sha1, (const unsigned char *) data, dataLen);
	SHA1Result(&sha1, sha1sum);

	mp_int hash, keyG, keyP, keyQ, keyY, r, s;
	mp_init_multi(&hash, &keyG, &keyP, &keyQ, &keyY, &r, &s, NULL);
	mp_read_unsigned_bin(&hash, sha1sum, sizeof(sha1sum));
	
	keyData = read_key(&keyY, keyData);
	keyData = read_key(&keyP, keyData);
	keyData = read_key(&keyQ, keyData);
	keyData = read_key(&keyG, keyData);
	mp_read_radix(&r, sigR, 16);
	mp_read_radix(&s, sigS, 16);
	
	return _dsa_verify_hash(&r, &s, &hash, &keyG, &keyP, &keyQ, &keyY);
}

#ifdef TEST

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

#endif
