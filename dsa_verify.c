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

int dsa_verify_blob(const char *data, int dataLen, const char* sigR, const char* sigS)
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
	
	mp_read_unsigned_bin(&keyG, DSA_KEY_G, sizeof(DSA_KEY_G));
	mp_read_unsigned_bin(&keyP, DSA_KEY_P, sizeof(DSA_KEY_P));
	mp_read_unsigned_bin(&keyQ, DSA_KEY_Q, sizeof(DSA_KEY_Q));
	mp_read_unsigned_bin(&keyY, DSA_KEY_Y, sizeof(DSA_KEY_Y));
	mp_read_radix(&r, sigR, 16);
	mp_read_radix(&s, sigS, 16);
	
	return _dsa_verify_hash(&r, &s, &hash, &keyG, &keyP, &keyQ, &keyY);
}

#ifdef TEST

int main()
{
	char *message = \
		"I think computer viruses should count as life. I think it\n" \
		" says something about human nature that the only form of\n" \
		" life we have created so far is purely destructive. We've\n" \
		" created life in our own image.\n";
	
	return dsa_verify_binary(
		message, strlen(message),
		"D795D68F0CFB19F8A5C042B6427DB8132D1403D1",
		"5D1E9010B9B0605BA6F0983CF49A14FD6F18892D");
}

#endif

