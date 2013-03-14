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

#ifndef _DSA_VERIFY_H_
#define _DSA_VERIFY_H_

// sigR and sigS should be hex-encoded strings, key points at binary data encoded by openssl_to_c.pl
int dsa_verify_blob(const char *data, int dataLen, const unsigned char *key, const char* sigR, const char* sigS);

#endif

