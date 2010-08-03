dsa\_verify
===========

C library to verify a blob against a DSA public key and a DSA signature. Aims at cross-platformness and small memory footprint. Useful for self-updating applications that want to verify their new binary, patch files, etc. To keep the implementation simple, support for parameter encoding using ASN1/DER/etc. schemes is left out.

Key generation
--------------
A DSA public key consists of parameters G, P, Q and Y; they are defined in `dsa_verify.h`. Using ssh-keygen and openssl a key can be generated and the parameters can be obtained. The included `openssl_to_c.pl` script can convert them to c-directives.

	ssh-keygen -t dsa # (optionally) supply a password, save to distribution.dsa
	openssl dsa -in distribution.dsa -noout -text | ./openssl_to_c.pl

Note that `ssh-keygen` only generates 1024-bits keys. This should be a good value for almost all uses though.

Signing
-------
A DSA signature consists parameters R and S. They can be obtained (in order) using:

	openssl dgst -dss1 -sign distribution.dsa my_binary_or_binary_patch | openssl asn1parse -inform DER

Note that the dss1 hashing algorithm is actually just sha1.

Verification
------------
In your application, you should obtain the binary blob and parameters R and S. You can then verify the blob using the function `dsa_verify_binary`. It returns 1 when the blob is untampered.

Public key in source
--------------------
The source code includes a public key and signature for the following private key:

	00:dc:78:60:20:56:9d:9c:4b:bd:32:f6:00:89:63:ce:ab:dc:0c:44:c8

Compilation
-----------
The included Makefile compiles 3 object-files, which you should link to your program.

Credits and attribution
-----------------------
The mp\_math library is a modified (only necessities) [LibTomMath](http://libtom.org/?page=features&newsitems=5&whatfile=ltm); the sha1 functions are copied from [RFC 3174](http://www.apps.ietf.org/rfc/rfc3174.html). The other sources are released under the GNU General Public License.
