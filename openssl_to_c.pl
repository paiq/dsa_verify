#!/usr/bin/env perl

# openssl_to_c.pl: Converts `openssl dsa -text` parameter output to C-style hex literals
#     that define a DSA public key.
#
# Expects input on stdin such as the following:
#
# pub:
#     4e:f3:ae:38:fb:09:7e:2c:d1:58:33:0a:27:ba:5c:
#     2a:a0:33:46:cf:e4:8a:bc:3e:dd:72:da:bb:3a:f9:
#     4f:89:73:d4:78:d5:db:6b:a8:c8:02:99:47:3e:b9:
#     dc:b8:6e:da:2d:8d:da:ec:08:21:81:47:38:1e:e2:
#     87:cd:3d:3f:19:1f:20:d3:53:c7:1a:9a:0c:64:a8:
#     a3:68:b5:b8:33:8b:e1:5b:f6:3a:e1:f1:7c:47:87:
#     f1:31:f6:b9:97:9f:b2:c1:c6:9c:1e:ce:8b:4e:0d:
#     16:0c:a9:a0:3f:a8:96:34:68:ba:7c:c5:6a:db:e1:
#     18:94:5a:85:0f:e8:28:f8
# P:  
#     00:f6:34:eb:73:b0:1a:68:47:72:95:7b:15:63:ec:
#     11:98:23:81:91:4f:94:85:ee:42:52:5e:88:89:55:
#     41:f7:ff:56:a7:2d:b3:05:be:34:c5:a1:b3:6b:96:
#     a0:2a:04:e1:69:9a:69:c9:29:df:60:19:5b:36:64:
#     cc:3c:5a:24:e1:c2:2b:ad:4f:44:0f:a9:c4:2e:27:
#     d5:58:3a:ac:2c:9f:fa:67:26:f2:d8:07:e7:25:35:
#     d1:d2:81:95:49:e9:13:52:fc:e5:30:bc:1b:61:db:
#     34:c7:97:8b:15:b8:3d:92:02:fe:2f:62:90:95:c4:
#     9a:6c:86:55:ee:41:7d:b4:05
# Q:  
#     00:e4:3d:d6:3f:c7:4a:c9:39:3e:bb:73:a5:f5:5b:
#     50:80:d6:ec:dd:dd
# G:  
#     00:ab:dd:5c:6c:12:c6:18:d8:ec:46:22:8b:05:fc:
#     33:63:21:2d:84:1c:2b:58:da:ba:e9:73:48:19:63:
#     53:8a:eb:b4:fe:e7:25:8c:c0:6f:4e:d7:0b:7d:45:
#     2b:cc:c9:39:77:7f:2e:8c:90:d8:cb:62:9d:23:9a:
#     9f:52:42:1e:6f:b2:ed:98:34:51:5b:6f:41:3e:70:
#     c7:31:13:9a:55:91:8a:44:45:9d:5e:5e:a1:42:94:
#     45:1e:58:27:e9:3e:45:8a:0b:f6:05:01:0a:a2:0d:
#     bd:1a:d3:61:8e:a7:38:69:f8:0c:90:f8:75:b3:fe:
#     6b:18:ce:5a:69:8b:84:d2:5a
#

%keys = ('pub' => 'Y', 'G' => 'G', 'P' => 'P', 'Q' => 'Q');

$_ = join("", (<>));
while ( /\n([a-zA-Z]+?):\s*([0-9a-f:\s]*?)(?=(\n[a-zA-Z])|$)/g )
{
	$key = $1;
	if (%keys->{$key}) {
		$hex = $2;
		$hex =~ s/\s*//g; # drop spaces
		$hex =~ s/:/, 0x/g; # convert to c hex defs
		$hex =~ s/((.*?\s){16})/$1\n\t/g; # group in hextets
		print "static const unsigned char DSA_KEY_". %keys->{$key} . "[] = {\n\t0x$hex };\n\n";
	}
}