# INV-RELOAD

Overview
-------------
This project is a part of Master Thesis prepared at DTU Compute, Department of Applied Mathematics and Computer Science. The project contains an implementation of reproduced FLUSH+RELOAD attack presented by Yarom and Falkner in 2014. Unlike the original attack, the reproduced side-channel attack targets the client-server model which uses RSA encryption/decryption and EdDSA signing/verifying implementation of libgcrypt.

Preparation
-------------
To conduct the attack, the client-server model should be built on Linux. In this scenario, the attacker at the client side traces the victim server's security-critical operations. The target library, which is libgcrypt, should be shared between the server and the client processes by memory deduplication technique to conduct the attack. Therefore, the identical libgcrypt file should be installed on the server side as well as the client side.

How to attack
-------------
The essential part of the attack is to specify the target addresses of security-critical operations. The target addresses in the target libgcrypt library can be obtained using GDB or <code>objdump</code>. Once the target addresses are specified, the attacker knows which address to trace during the attack. Sample target offsets are provided in offsets folder. Note that offsets for RSA are obtained from libgcrypt-1.5.2 configured with -O2 optimization and debug option and offsets for EdDSA are obtained from libgcrypt-1.8.4 configured with debug option.

When the server is waiting for the client's request, you can start the attack by issuing <code>$ ./run.sh</code> on the client side. This will generate a result file which contains the number of cycles to access the specified target addresses. The results can be analyzed using analysis tools in analysis folder.

Author
-------------
[Jaewook Woo](https://github.com/wjw0926)
