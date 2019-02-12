# INV-RELOAD

Overview
-------------
This project is a part of Master Thesis prepared at DTU Compute, Department of Applied Mathematics and Computer Science. The project contains an implementation of reproduced FLUSH+RELOAD attack presented by Yarom and Falkner in 2014. Unlike the original attack, the reproduced side-channel attack targets client-server model which uses RSA encryption/decryption and EdDSA signing/verifying implementation of libgcrypt-1.5.2.

Preperation
-------------
To conduct the attack, client-server model should be built on Linux. In this scenario, the attacker at the client side traces victim server's security-critical operations. The target library file, which is libgcryp-1.5.2, should be shared between the server and the client processes by memory deduplication technique to conduct the attack. Therefore, identical libgcrypt-1.5.2 file should be set up on the server side as well as client side.

How to attack
-------------
The essential part of the attack is to specify the target addresses of security-critical operations. The target addresses in the target libgcrypt library can be obtained using GDB or <pre><code>objdump</code></pre>. Once the target addresses are specified, the attacker knows which address to trace during the attack. Sample target offsets are provided in <pre><code>offsets/</code></pre>. Note that these offsets are obtained from libgcrypt-1.5.2 configured with -O2 optimization and debug option.

When the server is waiting for the client's request, you can issue <pre><code>$ ./run.sh</code></pre> in the <pre><code>RSA/client/</code></pre> or <pre><code>EdDSA/client/</code></pre> folder. This will generate a text file which contains the number of cycles to access the specified target addresses. The results can be analysed using analysis tools in <pre><code>analysis/</code></pre>.

Author
-------------
[Jaewook Woo](https://github.com/wjw0926)
