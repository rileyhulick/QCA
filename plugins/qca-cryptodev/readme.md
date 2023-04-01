TODO

QCA plugin based on the OpenBSD Cryptography Framework.

OpenBSD, FreeBSD, NetBSD, and Linux (via a non-standard kernel module) support a
userspace API for the kernel cryptography service via the `/dev/crypto` device.
This enables access to hardware accelerated cryptography and other system 
cryptography resources.

https://man.freebsd.org/cgi/man.cgi?query=crypto&manpath=FreeBSD+13.1-RELEASE+and+Ports
http://cryptodev-linux.org

Linux users are advised to favor the qca-linuxcrypto plugin, which uses the 
standard Linux Crypto API. Some hay is made about whether this API or that is
faster, but I am skeptical that there is any consistent systemic difference.
