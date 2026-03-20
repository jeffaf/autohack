FROM debian:bookworm-slim

# Enable i386 architecture for 32-bit build
RUN dpkg --add-architecture i386 &&     apt-get update &&     apt-get install -y --no-install-recommends         build-essential         gcc-multilib         xinetd         procps         gdb         binutils         file         wget         ca-certificates     && rm -rf /var/lib/apt/lists/*

# Build inetutils telnetd as 32-bit
RUN cd /tmp &&     wget -q https://ftp.gnu.org/gnu/inetutils/inetutils-2.4.tar.xz &&     tar xf inetutils-2.4.tar.xz &&     cd inetutils-2.4 &&     CFLAGS='-m32 -g -O0' LDFLAGS='-m32' ./configure --prefix=/usr --disable-clients --disable-servers --enable-telnetd &&     make -j$(nproc) &&     cp telnetd/telnetd /usr/sbin/in.telnetd-32 &&     cd / && rm -rf /tmp/inetutils*

COPY xinetd-telnet.conf /etc/xinetd.d/telnet

RUN useradd -m -s /bin/bash testuser &&     echo 'testuser:test' | chpasswd

EXPOSE 23

CMD ["sh", "-c", "echo 0 > /proc/sys/kernel/randomize_va_space 2>/dev/null; ulimit -c unlimited; exec xinetd -dontfork -stayalive"]
