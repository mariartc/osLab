/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <crypto/cryptodev.h>

#include "socket-common.h"

#define KEY_SIZE	16
#define BLOCK_SIZE      16

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt){
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
		ret = write(fd, buf, cnt);
		if (ret < 0)
				return ret;
		buf += ret;
		cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char *argv[])
{
	int sd, port, crypto_fd;
	ssize_t n;
	unsigned char buf[256], buf_out[256];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	int shutdownSocket = 1;
	unsigned char key[KEY_SIZE], iv[BLOCK_SIZE];
	struct session_op sess;
	struct crypt_op cryp;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, BLUE"Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "You are connected.\nType \"exit\" to shut the connection.\n\n"WHITE);

	// determine encryption key and initialization vector
	sprintf((char *)key, "mariamarkosbffe");
	sprintf((char *)iv, "mariamarkosbffe");
	// open crypto device
	crypto_fd = open("/dev/crypto", O_RDWR);
	if (crypto_fd < 0) perror("open(/dev/crypto)");

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	// get crypto session
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = key;

	if (ioctl(crypto_fd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	//chat
	memset(buf, 0, sizeof(buf));
	while(1){
		fd_set inset;
		int maxfd;
		FD_ZERO(&inset);                 // initialization
        FD_SET(STDIN_FILENO, &inset);   // select will check for input from stdin
		FD_SET(sd, &inset);            // select will check for input from socket
		
		maxfd = MAX(STDIN_FILENO, sd) + 1;

		int ready_fds = select(maxfd, &inset, NULL, NULL, NULL);
		if (ready_fds <= 0) {
				perror("select");
				continue;        // try again
		}

		// input from stdin (user has typed something)
        if (FD_ISSET(STDIN_FILENO, &inset)) {
			/* Read from input and write it to socket */
			memset(buf, 0, sizeof(buf)); //clear the buffer
			n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n < 0) {
				perror("read");
				exit(1);
			}

			buf[sizeof(buf) - 1] = '\0';
			if (memcmp(buf, "exit", 4) == 0) break;

			/*
			 * Encrypt buf to buf_out
			 */
			cryp.ses = sess.ses;
			cryp.len = sizeof(buf);
			cryp.src = buf;
			cryp.dst = buf_out;
			cryp.iv = iv;
			cryp.op = COP_ENCRYPT;


			if (ioctl(crypto_fd, CIOCCRYPT, &cryp)) {
				perror("ioctl(CIOCCRYPT)");
				return 1;
			}

			if (insist_write(sd, buf_out, 256) != 256) { // all 256 bytes contain the encrypted text
				perror("write");
				exit(1);
			}
		}

		// input from socket
		if(FD_ISSET(sd, &inset)){
			/* Read answer and write it to standard output */
			memset(buf, 0, sizeof(buf)); //clear the buffer
			n = read(sd, buf, sizeof(buf));
			memcpy(buf_out, buf, n); // copy buf to buf_out, in case the message is from server, therefor doesn't need decryption

			if (n < 0) {
				perror("read");
				exit(1);
			}
			if(n == 0){  // server closed connection
				if (close(sd) < 0)
					perror("close");
				shutdownSocket = 0;
				break;
			}

			fprintf(stderr, BLUE"");
			if(memcmp(buf, "Wait for peer to connect.\n", 27) != 0 
						&& memcmp(buf, "Peer connected.\n", 17) != 0
						&& memcmp(buf, "Peer left. Type exit to shut connection\n", 41) != 0){
				fprintf(stderr, GREEN"Peer says: ");
				/*
				 * Decrypt buf to buf_out
				 */
				cryp.ses = sess.ses;
				cryp.len = sizeof(buf);
				cryp.src = buf;
				cryp.dst = buf_out;
				cryp.iv = iv;
				cryp.op = COP_DECRYPT;
				if (ioctl(crypto_fd, CIOCCRYPT, &cryp)) {
					perror("ioctl(CIOCCRYPT)");
				return 1;
				}
			}
			if (insist_write(0, buf_out, n) != n) {
				perror("write");
				exit(1);
			}
			fprintf(stderr, WHITE"");
		}
	}

	fprintf(stderr, BLUE"\nConnection shut.\n"WHITE);

	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	 */
	if (shutdownSocket && shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}
	
	/* Finish crypto session */
	if (ioctl(crypto_fd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		return 1;
	}
	if (close(crypto_fd) < 0) perror("close(fd)");

	return 0;
}