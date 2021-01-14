/*
 * socket-server.c
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

#include "socket-common.h"

/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n){
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = toupper(buf[i]);
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt){
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0) return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(void)
{
	unsigned char buf[256];
	char addrstr[INET_ADDRSTRLEN];
	int sd, client, client2, left = 0;
	ssize_t n;
	socklen_t len;
	struct sockaddr_in sa;
	
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	/* Loop forever, accept()ing connections until two clients connect */
	for (;;) {
		fprintf(stderr, "Waiting for two incoming connections...\n");

		/* Accept the first incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((client = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));
		sprintf((char *)buf, "Wait for peer to connect.\n");
		if (insist_write(client, buf, 27) != 27) {
			perror("write to remote peer failed");
		}

		/* Accept the second incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((client2 = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));
		sprintf((char *)buf, "Peer connected.\n");
		if (insist_write(client, buf, 17) != 17) {
			perror("write to remote peer failed");
		}

		/* Both clients connected. They communicate */
		while(1){
			fd_set inset;
			int maxfd;
			FD_ZERO(&inset);             // initialization
			FD_SET(client, &inset);     // select will check for input from client's socket
			FD_SET(client2, &inset);   // select will check for input from client2's socket
			
			maxfd = MAX(client, client2) + 1;

			int ready_fds = select(maxfd, &inset, NULL, NULL, NULL);
			if (ready_fds <= 0) {
					perror("select");
					continue;    // try again
			}

			// input from client
			if (FD_ISSET(client, &inset)) {
				n = read(client, buf, sizeof(buf));
				if (n <= 0) {
					if (n < 0)
						perror("read from remote peer failed");
					else{
						fprintf(stderr, "Peer went away\n");
						left = 1;
						if (close(client) < 0)
							perror("close");
						break;
					}
				}
				if (insist_write(client2, buf, n) != n) {
					perror("write to remote peer failed");
				}
			}

			// input from client2
			if (FD_ISSET(client2, &inset)) {
				n = read(client2, buf, sizeof(buf));
				if (n <= 0) {
					if (n < 0)
						perror("read from remote peer failed");
					else{
						fprintf(stderr, "Peer went away\n");
						left = 2;
						if (close(client2) < 0)
							perror("close");
						break;
					}
				}
				if (insist_write(client, buf, n) != n) {
					perror("write to remote peer failed");
				}
			}
		}
		
		/* One client disconnected */
		if(left == 1){                                                  // First client left. Wait till first one leaves too
			sprintf((char *)buf, "Peer left. Type exit to shut connection\n"); // inform the second client
			if (insist_write(client2, buf, 41) != 41) {
				perror("write to remote peer failed");
			}
			while(1){                                              // while the second client stays connected
				n = read(client2, buf, sizeof(buf));              // ignore what they write
				if (n <= 0) {                                    // second client left
					fprintf(stderr, "Peer went away\n");
					if (close(client2) < 0){
						perror("close");
					}
					break;
				}
			}
		}
		if(left == 2){                                                  // First client left. Wait till first one leaves too
			sprintf((char *)buf, "Peer left. Type exit to shut connection\n"); // inform the first client
			if (insist_write(client, buf, 41) != 41) {
				perror("write to remote peer failed");
			}
			while(1){                                             // while the first client stays connected
				n = read(client, buf, sizeof(buf));              // ignore what they write
				if (n <= 0) {                                   // first client left
					fprintf(stderr, "Peer went away\n");
					if (close(client) < 0){
						perror("close");
					}
					break;
				}
			}
		}
	}

	/* This will never happen */
	return 1;
}