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

#include "socket-common.h"

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
	int sd, port;
	ssize_t n;
	char buf[100];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	int shutdownSocket = 1;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

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
			n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n < 0) {
				perror("read");
				exit(1);
			}

			buf[sizeof(buf) - 1] = '\0';
			if (strncmp(buf, "exit", 4) == 0) break;
			if (insist_write(sd, buf, n) != n) {
				perror("write");
				exit(1);
			}
		}

		// input from socket
		if(FD_ISSET(sd, &inset)){
			/* Read answer and write it to standard output */
			n = read(sd, buf, sizeof(buf));

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
			if(strncmp(buf, "Wait for peer to connect.\n", 27) != 0 
						&& strncmp(buf, "Peer connected.\n", 17) != 0
						&& strncmp(buf, "Peer left. Type exit to shut connection\n", 41) != 0) fprintf(stderr, GREEN"Peer says: ");
			if (insist_write(0, buf, n) != n) {
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

	return 0;
}