/*
* Copyright 2011 Range Networks, Inc.
*
* This software is distributed under the terms of the GNU Affero Public License.
* See the COPYING file in the main directory for details.
*
* This use of this software may be subject to additional restrictions.
* See the LEGAL file in the main directory for details.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#define DEFAULT_CMD_PATH "command"

int main(int argc, char **argv) {
    if ((argc != 2) && (argc != 3)) {
	printf("OpenBTSDo command [socket]\n");
	return 1;
    }

    const char* cmdPath = (argc == 3)? argv[2] : DEFAULT_CMD_PATH;
    char rspPath[200];

    sprintf(rspPath, "/tmp/OpenBTS.do.%d", getpid());

    // the socket
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
	perror("opening datagram socket");
	return 2;
    }

    // destination address
    struct sockaddr_un cmdSockName;
    cmdSockName.sun_family = AF_UNIX;
    strcpy(cmdSockName.sun_path, cmdPath);

    // locally bound address
    struct sockaddr_un rspSockName;
    rspSockName.sun_family = AF_UNIX;
    strcpy(rspSockName.sun_path, rspPath);
    if (bind(sock, (struct sockaddr *) &rspSockName, sizeof(struct sockaddr_un))) {
	perror("binding name to datagram socket");
	return 3;
    }

    if (sendto(sock, argv[1], strlen(argv[1]) + 1, 0, (struct sockaddr*)&cmdSockName, sizeof(cmdSockName)) < 0) {
	perror("sending datagram");
	return 4;
    }

    const int bufsz = 1500;
    char resbuf[bufsz];
    int nread = recv(sock, resbuf, bufsz - 1, 0);
    if (nread < 0) {
	perror("receiving response");
	return 5;
    }
    resbuf[nread] = '\0';
    printf("%s\n", resbuf);
    
    close(sock);
}
