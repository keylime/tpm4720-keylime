/********************************************************************************/
/*                                                                              */
/*                              TPM Host IO                                     */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: tpm_io.c 4716 2013-12-24 20:47:44Z kgoldman $			*/
/*                                                                              */
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* These are platform specific.  This version uses a TCP/IP socket interface.

   Environment variables are:
           
           TPM_PORT - the client and server socket port number
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef TPM_WINDOWS
#include <windows.h>
#endif  /* TPM_WINDOWS */

#include "tpm_debug.h"
#include "tpm_commands.h"
#include "tpm_error.h"
#include "tpm_pcr.h"
#include "tpm_platform.h"
#include "tpm_types.h"


/* header for this file */
#include "tpm_io.h"

#ifndef SSIZE_MAX
#define SSIZE_MAX INT_MAX
#endif


/*
  local prototypes
*/

static TPM_RESULT TPM_IO_ReadBytes(TPM_CONNECTION_FD *connection_fd,
                                   unsigned char *buffer,
                                   size_t nbytes);

#ifdef TPM_POSIX        /* Posix sockets and threads */
#ifndef TPM_UNIX_DOMAIN_SOCKET
static TPM_RESULT TPM_IO_ServerSocket_Open(int *sock_fd,
                                           short port,
                                           uint32_t in_addr);
#else	/* TPM_UNIX_DOMAIN_SOCKET */
static TPM_RESULT TPM_IO_ServerSocket_Open(int *sock_fd);
#endif 	/* TPM_UNIX_DOMAIN_SOCKET */
#endif	/* TPM_POSIX */


#ifdef TPM_WINDOWS
static TPM_RESULT TPM_IO_ServerSocket_Open(SOCKET *sock_fd,
                                           short port,
                                           uint32_t in_addr);
static void TPM_HandleWsaStartupError(const char *prefix,
                                      int irc);
static void TPM_HandleWsaError(const char *prefix);
static void TPM_GetWsaStartupError(int status,
                                   const char **error_string);
static void TPM_GetWsaError(const char **error_string);
#endif  /* TPM_WINDOWS */

/*
  global variables
*/

static const char *port_str;    /* TPM command/response server port
                                   port number for TCP/IP
                                   domain file name for Unix domain socket */


/* platform dependent */

#ifdef TPM_POSIX        /* Posix sockets and threads */
static int      sock_fd = -1;
#endif  /* TPM_POSIX */

#ifdef TPM_WINDOWS
static SOCKET   sock_fd = INVALID_SOCKET;
#endif  /* TPM_WINDOWS */




/* TPM_IO_Read() reads a TPM command packet from the host

   Puts the result in 'buffer' up to 'bufferSize' bytes.

   On success, the number of bytes in the buffer is equal to 'bufferLength' bytes

   This function is intended to be platform independent.
*/

TPM_RESULT TPM_IO_Read(TPM_CONNECTION_FD *connection_fd,        /* read/write file descriptor */
                       unsigned char *buffer,   /* output: command stream */
                       uint32_t *bufferLength,	/* output: command stream length */
                       size_t bufferSize,       /* input: max size of output buffer */
                       void *mainLoopArgs)
{       
    TPM_RESULT          rc = 0;
    uint32_t              headerSize;     /* minimum required bytes in command through paramSize */
    uint32_t              paramSize;      /* from command stream */
    
    /* check that the buffer can at least fit the command through the paramSize */
    if (rc == 0) {
        headerSize = sizeof(TPM_TAG) + sizeof(uint32_t);  
        if (bufferSize < headerSize) {
            printf("TPM_IO_Read: Error, buffer size %lu less than minimum %u\n",
                   (unsigned long)bufferSize, headerSize);
            rc = TPM_SIZE;
        }
    }
    /* read the command through the paramSize from the socket stream */
    if (rc == 0) {
        mainLoopArgs = mainLoopArgs;            /* not used */
        rc = TPM_IO_ReadBytes(connection_fd, buffer, headerSize);
    }
    if (rc == 0) {
        TPM_PrintAll("  TPM_IO_Read: through paramSize", buffer, headerSize);
        /* extract the paramSize value, last field in header */
        paramSize = LOAD32(buffer, headerSize - sizeof(uint32_t));
        *bufferLength = headerSize + paramSize - (sizeof(TPM_TAG) + sizeof(uint32_t));
        if (bufferSize < *bufferLength) {
            printf("TPM_IO_Read: Error, buffer size %lu is less than required %u\n",
                   (unsigned long)bufferSize, *bufferLength);
            rc = TPM_SIZE;
        }
    }
    /* read the rest of the command (already read tag and paramSize) */
    if (rc == 0) {
        rc = TPM_IO_ReadBytes(connection_fd,
                              buffer + headerSize,
                              paramSize - (sizeof(TPM_TAG) + sizeof(uint32_t)));
    }
    if (rc == 0) {
        TPM_PrintAll(" TPM_IO_Read:", buffer, *bufferLength);
    }
    return rc;
}

#ifdef TPM_POSIX        /* Unix Sockets */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/time.h>

/* TPM_IO_Init initializes the TPM to host interface.

   This is the Unix platform dependent socket version.
*/

TPM_RESULT TPM_IO_Init(void)
{
    TPM_RESULT          rc = 0;
#ifndef TPM_UNIX_DOMAIN_SOCKET
    int                 irc;
    short               port;           /* TCP/IP port */
#endif /* TPM_UNIX_DOMAIN_SOCKET */

    printf(" TPM_IO_Init:\n");
    /* get the socket port number */
    if (rc == 0) {
        port_str = getenv("TPM_PORT");
        if (port_str == NULL) {
            printf("TPM_IO_Init: Error, TPM_PORT environment variable not set\n");
            rc = TPM_IOERROR;
        }
    }
#ifndef TPM_UNIX_DOMAIN_SOCKET
    if (rc == 0) {
        irc = sscanf(port_str, "%hu", &port);
        if (irc != 1) {
            printf("TPM_IO_Init: Error, TPM_PORT environment variable invalid\n");
            rc = TPM_IOERROR;
        }
    }
    /* create a socket */
    if (rc == 0) {
        rc = TPM_IO_ServerSocket_Open(&sock_fd,
                                      port,
                                      INADDR_ANY);
        if (rc != 0) {
            printf("TPM_IO_Init: Warning, could not open TCP/IP server socket.\n");
        }
    }
#else /* TPM_UNIX_DOMAIN_SOCKET */
    /* create a socket */
    if (rc == 0) {
        rc = TPM_IO_ServerSocket_Open(&sock_fd);
        if (rc != 0) {
            printf("TPM_IO_Init: Warning, could not open server domain socket.\n");
        }
    }
#endif /* TPM_UNIX_DOMAIN_SOCKET */
    if (rc == 0) {
        printf("TPM_IO_Init: Waiting for connections on %s\n", port_str);
    }
    return rc;
}


/* Open a TCP Server socket given the provided parameters. Set it into
   listening mode so connections can be accepted on it.

   This is the Unix platform dependent socket version.
*/

#ifndef TPM_UNIX_DOMAIN_SOCKET
static TPM_RESULT TPM_IO_ServerSocket_Open(int *sock_fd,
                                           short port,
                                           uint32_t in_addr)
#else /* TPM_UNIX_DOMAIN_SOCKET */
static TPM_RESULT TPM_IO_ServerSocket_Open(int *sock_fd)
#endif /* TPM_UNIX_DOMAIN_SOCKET */
{
    TPM_RESULT          rc = 0;
    int                 irc;
#ifndef TPM_UNIX_DOMAIN_SOCKET
    int                 domain = AF_INET;
    struct sockaddr_in  serv_addr;
    int                 opt;
#else /* TPM_UNIX_DOMAIN_SOCKET */
    int                 domain = AF_LOCAL;
    struct sockaddr_un  serv_addr;
#endif /* TPM_UNIX_DOMAIN_SOCKET */

    /* create a socket */
    if (rc == 0) {
        printf(" TPM_IO_ServerSocket_Open: Port %s\n", port_str);
        *sock_fd = socket(domain, SOCK_STREAM, 0);      /* socket */
        if (*sock_fd == -1) {
            printf("TPM_IO_ServerSocket_Open: Error, server socket() %d %s\n",
                   errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }
#ifndef TPM_UNIX_DOMAIN_SOCKET
    if (rc == 0) {
        memset((char *)&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;                 /* Internet socket */
        serv_addr.sin_port = htons(port);               /* host to network byte order for short */
        serv_addr.sin_addr.s_addr = htonl(in_addr);     /* host to network byte order for long */
        opt = 1;
        /* Set SO_REUSEADDR before calling bind() for servers that bind to a fixed port number. */
        irc = setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (irc != 0) {
            printf("TPM_IO_ServerSocket_Open: Error, server setsockopt() %d %s\n",
                   errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }
#else /* TPM_UNIX_DOMAIN_SOCKET */
    if (rc == 0) {
        irc = unlink(port_str); /* remove any previous file */
        if ((irc == -1) &&
            (errno != ENOENT)) {        /* file might not exist, ignore this error */
            printf("TPM_IO_ServerSocket_Open: Error server unlink() %d %s\n",
                   errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }
    if (rc == 0) {
        memset((char *)&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sun_family = AF_LOCAL;        /* UNIX domain socket */
        /* check length, since it comes from an environment variable */
        if (strlen(port_str) >= sizeof(serv_addr.sun_path)) {
            printf("TPM_IO_ServerSocket_Open: Error, domain socket name too long\n");
            rc = TPM_IOERROR;
        }
    }
    if (rc == 0) {
        strcpy(serv_addr.sun_path, port_str);
    }
#endif /* TPM_UNIX_DOMAIN_SOCKET */
    /* bind the (local) server port name to the socket */
    if (rc == 0) {
        irc = bind(*sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (irc != 0) {
            close(*sock_fd);
            *sock_fd = -1;
            printf("TPM_IO_ServerSocket_Open: Error, server bind() %d %s\n",
                   errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }
    /* listen for a connection to the socket */
    if (rc == 0) {
        irc = listen(*sock_fd, SOMAXCONN);
        if (irc != 0) {
            close(*sock_fd);
            *sock_fd = -1;
            printf("TPM_IO_ServerSocket_Open: Error, server listen() %d %s\n",
                   errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }
    return rc;
}

/* TPM_IO_Connect() establishes a connection between the TPM server and the host client
   
   This is the Unix platform dependent socket version.
*/

TPM_RESULT TPM_IO_Connect(TPM_CONNECTION_FD *connection_fd,     /* read/write file descriptor */
                          void *mainLoopArgs)
{
    TPM_RESULT          rc = 0;
    socklen_t           cli_len;
#ifndef TPM_UNIX_DOMAIN_SOCKET
    struct sockaddr_in  cli_addr;       /* Internet version of sockaddr */
#else /* TPM_UNIX_DOMAIN_SOCKET */
    struct sockaddr_un  cli_addr;
#endif /* TPM_UNIX_DOMAIN_SOCKET */
    int                 max_fd = -1;
    fd_set              readfds;
    int                 n;

    mainLoopArgs = mainLoopArgs;        /* not used */

    while (rc == 0) {
        FD_ZERO(&readfds);

        FD_SET(sock_fd, &readfds);
        max_fd = sock_fd;
        printf("TPM_IO_Connect: Waiting for connections on port %s\n", port_str);

        
        n = select(max_fd + 1, &readfds, NULL, NULL, NULL);
        
        if (n > 0 && FD_ISSET(sock_fd, &readfds)) {
            cli_len = sizeof(cli_addr);
            /* block until connection from client */
            printf("\n TPM_IO_Connect: Accepting connection from port %s ...\n", port_str);
            connection_fd->fd = accept(sock_fd, (struct sockaddr *)&cli_addr, &cli_len);
            if (connection_fd->fd < 0) {
                printf("TPM_IO_Connect: Error, accept() %d %s\n", errno, strerror(errno));
                rc = TPM_IOERROR;
            }
            break;
        }

    }

    return rc;
}

/* TPM_IO_ReadBytes() reads nbytes from connection_fd and puts them in buffer.

   The buffer has already been checked for sufficient size.

   This is the Unix platform dependent socket version.
*/

static TPM_RESULT TPM_IO_ReadBytes(TPM_CONNECTION_FD *connection_fd,    /* read/write file descriptor */
                                   unsigned char *buffer,
                                   size_t nbytes)
{
    TPM_RESULT rc = 0;
    ssize_t nread = 0;
    size_t nleft = nbytes;

    printf("  TPM_IO_ReadBytes: Reading %lu bytes\n", (unsigned long)nbytes);
    /* read() is unspecified with nbytes too large */
    if (rc == 0) {
        if (nleft > SSIZE_MAX) {
            rc = TPM_BAD_PARAMETER;
        }
    }
    while ((rc == 0) && (nleft > 0)) {
        nread = read(connection_fd->fd, buffer, nleft);
        if (nread > 0) {
            nleft -= nread;
            buffer += nread;
        }           
        else if (nread < 0) {       /* error */
            printf("TPM_IO_ReadBytes: Error, read() error %d %s\n",
                   errno, strerror(errno));
            rc = TPM_IOERROR;
        }
        else if (nread == 0) {          /* EOF */
            printf("TPM_IO_ReadBytes: Error, read EOF, read %lu bytes\n",
                   (unsigned long)(nbytes - nleft));
            rc = TPM_IOERROR;
        }
    }
    return rc;
}

/* TPM_IO_Write() writes 'buffer_length' bytes to the host.
   
   This is the Unix platform dependent socket version.
*/

TPM_RESULT TPM_IO_Write(TPM_CONNECTION_FD *connection_fd,       /* read/write file descriptor */
                        const unsigned char *buffer,
                        size_t buffer_length)
{       
    TPM_RESULT  rc = 0;
    ssize_t     nwritten = 0;
    
    if (rc == 0) {
        TPM_PrintAll(" TPM_IO_Write:", buffer, buffer_length);
    }
    /* write() is unspecified with buffer_length too large */
    if (rc == 0) {
        if (buffer_length > SSIZE_MAX) {
            rc = TPM_BAD_PARAMETER;
        }
    }
    /* test that connection is open to write */
    if (rc == 0) {
        if (connection_fd->fd < 0) {
            printf("TPM_IO_Write: Error, connection not open, fd %d\n",
                   connection_fd->fd);
            rc = TPM_IOERROR;
        }
    }
    while ((rc == 0) && (buffer_length > 0)) {
        nwritten = write(connection_fd->fd, buffer, buffer_length);
        if (nwritten >= 0) {
            buffer_length -= nwritten;
            buffer += nwritten;
        }
        else {
            printf("TPM_IO_Write: Error, write() %d %s\n",
                   errno, strerror(errno));
            rc = TPM_IOERROR;
        }
    }
    return rc;
}

/* TPM_IO_Disconnect() breaks the connection between the TPM server and the host client

   This is the Unix platform dependent socket version.
*/

TPM_RESULT TPM_IO_Disconnect(TPM_CONNECTION_FD *connection_fd)
{
    TPM_RESULT  rc = 0;

    /* close the connection to the client */
    close(connection_fd->fd);
    connection_fd->fd = -1;     /* mark the connection closed */
    return rc;
}


#endif  /* TPM_POSIX */

#ifdef TPM_WINDOWS      /* Windows sockets */

/* TPM_IO_Init initializes the TPM to host interface.

   This is the Windows platform dependent socket version.
*/

TPM_RESULT TPM_IO_Init(void)
{
    TPM_RESULT          rc = 0;
    int                 irc;
    short               port;
    
    printf(" TPM_IO_Init:\n");
    /* get the socket port number */
    if (rc == 0) {
        port_str = getenv("TPM_PORT");
        if (port_str == NULL) {
            printf("TPM_IO_Init: Error, TPM_PORT environment variable not set\n");
            rc = TPM_IOERROR;
        }
    }
    if (rc == 0) {
        irc = sscanf(port_str, "%hu", &port);
        if (irc != 1) {
            printf("TPM_IO_Init: Error, TPM_PORT environment variable invalid\n");
            rc = TPM_IOERROR;
        }
    }
    /* create a tcpip protocol socket */
    if (rc == 0) {
        rc = TPM_IO_ServerSocket_Open(&sock_fd,
                                      port,
                                      INADDR_ANY);
        if (rc != 0) {
            printf("TPM_IO_Init: Warning, could not open TCP/IP server socket.\n");
        }
    }
    if (rc == 0) {
        printf("TPM_IO_Init: Waiting for connections on port %d.\n",port);
    }
    if (rc != 0) {
        WSACleanup();
    }
    return rc;
}


/* Open a TCP Server socket given the provided parameters. Set it into
   listening mode so connections can be accepted on it.

   This is the Windows platform dependent socket version.
*/

static TPM_RESULT TPM_IO_ServerSocket_Open(SOCKET *sock_fd,
                                           short port,
                                           uint32_t in_addr)
{
    TPM_RESULT          rc = 0;
    int                 irc;
    WSADATA             wsaData;
    struct sockaddr_in  serv_addr;
    int                 opt;

    /* initiate use of the Windows Sockets DLL 2.0 */
    if (rc == 0) {
        if ((irc = WSAStartup(0x202,&wsaData)) != 0) {          /* if not successful */
            printf("TPM_IO_ServerSocket_Open: Error, WSAStartup()\n");
            TPM_HandleWsaStartupError("TPM_IO_Init:", irc);
            rc = TPM_IOERROR;
        }
    }
    /* create a tcpip protocol socket */
    if (rc == 0) {
        printf(" TPM_IO_ServerSocket_Open: Port %hu\n", port);
        *sock_fd = socket(AF_INET, SOCK_STREAM, 0);     /* tcpip socket */
        if (*sock_fd == INVALID_SOCKET) {
            printf("TPM_IO_ServerSocket_Open: Error, server socket()\n");
            TPM_HandleWsaError("TPM_IO_ServerSocket_Open:");
            rc = TPM_IOERROR;
        }
    }
    if (rc == 0) {
        memset((char *)&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;                 /* Internet socket */
        serv_addr.sin_port = htons(port);               /* host to network byte order for short */
        serv_addr.sin_addr.s_addr = htonl(in_addr);     /* host to network byte order for long */
        opt = 1;
        /* Set SO_REUSEADDR before calling bind() for servers that bind to a fixed port number. */
        /* For boolean values, opt must be an int, but the setsockopt prototype is IMHO wrong.
           It should take void *, but uses char *.  Hence the type cast. */       
        irc = setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
        if (irc == SOCKET_ERROR) {
            printf("TPM_IO_ServerSocket_Open: Error, server setsockopt()\n");
            TPM_HandleWsaError("TPM_IO_ServerSocket_Open:");
            closesocket(*sock_fd);
            *sock_fd = INVALID_SOCKET;
            rc = TPM_IOERROR;
        }
    }
    /* bind the (local) server port name to the socket */
    if (rc == 0) {
        irc = bind(*sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (irc == SOCKET_ERROR) {
            printf("TPM_IO_ServerSocket_Open: Error, server bind()\n");
            TPM_HandleWsaError("TPM_IO_ServerSocket_Open:");
            closesocket(*sock_fd);
            *sock_fd = INVALID_SOCKET;
            rc = TPM_IOERROR;
        }
    }
    /* listen for a connection to the socket */
    if (rc == 0) {
        irc = listen(*sock_fd, SOMAXCONN);
        if (irc == SOCKET_ERROR) {
            printf("TPM_IO_ServerSocket_Open: Error, server listen()\n");
            TPM_HandleWsaError("TPM_IO_ServerSocket_Open:");
            closesocket(*sock_fd);
            *sock_fd = INVALID_SOCKET;
            rc = TPM_IOERROR;
        }
    }
    return rc;
}

/* TPM_IO_Connect() establishes a connection between the TPM server and the host client
   
   This is the Windows platform dependent socket version.
*/

TPM_RESULT TPM_IO_Connect(TPM_CONNECTION_FD *connection_fd,     /* read/write file descriptor */
                          void *mainLoopArgs)
{
    TPM_RESULT          rc = 0;
    int                 cli_len;
    struct sockaddr_in  cli_addr;               /* Internet version of sockaddr */
    
    mainLoopArgs = mainLoopArgs;        /* not used */
    /* accept a connection */
    if (rc == 0) {
        cli_len = sizeof(cli_addr);
        /* block until connection from client */
        printf("\n TPM_IO_Connect: Waiting for connection on port %s...\n", port_str);
        connection_fd->fd = accept(sock_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (connection_fd->fd == SOCKET_ERROR) { 
            printf("TPM_IO_Connect: Error, accept()\n");
            TPM_HandleWsaError("TPM_IO_Connect: ");
            closesocket(sock_fd);
            WSACleanup();
            rc = TPM_IOERROR;
        }
    }
    return rc;
}

/* TPM_IO_ReadBytes() reads nbytes from connection_fd and puts them in buffer.

   The buffer has already been checked for sufficient size.

   This is the Windows platform dependent socket version.
*/

static TPM_RESULT TPM_IO_ReadBytes(TPM_CONNECTION_FD *connection_fd,    /* read/write file descriptor */
                                   unsigned char *buffer,
                                   size_t nbytes)
{
    TPM_RESULT rc = 0;
    int nread = 0;
    size_t nleft = nbytes;

    printf("  TPM_IO_ReadBytes: Reading %u bytes\n", nbytes);
    /* read() is unspecified with nbytes too large */
    if (rc == 0) {
        if (nleft > SSIZE_MAX) {
            rc = TPM_BAD_PARAMETER;
        }
    }
    while ((rc == 0) && (nleft > 0)) {
	/* cast for winsock.  Unix uses void * */
        nread = recv(connection_fd->fd, (char *)buffer, nleft, 0);
        if ((nread == SOCKET_ERROR) ||
            (nread < 0)) {                      /* error */
            printf("TPM_IO_ReadBytes: Error, read() error\n");
            TPM_HandleWsaError("TPM_IO_ReadBytes:");
            TPM_IO_Disconnect(connection_fd);
            rc = TPM_IOERROR;
        }
        else if (nread > 0) {
            nleft -= nread;
            buffer += nread;
        }           
        else if (nread == 0) {          /* EOF */
            printf("TPM_IO_ReadBytes: Error, read EOF, read %u bytes\n", nbytes - nleft);
            rc = TPM_IOERROR;
        }
    }
    return rc;
}

/* TPM_IO_Write() writes 'buffer_length' bytes to the host.
   
   This is the Windows platform dependent socket version.
*/

TPM_RESULT TPM_IO_Write(TPM_CONNECTION_FD *connection_fd,       /* read/write file descriptor */
                        const unsigned char *buffer,
                        size_t buffer_length)
{       
    TPM_RESULT  rc = 0;
    int         nwritten = 0;
    
    if (rc == 0) {
        TPM_PrintAll(" TPM_IO_Write:", buffer, buffer_length);
    }
    /* write() is unspecified with buffer_length too large */
    if (rc == 0) {
        if (buffer_length > SSIZE_MAX) {
            rc = TPM_BAD_PARAMETER;
        }
    }
    /* test that connection is open to write */
    if (rc == 0) {
        if (connection_fd->fd == SOCKET_ERROR) {
            printf("TPM_IO_Write: Error, connection not open, fd %d\n",
                   connection_fd->fd);
            rc = TPM_IOERROR;
        }
    }
    while ((rc == 0) && (buffer_length > 0)) {
	/* cast for winsock.  Unix uses void * */
        nwritten = send(connection_fd->fd, (char *)buffer, buffer_length, 0);
        if ((nwritten == SOCKET_ERROR) ||
            (nwritten < 0)) {
            printf("TPM_IO_Write: Error, send()\n");
            TPM_HandleWsaError("TPM_IO_Write:");        /* report the error */
            TPM_IO_Disconnect(connection_fd);
            rc = TPM_IOERROR;
        }           
        else {
            buffer_length -= nwritten;
            buffer += nwritten;
        }
    }
    return rc;
}

/* TPM_IO_Disconnect() breaks the connection between the TPM server and the host client

   This is the Windows platform dependent socket version.
*/

TPM_RESULT TPM_IO_Disconnect(TPM_CONNECTION_FD *connection_fd)
{
    TPM_RESULT  rc = 0;
    int         irc;

    /* close the connection to the client */
    if (rc == 0) {
        irc = closesocket(connection_fd->fd);
        connection_fd->fd = SOCKET_ERROR;       /* mark the connection closed */
        if (irc == SOCKET_ERROR) {
            printf("TPM_IO_Disconnect: Error, closesocket()\n");
            rc = TPM_IOERROR;
        }
    }
    return rc;
}


void TPM_HandleWsaStartupError(const char *prefix,
                               int irc)
{
    const char *error_string;

    TPM_GetWsaStartupError(irc, &error_string);
    printf("%s %s\n", prefix, error_string);
    return;
}

static void TPM_HandleWsaError(const char *prefix)
{
    const char *error_string;

    TPM_GetWsaError(&error_string);
    printf("%s %s\n", prefix, error_string);
    return;
}

static void TPM_GetWsaStartupError(int status,
                                   const char **error_string)
{
    /* convert WSAStartup status to more useful text.  Copy the text to error_string */
       
    switch(status) {
      case WSASYSNOTREADY:
        *error_string = "WSAStartup error: WSASYSNOTREADY underlying network subsystem not "
			"ready for network communication";
        break;
      case WSAVERNOTSUPPORTED:
        *error_string = "WSAStartup error: WSAVERNOTSUPPORTED version requested not provided by "
			"WinSock implementation";
        break;
      case WSAEINPROGRESS:
        *error_string = "WSAStartup error: WSAEINPROGRESS blocking WinSock 1.1 operation in "
			"progress";
        break;
      case WSAEPROCLIM:
        *error_string = "WSAStartup error: WSAEPROCLIM Limit on number of tasks supported by "
			"WinSock implementation has been reached";
        break;
      case WSAEFAULT:
        *error_string = "WSAStartup error: WSAEFAULT lpWSAData is not a valid pointer";
        break;
      default:
        *error_string = "WSAStartup error: return code unknown";
        break;
    }
    return;
}

static void TPM_GetWsaError(const char **error_string)
{
    /* Use WSAGetLastError, and convert the resulting number
       to more useful text.  Copy the text to error_string */
    
    int error;
        
    error = WSAGetLastError();
    switch(error) {

      case WSANOTINITIALISED :
        *error_string = "A successful WSAStartup must occur before using this function";
        break;
      case WSAENETDOWN :
        *error_string = "The network subsystem or the associated service provider has failed";
        break;
      case WSAEAFNOSUPPORT :
        *error_string = "The specified address family is not supported";
        break;
      case WSAEINPROGRESS :
        *error_string = "A blocking Windows Sockets 1.1 call is in progress, "
                        "or the service provider is still processing a callback function";
        break;
      case WSAEMFILE:
        *error_string = "No more socket descriptors are available";
        break;
      case WSAENOBUFS:
        *error_string = "No buffer space is available";
        break;
      case WSAEPROTONOSUPPORT:
        *error_string = "The specified protocol is not supported";
        break;
      case WSAEPROTOTYPE:
        *error_string = "The specified protocol is the wrong type for this socket";
        break;
      case WSAESOCKTNOSUPPORT :
        *error_string = "The specified socket type is not supported in this address family";
        break;
      case WSAEFAULT:
        *error_string = "A parameter is too small, bad format, or bad value";
        break;
      case WSAEINVAL:
        *error_string = "The socket has not been bound with bind, or listen not called";
        break;
      case WSAENETRESET:
        *error_string = "The connection has been broken due to the remote host resetting";
        break;
      case WSAENOPROTOOPT:
        *error_string = "The option is unknown or unsupported for the specified provider";
        break;
      case WSAENOTCONN:
        *error_string = "Connection has been reset when SO_KEEPALIVE is set";
        break;
      case WSAENOTSOCK:
        *error_string = "The descriptor is not a socket";
        break;
      case WSAEADDRINUSE:
        *error_string = "The specified address is already in use";
        break;
       case WSAEISCONN:
        *error_string = "The socket is already connected";
        break;
     case WSAEOPNOTSUPP:
        *error_string = "The referenced socket is not of a type that supports the operation";
        break;
       case WSAEINTR:
        *error_string = "The (blocking) call was canceled through WSACancelBlockingCall";
     case WSAEWOULDBLOCK:
        *error_string = "The socket is marked as nonblocking and no connections are present to be "
			"accepted";
        break;
      case WSAESHUTDOWN:
        *error_string = "The socket has been shut down; it is not possible to recv or send on a "
			"socket after shutdown has been invoked with how set to SD_RECEIVE or "
			"SD_BOTH";
        break;
      case WSAEMSGSIZE:
        *error_string = "The message was too large to fit into the specified buffer and was "
			"truncated";
        break;
      case WSAECONNABORTED:
        *error_string = "The virtual circuit was terminated due to a time-out or other failure. "
                        "The application should close the socket as it is no longer usable";
        break;
      case WSAETIMEDOUT:
        *error_string = "The connection has been dropped because of a network failure or because "
                        "the peer system failed to respond";
        break;
      case WSAECONNRESET:
        *error_string = "The virtual circuit was reset by the remote side executing a hard or "
			"abortive close. The application should close the socket as it is no "
			"longer usable. On a UDP datagram socket this error would indicate that "
			"a previous send operation resulted in an ICMP Port Unreachable message";
        break;
       case WSAEACCES:
        *error_string = "The requested address is a broadcast address, but the appropriate flag "
			"was not set";
        break;
       case WSAEHOSTUNREACH:
        *error_string = "The remote host cannot be reached from this host at this time";
        break;
                
      default:
        *error_string = "unknown error type\n";
        break;
    }
    return;
}

#endif  /* TPM_WINDOWS */
