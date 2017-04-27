/********************************************************************************/
/*										*/
/*			    Windows TPM Proxy	 				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*		$Id: tpm_proxy.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
/*										*/
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

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <windows.h>

#define LOAD32(buffer,offset)         ( ntohl(*(uint32_t *)&(buffer)[(offset)]) )
#ifndef SSIZE_MAX
#define SSIZE_MAX INT_MAX
#endif


/* standard TCG definitions */

typedef unsigned long 	TSS_RESULT;
typedef unsigned char 	BYTE;
typedef unsigned short 	TPM_TAG;

/* TDDL function prototypes */
typedef TSS_RESULT (*TddlOpen)(void);
typedef TSS_RESULT (*TddlTransmitData)(BYTE *pTransmitBuf,
				       uint32_t TransmitBufLen,
				       BYTE *pReceiveBuf,
				       uint32_t *pReceiveBufLen);
typedef TSS_RESULT (*TddlClose)(void);

/* local constants */

#define ERROR_CODE	-1
#define DEFAULT_PORT 	6544
#define PACKET_SIZE	4096
#define TRACE_SIZE	(PACKET_SIZE * 4)

/* local prototypes */

void printUsage(void);
long getArgs(short *port,
	     int *verbose,
	     char **logFileName,
	     int argc,
	     char **argv);
void logAll(const char *message, unsigned long length, const unsigned char* buff);

TSS_RESULT socketInit(SOCKET *sock_fd, short port);
TSS_RESULT socketConnect(SOCKET *accept_fd,
			 SOCKET sock_fd,
			 short port);
TSS_RESULT socketRead(SOCKET accept_fd,
		      char *buffer,
		      uint32_t *bufferLength,
		      size_t bufferSize);
TSS_RESULT socketReadBytes(SOCKET accept_fd,
			   char *buffer,
			   size_t nbytes);
TSS_RESULT socketWrite(SOCKET accept_fd,
		       const char *buffer,
		       size_t buffer_length);
TSS_RESULT socketDisconnect(SOCKET accept_fd);

void TPM_HandleWsaStartupError(const char *prefix,
			       int irc);
void TPM_HandleWsaError(const char *prefix);
void TPM_GetWsaStartupError(int status,
			    const char **error_string);
void TPM_GetWsaError(const char **error_string);


/* global variable for trace logging */

int 	verbose;	/* verbose debug tracing */
char 	*logFilename;	/* trace log file name */
char	logMsg[TRACE_SIZE];	/* since it's big, put it here rather than on the stack */

int main(int argc, char** argv)
{
    HMODULE 		h = 0;
    TSS_RESULT 		rc = 0;
    time_t 		start_time;
    TddlOpen 		tddlOpen = NULL;	/* TDDL_Open dll function pointer */
    TddlTransmitData 	tddlTransmitData = NULL; /* TDDL_TransmitData dll function pointer */
    TddlClose 		tddlClose = NULL;	/* TDDL_Close dll function pointer */
    SOCKET 		sock_fd;		/* server socket */
    SOCKET 		accept_fd;    		/* server accept socket for a packet */
    int 		socketOpened = FALSE;

    /* TPM command and response */
    BYTE command[PACKET_SIZE]; 
    uint32_t commandLength;
    BYTE response[PACKET_SIZE];
    uint32_t responseLength;
		      
    /* command line arguments */
    short port;			/* TCPIP server port */

    /* command line argument defaults */
    port = DEFAULT_PORT;
    logFilename = NULL;
    verbose = FALSE;

    /* initialization */
    setvbuf(stdout, 0, _IONBF, 0);	/* output may be going through pipe */
    start_time = time(NULL);
    
    /* get command line arguments */
    if (rc == 0) {
	rc = getArgs(&port, &verbose, &logFilename,
		     argc, argv);
    }
    /* since the TPM driver is not shipped with a .lib file, can't link to tddl, have to find the
       functions at run time */
    if (rc == 0) {
	h = LoadLibrary("tddl.dll");
	if (h == 0) {
	    printf("Cannot load library tddl.dll\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	tddlOpen = (TddlOpen) GetProcAddress(h, "TDDL_Open");
	tddlTransmitData = (TddlTransmitData) GetProcAddress(h, "TDDL_TransmitData");
	tddlClose = (TddlClose) GetProcAddress(h, "TDDL_Close");
	if ((tddlOpen == NULL) ||
	    (tddlTransmitData == NULL) ||
	    (tddlClose == NULL)) {
	    printf("Cannot find TDDL functions in tddl.dll\n");
	    printf("tddlOpen %p\n", tddlOpen);
	    printf("tddlTransmitData %p\n", tddlTransmitData);
	    printf("tddlClose %p\n", tddlClose);
	    rc = ERROR_CODE;
	}
    }
    /* open TPM */
    if (rc == 0) {
	printf("tpm_proxy: start at %s", ctime(&start_time));
	if (verbose) printf("Opening TPM\n");
	rc = (*tddlOpen)();
	if (rc != 0) {
	    printf("TDDL_Open failed, rc %ld\n", rc);
	}
    }
#if 0
    /* test code, send TPM_Startup */
    if (rc == 0) {
	unsigned char tpm_startup[] = {0x00,0xC1,0x00,0x00,0x00,0x0C,0x00,0x00,0x00,0x99,0x00,0x01};
	memcpy(command, tpm_startup, sizeof(tpm_startup));
	commandLength = sizeof(tpm_startup);
	responseLength = sizeof(response);
	rc = (*tddlTransmitData)(command,
				 commandLength,
				 response,
				 &responseLength);
	printf("TDDL_TransmitData rc %d\n", rc);
    }
    if (rc == 0) {
	unsigned int 	i;
	printf("TDDL_TransmitData response length %d\n", responseLength);
	for (i = 0 ; i < responseLength ; i++) {
	    printf("%02x", response[i]);
	    printf("\n");
	}
    }
#endif
    /* initialize server socket */
    if (rc == 0) {
	if (verbose) printf("Opening socket at port %hu\n", port);
	rc = socketInit(&sock_fd, port);
	if (rc != 0) {
	    printf("socket open failed\n");
	}
	else {
	    socketOpened = TRUE;
	}
    }
    /* main loop */
    while (rc == 0) {
	/* connect to the client application */
	if (rc == 0) {
	    if (verbose) printf("Connecting on socket\n");
	    rc = socketConnect(&accept_fd, sock_fd, port);
	}
	/* read a command from client */
	if (rc == 0) {
	    rc = socketRead(accept_fd,
			    (char *)command,	/* windows wants signed */
			    &commandLength,
			    sizeof(command));
	    logAll("Command", commandLength, command);
	}
	/* send command to TPM and receive response */
	if (rc == 0) {
	    responseLength = sizeof(response);
	    rc = (*tddlTransmitData)(command,
				     commandLength,
				     response,
				     &responseLength);
	    if (rc != 0) {
		printf("TDDL_TransmitData: error 0x%08lx %ld\n", rc, rc);
	    }
	}
	/* send response to client */
	if (rc == 0) {
	    logAll("Response", responseLength, response);
	    rc = socketWrite(accept_fd,
			     (char *)response,	/* windows wants signed */
			     responseLength);
	}
	/* disconnect from client */
	if (rc == 0) {
	    rc = socketDisconnect(accept_fd);
	}
    }
    /* close TPM */
    if (tddlClose != NULL) {
	(*tddlClose)();
    }
    /* close socket */
    if (socketOpened) {
	socketDisconnect(sock_fd);
    }
    return rc;
}

/*
  All the socket code is basically a cut and paste from tpm_io.c
*/

TSS_RESULT socketInit(SOCKET *sock_fd, short port)
{
    TSS_RESULT   	rc = 0;
    int			irc;
    struct sockaddr_in 	serv_addr;
    int 		opt;
    WSADATA 		wsaData;

    /* initiate use of the Windows Sockets DLL 2.0 */
    if (rc == 0) {
	if ((irc = WSAStartup(0x202,&wsaData)) != 0) {		/* if not successful */
	    printf("socketInit: Error, WSAStartup()\n");
	    TPM_HandleWsaStartupError("socketInit:", irc);
	    rc = ERROR_CODE;
	}
    }
    /* create a tcpip protocol socket */
    if (rc == 0) {
	/* if (verbose) printf(" socketInit: Port %hu\n", port); */
	*sock_fd = socket(AF_INET, SOCK_STREAM, 0);	/* tcpip socket */
	if (*sock_fd == INVALID_SOCKET) {
	    printf("socketInit: Error, server socket()\n");
	    TPM_HandleWsaError("socketInit:");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;			/* Internet socket */
	serv_addr.sin_port = htons(port);		/* host to network byte order for short */
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);	/* host to network byte order for long */
	opt = 1;
	/* Set SO_REUSEADDR before calling bind() for servers that bind to a fixed port number. */
	/* For boolean values, opt must be an int, but the setsockopt prototype is IMHO wrong.
	   It should take void *, but uses char *.  Hence the type cast. */       
	irc = setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
	if (irc == SOCKET_ERROR) {
	    printf("socketInit: Error, server setsockopt()\n");
	    TPM_HandleWsaError("socketInit:");
	    closesocket(*sock_fd);
	    rc = ERROR_CODE;
	}
    }
    /* bind the (local) server port name to the socket */
    if (rc == 0) {
	irc = bind(*sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (irc == SOCKET_ERROR) {
	    printf("socketInit: Error, server bind()\n");
	    TPM_HandleWsaError("socketInit:");
	    closesocket(*sock_fd);
	    rc = ERROR_CODE;
	}
    }
    /* listen for a connection to the socket */
    if (rc == 0) {
	irc = listen(*sock_fd, SOMAXCONN);
	if (irc == SOCKET_ERROR) {
	    printf("socketInit: Error, server listen()\n");
	    TPM_HandleWsaError("socketInit:");
	    closesocket(*sock_fd);
	    rc = ERROR_CODE;
	}
    }
    if (rc != 0) {
	WSACleanup();
    }
    return rc;
}

TSS_RESULT socketConnect(SOCKET *accept_fd,
			 SOCKET sock_fd,
			 short port)
{
    TSS_RESULT		rc = 0;
    int			cli_len;
    struct sockaddr_in 	cli_addr;		/* Internet version of sockaddr */
    
    /* accept a connection */
    if (rc == 0) {
	cli_len = sizeof(cli_addr);
	/* block until connection from client */
	/* printf(" socketConnect: Waiting for connection on port %hu ...\n", port); */
	*accept_fd = accept(sock_fd, (struct sockaddr *)&cli_addr, &cli_len);
	if (*accept_fd == SOCKET_ERROR) { 
	    printf("socketConnect: Error, accept()\n");
	    TPM_HandleWsaError("socketConnect: ");
	    closesocket(sock_fd);
	    WSACleanup();
	    rc = ERROR_CODE;
	}
    }
    return rc;
}

/* socketRead() reads a TPM command packet from the host

   Puts the result in 'buffer' up to 'bufferSize' bytes.

   On success, the number of bytes in the buffer is equal to 'bufferLength' bytes

   This function is intended to be platform independent.
*/

TSS_RESULT socketRead(SOCKET accept_fd,		/* read/write file descriptor */
		      char *buffer,		/* output: command stream */
		      uint32_t *bufferLength,	/* output: command stream length */
		      size_t bufferSize)	/* input: max size of output buffer */
{	
    TSS_RESULT		rc = 0;
    uint32_t		headerSize;	/* minimum required bytes in command through paramSize */
    uint32_t		paramSize;	/* from command stream */
    
    /* check that the buffer can at least fit the command through the paramSize */
    if (rc == 0) {
	headerSize = sizeof(TPM_TAG) + sizeof(uint32_t);	
	if (bufferSize < headerSize) {
	    printf("socketRead: Error, buffer size %u less than minimum %u\n",
		   bufferSize, headerSize);
	    rc = ERROR_CODE;
	}
    }
    /* read the command through the paramSize from the socket stream */
    if (rc == 0) {
	rc = socketReadBytes(accept_fd, buffer, headerSize);
    }
    if (rc == 0) {
	/* extract the paramSize value, last field in header */
	paramSize = LOAD32(buffer, headerSize - sizeof(uint32_t));
	*bufferLength = headerSize + paramSize - (sizeof(TPM_TAG) + sizeof(uint32_t));
	if (bufferSize < *bufferLength) {
	    printf("socketRead: Error, buffer size %u is less than required %u\n",
		   bufferSize, *bufferLength);
	    rc = ERROR_CODE;
	}
    }
    /* read the rest of the command (already read tag and paramSize) */
    if (rc == 0) {
	rc = socketReadBytes(accept_fd,
			     buffer + headerSize,
			     paramSize - (sizeof(TPM_TAG) + sizeof(uint32_t)));
    }
    return rc;
}


/* socketReadBytes() reads nbytes from accept_fd and puts them in buffer.

   The buffer has already been checked for sufficient size.
*/

TSS_RESULT socketReadBytes(SOCKET accept_fd,	/* read/write file descriptor */
			   char *buffer,
			   size_t nbytes)
{
    TSS_RESULT rc = 0;
    int nread = 0;
    size_t nleft = nbytes;

    /* read() is unspecified with nbytes too large */
    if (rc == 0) {
	if (nleft > SSIZE_MAX) {
	    rc = ERROR_CODE;
	}
    }
    while ((rc == 0) && (nleft > 0)) {
	nread = recv(accept_fd, buffer, nleft, 0);
	if ((nread == SOCKET_ERROR) ||
	    (nread < 0)) {       		/* error */
	    printf("socketReadBytes: Error, read() error\n");
	    TPM_HandleWsaError("socketReadBytes:");
	    socketDisconnect(accept_fd);
            rc = ERROR_CODE;
	}
	else if (nread > 0) {
	    nleft -= nread;
	    buffer += nread;
	}	    
	else if (nread == 0) {  	/* EOF */
	    printf("socketReadBytes: Error, read EOF, read %u bytes\n", nbytes - nleft);
            rc = ERROR_CODE;
	}
    }
    return rc;
}

TSS_RESULT socketWrite(SOCKET accept_fd,	/* read/write file descriptor */
		       const char *buffer,
		       size_t buffer_length)
{	
    TSS_RESULT 	rc = 0;
    int		nwritten = 0;
    
    /* write() is unspecified with buffer_length too large */
    if (rc == 0) {
	if (buffer_length > SSIZE_MAX) {
	    rc = ERROR_CODE;
	}
    }
    /* test that connection is open to write */
    if (rc == 0) {
	if (accept_fd == SOCKET_ERROR) {
	    printf("socketWrite: Error, connection not open, fd %d\n",
		   accept_fd);
	    rc = ERROR_CODE;
	}
    }
    while ((rc == 0) && (buffer_length > 0)) {
	nwritten = send(accept_fd, buffer, buffer_length, 0);
	if ((nwritten == SOCKET_ERROR) ||
	    (nwritten < 0)) {
	    printf("socketWrite: Error, send()\n");
	    TPM_HandleWsaError("socketWrite:");	/* report the error */
	    socketDisconnect(accept_fd);
	    rc = ERROR_CODE;
	}	    
	else {
	    buffer_length -= nwritten;
	    buffer += nwritten;
	}
    }
    return rc;
}

/* socketDisconnect() breaks the connection between the TPM server and the host client

   This is the Windows platform dependent socket version.
*/

TSS_RESULT socketDisconnect(SOCKET accept_fd)
{
    TSS_RESULT 	rc = 0;
    int		irc;

    /* close the connection to the client */
    if (rc == 0) {
	irc = closesocket(accept_fd);
	accept_fd = SOCKET_ERROR;	/* mark the connection closed */
	if (irc == SOCKET_ERROR) {
	    printf("socketDisconnect: Error, closesocket()\n");
	    rc = ERROR_CODE;
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

void TPM_HandleWsaError(const char *prefix)
{
    const char *error_string;

    TPM_GetWsaError(&error_string);
    printf("%s %s\n", prefix, error_string);
    return;
}

void TPM_GetWsaStartupError(int status,
			    const char **error_string)
{
    /* convert WSAStartup status to more useful text.  Copy the text to error_string */
       
    switch(status) {
      case WSASYSNOTREADY:
	*error_string = "WSAStartup error: WSASYSNOTREADY underlying network subsystem not ready for "
			"network communication";
	break;
      case WSAVERNOTSUPPORTED:
	*error_string = "WSAStartup error: WSAVERNOTSUPPORTED version requested not provided by WinSock "
			"implementation";
	break;
      case WSAEINPROGRESS:
	*error_string = "WSAStartup error: WSAEINPROGRESS blocking WinSock 1.1 operation in progress";
	break;
      case WSAEPROCLIM:
	*error_string = "WSAStartup error: WSAEPROCLIM Limit on number of tasks supported by WinSock "
			"implementation has been reached";
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

void TPM_GetWsaError(const char **error_string)
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
	*error_string = "The socket is marked as nonblocking and no connections are present to be accepted";
	break;
      case WSAESHUTDOWN:
	*error_string = "The socket has been shut down; it is not possible to recv or send on a socket "
			"after shutdown has been invoked with how set to SD_RECEIVE or SD_BOTH";
	break;
      case WSAEMSGSIZE:
	*error_string = "The message was too large to fit into the specified buffer and was truncated";
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
	*error_string = "The virtual circuit was reset by the remote side executing a hard or abortive close. "
			"The application should close the socket as it is no longer usable. On a UDP datagram "
			"socket this error would indicate that a previous send operation resulted in an ICMP "
			"Port Unreachable message";
	break;
      case WSAEACCES:
	*error_string = "The requested address is a broadcast address, but the appropriate flag was not set";
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


/* logging, tracing */

void logAll(const char *message, unsigned long length, const unsigned char* buff)
{
    unsigned long i;
    size_t 	nextChar = 0;
    FILE 	*logFile;	/* trace log file descriptor */

    /* construct the log message, keep appending to the character string */
    if (buff != NULL) {
	nextChar += sprintf(logMsg + nextChar, "%s length %lu\n ", message, length);
	for (i = 0 ; i < length ; i++) {
	    if (i && !( i % 16 )) {
		nextChar += sprintf(logMsg + nextChar, "\n ");
	    }
	    nextChar += sprintf(logMsg + nextChar, "%.2X ",buff[i]);
	}
	nextChar += sprintf(logMsg + nextChar, "\n");
    }
    else {
	nextChar += sprintf(logMsg + nextChar, "%s null\n", message);
    }
    if (verbose) printf("%s", logMsg);
    if (logFilename != NULL) {
	/* Open the log file if specified.  It's a hack to keep opening and closing the file for
	   each append, but it's easier that trying to catch a signal to close the file.  Windows
	   evidently doesn't automatically close the file when the program exits. */
	logFile = fopen(logFilename, "a");
	if (logFile == NULL) {
	    printf("Error, opening %s for write failed, %s\n",
		   logFilename, strerror(errno));
	}
	/* if success, print and close */
	else {
	    fprintf(logFile, "%s", logMsg);
	    fclose(logFile);
	}
    }
    return;
}

/* parse the command line arguments */

long getArgs(short *port,
	     int *verbose,
	     char **logFilename,
	     int argc,
	     char **argv)
{
    long 	rc = 0;
    int		irc;
    int 	i;
    FILE 	*logFile;	/* trace log file descriptor */

    /* get the command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if ((strcmp(argv[i],"-p") == 0) ||
	    (strcmp(argv[i],"--port") == 0)) {
	    i++;
	    if (i < argc) {
		irc = sscanf(argv[i], "%hu", port);
		if (irc != 1) {
		    printf("-p --port (socket port) illegal value %s\n", argv[i]);
		    rc = ERROR_CODE;
		}
	    } else {
		printf("-p --port (socket port) needs a value\n");
		rc = ERROR_CODE;
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	    rc = ERROR_CODE;
	}
	else if ((strcmp(argv[i],"-v") == 0) ||
		 (strcmp(argv[i],"--verbose") == 0)) {
	    *verbose = TRUE;
	}
	else if ((strcmp(argv[i],"-l") == 0) ||
		 (strcmp(argv[i],"--log") == 0)) {
	    i++;
	    if (i < argc) {
		if (strlen(argv[i]) < FILENAME_MAX) {
		    *logFilename = argv[i];
		}
		else {
		    printf("-l --log (log file name) too long\n");
		    rc = ERROR_CODE;
		}
	    }
	    else {
		printf("-l --log option (log file name) needs a value\n");
		rc = ERROR_CODE;
	    }
	}
	else {
	    printf("\n%s is not a valid option\n",argv[i]);
	    printUsage();
	    rc = ERROR_CODE;
	}
    }
    /* erase old contents of log file */
    if ((rc == 0) && (*logFilename != NULL)) {
	logFile = fopen(*logFilename, "w");
	if (logFile == NULL) {
	    printf("Cannot open log file %s\n", *logFilename);
	    rc = ERROR_CODE;
	}
	else {
	    fclose(logFile);
	}
    }
    return rc;
}

void printUsage()
{
    printf("\n");
    printf("tpm_proxy\n");
    printf("\n");
    printf("Pass through connecting a TCPIP port to a hardware TPM\n");
    printf("\n");
    printf("\t--port,-p <n> TCPIP server port (default 6544)\n");
    printf("\t--verbose,-v verbose mode (default false)\n");
    printf("\t--log,-l log transactions into given file (default none)\n");
    printf("\t \n");
    return;
}

