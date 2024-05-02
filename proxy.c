/*
 * proxy.c - CS:APP Web proxy
 *
 * TEAM MEMBERS:  put your name(s) and e-mail addresses here
 *     Garrett Parker, parkegp0@sewanee.edu
 *     Michael Komnick, komnimj0@sewanee.edu
 * 
 * This code is a proxy program in which functions a premetive logging
 * and firewall middle man for processing http requests.
 */ 

#include "csapp.h"
#include <sys/stat.h>

/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400

// For reading in the blocklist line by line
#define BUFFER_SIZE_BYTES 255

/* You won't lose style points for including this long line in your code */
static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";

/*
 * Function prototypes
 */
int parse_uri(char *uri, char *target_addr, char *path, int  *port);
void format_log_entry(char *logstring, int fd, 
                        char *uri, int size);
void *thread(void *vargp);
void read_requesthdrs(rio_t *rp, char *dest) ;
void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg);
void readBlocklist();
char **blockList;

// Semaphore to protect the log file writing
volatile long cnt = 0;
sem_t mutex;

/* 
 * main - Main routine for the proxy program 
 */
int main(int argc, char **argv){
    /* Check arguments */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
        exit(0);
    }

    //Carl Note: we believe it should crash here,
    //because if it continues it could corrupt the log file.
    Sem_init(&mutex, 0, 1);

    //loads Blocklist to mem
    readBlocklist();

    //ignore SIGPIPE
    Signal(SIGPIPE,SIG_IGN);

    int listenfd, *connfdp;
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;
    pthread_t tid;

    //listens for connection on port, if connection is accepted,
    //creates a thread to handle that connection.
    listenfd = Open_listenfd(argv[1]);
    while (1) {
        clientlen = sizeof(clientaddr);
        connfdp = Malloc(sizeof(int));
        *connfdp = Accept(listenfd, (SA *)&clientaddr, &clientlen); 
        Pthread_create(&tid, NULL, thread, connfdp);
    }

    //frees mem of Blocklist
    if(blockList != NULL) {
        // Freeing the blocklist
        int i = 0;
        while(blockList[i] != NULL) {
            free(blockList[i]);
            i++;
        }
        free(blockList);
    }

    return 0;
}


/* 
 * readBlocklist - Read from file to create a simple firewall 
 * that prevents access to certain sites.
 */
void readBlocklist() {
    char *path = "blocklist";
    FILE *fp = fopen(path, "r");
    if(fp == NULL) {
        printf("WARNING:\nThe blocklist file either doesn't exist or cannot be opened.\n");
        return;
    }

    int num_lines = 1;
    blockList = malloc(sizeof(blockList[0]) * num_lines);

    char *new_line = NULL;
    size_t str_len = 0;
    ssize_t bytes_read;
    while ((bytes_read = getline(&new_line, &str_len, fp)) != -1) {
        new_line[strcspn(new_line, "\n")] = 0;

        // Resize the array we allocated on the heap
        void *ptr = realloc(blockList, (num_lines + 1) * sizeof(blockList[0]));

        // Check if the allocation was successful
        if (ptr == NULL) {
          fprintf(stderr, "Failed to allocate memory at %s:%d\n", __FILE__, __LINE__);
        //   assert(false);
        }
        // Overwrite `lines` with the pointer to the new memory region only if realloc() was successful
        blockList = ptr;

        // Allocate a copy on the heap
        // so that the array elements don't all point to the same buffer
        blockList[num_lines - 1] = strdup(new_line);

        // Keep track of the size of the array
        num_lines++;
    }

    // Free the buffer that was allocated by getline()
    free(new_line);
    // Close the file since we're done with it
    fclose(fp);

    return;
}

/*
 * *thread - handles the connection after it is established.
 *
 * Given a connection from listenfd
 * 
 */
void *thread(void *vargp) {
    int connfd = *((int *)vargp);
    Pthread_detach(pthread_self());
    free(vargp);

    char buf[MAXLINE], method[MAXLINE], 
         uri[MAXLINE], version[MAXLINE],
         filename[MAXLINE], pathname[MAXLINE], 
         request[MAXLINE];
    int requestfd, *port = Malloc(sizeof(int)); 
    rio_t rio;

    //ignore SIGPIPE
    Signal(SIGPIPE,SIG_IGN);

    /* Read request line and headers */

    // Associating file descriptor with the rio buffer
    Rio_readinitb(&rio, connfd);
    
    // Checking if reading a line into the buffer encountered an error
    // This was "if(!Rio_readlineb(&rio, buf, MAXLINE)) return NULL;"
    // This should still work though
    if (rio_readlineb(&rio, buf, MAXLINE) < 0) {
        close(connfd);
        return NULL;
    }

    // This is the client's request that was sent to the proxy
    // printf("%s", buf);

    // Copying the buffer components into their corresponding variables
    sscanf(buf, "%s %s %s", method, uri, version);

    // Disregarding methods other than GET
    if (strcasecmp(method, "GET")) {
        clienterror(
            connfd,
            filename,
            "405",
            "Method Not Allowed",
            "This HTTP method is not allowed using this proxy."
        );
        return NULL;
    }

    // Separating the URI into the filename (aka host), pathname, and port
    parse_uri(uri, filename, pathname, port); 
    
    // Filtering out hosts in the blocked list
    if(blockList != NULL) {
        int i = 0;
        while(blockList[i] != NULL) {
            if(strcmp(filename, blockList[i]) == 0) {
                clienterror(
                    connfd,
                    filename,
                    "403",
                    "Blocked Host",
                    "This website has been blocked as it may be malicious."
                );
                return NULL;
            }
            i++;
        }
    }

    // Reading the rest of the HTTP request headers
    char remainingHeaders[MAXLINE];
    read_requesthdrs(&rio, remainingHeaders);
    // printf("THESE ARE THE HEADERS TO TOKENISE:\n%s\n", remainingHeaders);

    // Proxy make request
    // Storing the port as a string
    char portStr[MAXLINE];
    snprintf(portStr, sizeof(portStr), "%d", *port);
    if((requestfd = open_clientfd(filename, portStr)) < 0) {
        printf("Error opeining connection to %s\n", uri);
        clienterror(
                    connfd,
                    filename,
                    "404",
                    "Failure to find page",
                    "This server might be down or page doesn't exist."
                   );
        return NULL;
    }

    // Preparing the request
    snprintf(request, sizeof(request), "%s /%s %s\r\n", 
            method, pathname, "HTTP/1.0");

    char hostHead[MAXLINE];
    snprintf(hostHead, sizeof(hostHead)+200, "Host: %s\r\n", filename);

    strcat(request,hostHead);
    strcat(request, user_agent_hdr);
    strcat(request,"Connection: close\r\n");
    strcat(request,"Proxy-Connection: close\r\n");

    char *token = strtok(remainingHeaders, "\r\n");
    // printf("FIRST TOKEN:\n%s\n", token);
    while(token != NULL) {
        if(!strstr(token, "Host: ") && !strstr(token, "User-Agent: ") &&
           !strstr(token, "Connection: ") && !strstr(token, "Proxy-Connection: ")) {
            strcat(token, "\r\n");
            strcat(request, token);
        }
        token = strtok(NULL, "\r\n");
    }
    strcat(request,"\r\n");
    // printf("THE REQUEST TO SEND: \n%s", request);

    // Sending the request
    if(rio_writen(requestfd, request, strlen(request)) != strlen(request)){
        printf("Error sending request to server!\n");
    }

    //begin recieving and sending final headers
    size_t rLen = 0;
    int n;
    while((n = rio_readn(requestfd, buf, MAXLINE)) > 0) {
        rLen += n;
        if(rio_writen(connfd, buf, strlen(buf)) != strlen(buf)) {
            printf("Error sending response to client!\n");
        }
        bzero(buf, MAXLINE);
    }
    int rSize = rLen * 8;

    // Logging the response
    char logString[MAXLINE];
    format_log_entry(logString, requestfd, uri, rSize);
    P(&mutex);
    FILE *logptr;
    logptr = fopen("proxy.log", "a");
    fprintf(logptr, "%s",logString);
    fclose(logptr);
    V(&mutex);
    // printf("LOG TEST: %s", logString);

    // Closing the connections
    close(requestfd);
    close(connfd);

    return NULL;
}

/*
 * read_requesthdrs - Read Request Header
 * 
 * reads all request headers from the client to console.
 * 
 */
void read_requesthdrs(rio_t *rp, char *dest) {
    char buf[MAXLINE];

    // Reading the first header line into the buffer
    rio_readlineb(rp, buf, MAXLINE);
    // printf("%s", buf);
    strcat(dest, buf);

    // Getting the rest of the header lines
    while(strcmp(buf, "\r\n")) {
        rio_readlineb(rp, buf, MAXLINE);
        // printf("%s", buf);
        strcat(dest, buf);
    }

    // printf("Request Headers Variable:\n%s",requestHeaders);

    return;
}

/*
 * parse_uri - URI parser
 * 
 * Given a URI from an HTTP proxy GET request (i.e., a URL), extract
 * the host name, path name, and port.  The memory for hostname and
 * pathname must already be allocated and should be at least MAXLINE
 * bytes. Return -1 if there are any problems.
 */
int parse_uri(char *uri, char *hostname, char *pathname, int *port){
    char *hostbegin;
    char *hostend;
    char *pathbegin;
    int len;

    if (strncasecmp(uri, "http://", 7) != 0) {
        hostname[0] = '\0';
        return -1;
    }
       
    /* Extract the host name */
    hostbegin = uri + 7;
    hostend = strpbrk(hostbegin, " :/\r\n\0");
    if (hostend) {
        len = hostend - hostbegin;
    } else {
        len = strlen(hostbegin);
    }
    
    strncpy(hostname, hostbegin, len);
    hostname[len] = '\0';

    
    /* Extract the port number */
    *port = 80; /* default */
    if (hostend && *hostend == ':')   
	    *port = atoi(hostend + 1);
    
    /* Extract the path */
    pathbegin = strchr(hostbegin, '/');
    if (pathbegin == NULL) {
	    pathname[0] = '\0';
    }
    else {
        pathbegin++;	
        strcpy(pathname, pathbegin);
    }

    return 0;
}

/*
 * format_log_entry - Create a formatted log entry in logstring. 
 * 
 * The inputs are the socket address of the requesting client
 * (sockaddr), the URI from the request (uri), and the size in bytes
 * of the response from the server (size).
 */
void format_log_entry(char *logstring, int fd, char *uri, int size) {
    time_t now;
    char time_str[MAXLINE];
    char host[INET_ADDRSTRLEN];
 
    /* Get a formatted time string */
    now = time(NULL);
    strftime(time_str, sizeof(time_str), "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

    /* 
     * Next, convert the IP address in network byte order to dotted decimal
     * form. Note that we could have used inet_ntoa, but chose not to
     * because inet_ntoa is a Class 3 thread unsafe function that
     * returns a pointer to a static variable (Ch 13, CS:APP).
     */
    struct sockaddr_in addr;
    inet_ntop(AF_INET, &(addr.sin_addr), host, INET_ADDRSTRLEN);
    
    /* Finally, store (and return) the formatted log entry string in logstring */
    snprintf(logstring, MAXLINE, "[%s] %s %s %d\n", time_str, host, uri, size);

    return;
}

/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum, char *msgA, char *msgB) {
    char buf[MAXLINE], body[MAXBUF];

    /* Build the HTTP response body */
    sprintf(body, "<html><title>Error</title>");
    sprintf(body, "%s<body bgcolor=""ffffff"">\r\n", body);
    sprintf(body, "%s%s: %s\r\n", body, errnum, msgA);
    sprintf(body, "%s<p>%s: %s\r\n", body, msgB, cause);

    /* Print the HTTP response */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, msgA);
    if(rio_writen(fd, buf, strlen(buf)) != strlen(buf)) {
        printf("Error in sending the client error page!\n");
    }
    sprintf(buf, "Content-type: text/html\r\n");
    if(rio_writen(fd, buf, strlen(buf)) != strlen(buf)) {
        printf("Error in sending the client error page!\n");
    }
    sprintf(buf, "Content-length: %d\r\n\r\n", (int)strlen(body));
    if(rio_writen(fd, buf, strlen(buf)) != strlen(buf)) {
        printf("Error in sending the client error page!\n");
    }
    if(rio_writen(fd, body, strlen(body)) != strlen(body)) {
        printf("Error in sending the client error page!\n");
    }
}