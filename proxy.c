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
void read_blocklist();
void add_msg_to_log(char *logMsg);
void filter_request_headers(char *src, char *dest);

// String array to hold blockList
char **blockList;

// Semaphore to protect the log file writing
sem_t mutex;

/* 
 * main - Main routine for the proxy program that opens a listening port and
 *        creates threads for each new client connection
 */
int main(int argc, char **argv){
    /* Check arguments */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
        exit(0);
    }

    // Set up the semaphore to protect the log file
    if(sem_init(&mutex, 0, 1) < 0) {
        printf("Warning:\nFailed to set up semaphore!\n");
        printf("Log file will not be protected!\n");
    }

    // Loads blocklist file into the blocklist string array
    read_blocklist();

    // Ignore SIGPIPE to prevent crashing
    if(signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        printf("SIGPIPE Handler Error!\n");
    }

    // Setting up the server and client connections
    int listenfd, *connfdp;
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;
    pthread_t tid;

    // Listens for connection on port, if connection is accepted,
    // creates a thread to handle that connection
    listenfd = Open_listenfd(argv[1]);
    while (1) {
        clientlen = sizeof(clientaddr);
        connfdp = Malloc(sizeof(int));
        *connfdp = Accept(listenfd, (SA *)&clientaddr, &clientlen); 
        Pthread_create(&tid, NULL, thread, connfdp);
    }

    // Frees the memory of blocklist
    if(blockList != NULL) {
        // Freeing the blocklist's elements
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
 * read_blocklist - Reads the "blocklist" file if it exists and loads it into
 *                  the blocklist string array
 */
void read_blocklist() {
    // Attempting to open the blocklist file for reading
    char *path = "blocklist";
    FILE *fp = fopen(path, "r");
    if(fp == NULL) {
        printf("WARNING:\nThe blocklist file either doesn't exist or cannot be opened.\n");
        return;
    }

    // Allocating memory for the first line
    int num_lines = 1;
    blockList = malloc(sizeof(blockList[0]) * num_lines);

    char *new_line = NULL;
    size_t str_len = 0;
    ssize_t bytes_read;
    while ((bytes_read = getline(&new_line, &str_len, fp)) != -1) {
        new_line[strcspn(new_line, "\n")] = 0;

        // Resize the array we allocated to allow for the next line
        void *ptr = realloc(blockList, (num_lines + 1) * sizeof(blockList[0]));

        // Check if the allocation was successful
        if (ptr == NULL) {
          printf("WARNING:\nError loading blocklist!\n");
          printf("Blocklist will NOT be enforced!\n");
          return;
        }

        // Overwrite blocklist with the pointer to the new memory region
        blockList = ptr;

        // Allocate a copy on the heap so that the array elements don't all
        // point to the same buffer
        blockList[num_lines - 1] = strdup(new_line);

        // Keep track of the size of the array
        num_lines++;
    }

    // Resource cleanup
    free(new_line);
    fclose(fp);

    return;
}

/*
 * thread - Handles a client connection after it is established
 * 
 */
void *thread(void *vargp) {
    // Setting up the connection and freeing the memory of the pointer created
    // in the main function that was used to prevent race conditions
    int connfd = *((int *)vargp);
    Pthread_detach(pthread_self());
    free(vargp);

    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE],
         filename[MAXLINE], pathname[MAXLINE], request[MAXLINE];
    int requestfd, *port = Malloc(sizeof(int)); 
    rio_t rio;

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
        if(strcmp(method, "") != 0) {
            clienterror(
            connfd,
            filename,
            "405",
            "Method Not Allowed",
            "This HTTP method is not allowed using this proxy."
        );
        } else {
            printf("Client connection has been prematurely closed!\n");
        }
        return NULL;
    }

    // Separating the URI into the filename (aka host), pathname, and port
    parse_uri(uri, filename, pathname, port); 
    
    // Filtering out hosts in the blocked list
    if(blockList != NULL) {
        int i = 0;
        while(blockList[i] != NULL) {
            if(strcmp(filename, blockList[i]) == 0) {
                char log[MAXLINE];
                format_log_entry(log, connfd, uri, 0);
                log[strlen(log) - 1] = ' ';
                strcat(log, "- BLOCKED REQUEST: POTENTIALLY MALICIOUS SITE\n");
                add_msg_to_log(log);
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

    // Proxy make request
    // Storing the port as a string
    char portStr[MAXLINE];
    snprintf(portStr, sizeof(portStr), "%d", *port);
    if((requestfd = open_clientfd(filename, portStr)) < 0) {
        printf("Error opening connection to %s\n", uri);
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
    snprintf(request, sizeof(request), "%s /%s %s\r\n", method, pathname,
             "HTTP/1.0");
    char hostHead[MAXLINE];
    snprintf(hostHead, sizeof(hostHead)+200, "Host: %s\r\n", filename);
    strcat(request,hostHead);
    strcat(request, user_agent_hdr);
    strcat(request,"Connection: close\r\n");
    strcat(request,"Proxy-Connection: close\r\n");
    filter_request_headers(remainingHeaders, request);
    strcat(request,"\r\n");

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
            if(errno == EPIPE) {
                printf("Error sending response to client!\n");
                close(requestfd);
                close(connfd);
                return;   
            }
        }
        bzero(buf, MAXLINE);
    }

    // Checkign for ECONNRESET error and
    if(n == -1) {
        if(errno == ECONNRESET) {
            printf("Connection closed by the host prematurely!\n");
            close(requestfd);
            close(connfd);
            return;
        }
    }
    int rSize = rLen * 8;

    // Logging the response
    char logString[MAXLINE];
    format_log_entry(logString, connfd, uri, rSize);
    add_msg_to_log(logString);

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
    strcat(dest, buf);

    // Getting the rest of the header lines
    while(strcmp(buf, "\r\n")) {
        rio_readlineb(rp, buf, MAXLINE);
        strcat(dest, buf);
    }

    return;
}

void filter_request_headers(char *src, char *dest) {
    char *token = strtok(src, "\r\n");
    while(token != NULL) {
        if(!strstr(token, "Host: ") && !strstr(token, "User-Agent: ") &&
           !strstr(token, "Connection: ") && !strstr(token, "Proxy-Connection: ") &&
           !strstr(token, "Keep-Alive: ")) {
            strcat(token, "\r\n");
            strcat(dest, token);
        }
        token = strtok(NULL, "\r\n");
    }
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
    socklen_t addrlen;
    struct sockaddr_in addr;
    addrlen = sizeof(addr);
    int res = getpeername(fd, (struct sockaddr *)&addr, &addrlen);
    // inet_ntop is thread safe according to the internet!
    inet_ntop(AF_INET, &addr.sin_addr, host, INET_ADDRSTRLEN);
    
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

    /* Serve the HTTP response */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, msgA);
    sprintf(buf, "%sContent-type: text/html\r\n", buf);
    sprintf(buf, "%sContent-length: %d\r\n\r\n", buf, (int)strlen(body));
    if(rio_writen(fd, buf, strlen(buf)) != strlen(buf)) {
        printf("Failed to send HTTP error response headers to the client!\n");
        printf("Erorr Headers: %s", buf);
        close(fd);
        return;
    }
    if(rio_writen(fd, body, strlen(body)) != strlen(body)) {
        printf("Failed to send HTML error response body to the client!\n");
        printf("Erorr HTML Body: %s", body);
        close(fd);
        return;
    }

    close(fd);

    return;
}

void add_msg_to_log(char *logMsg) {
    // Protecting the log file with a semaphore
    if(sem_wait(&mutex) < 0) {
        printf("Warning:\nFailed to test log file accessibility!\n");
        printf("The following message will not be logged:\n%s", logMsg);
        return;
    }
    FILE *logptr;
    logptr = fopen("proxy.log", "a");
    fprintf(logptr, "%s", logMsg);
    fclose(logptr);
    if(sem_post(&mutex) < 0) {
        printf("Warning:\nAn error has occured in unlocking the log file!\n");
    }
    return NULL;
}