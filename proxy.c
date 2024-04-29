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
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, 
                        char *uri, int size);
void *thread(void *vargp);
void read_requesthdrs(rio_t *rp) ;
void readBlocklist();
char **blockList;

/* 
 * main - Main routine for the proxy program 
 */
int main(int argc, char **argv){
    readBlocklist();

    int listenfd, *connfdp;
    char hostname[MAXLINE], port[MAXLINE];
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;
    pthread_t tid;

    /* Check arguments */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
        exit(0);
    }

    listenfd = Open_listenfd(argv[1]);
    while (1) {
        clientlen = sizeof(clientaddr);
        connfdp = Malloc(sizeof(int));
        *connfdp = Accept(listenfd, (SA *)&clientaddr, &clientlen); 
        Pthread_create(&tid, NULL, thread, connfdp);
    }

    if(blockList != NULL) {
        // Freeing the blocklist
        int i = 0;
        while(blockList[i] != NULL) {
            // printf("%s\n", blockList[i]);
            free(blockList[i]);
            i++;
        }
        free(blockList);
    }

    return 0;
}

void readBlocklist() {
    char *path = "blocklist";
    FILE *fp = fopen(path, "r");
    if(fp == NULL) {
        printf("WARNING:\nThe blocklist file either doesn't exist or cannot be opened.\n");
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
        // Note that this can fail if there isn't enough free memory available
        // This is also a comparatively expensive operation
        // so you wouldn't typically do a resize for every single line
        // Normally you would allocate extra space, wait for it to run out, then reallocate
        // Either growing by a fixed size, or even doubling the size, each time it gets full

        // Check if the allocation was successful
        if (ptr == NULL) {
          fprintf(stderr, "Failed to allocate memory at %s:%d\n", __FILE__, __LINE__);
        //   assert(false);
        }
        // Overwrite `lines` with the pointer to the new memory region only if realloc() was successful
        blockList = ptr;

        // Allocate a copy on the heap
        // so that the array elements don't all point to the same buffer
        // we must remember to free() this later
        blockList[num_lines - 1] = strdup(new_line);

        // Keep track of the size of the array
        num_lines++;
    }

    // Free the buffer that was allocated by getline()
    free(new_line);
    // Close the file since we're done with it
    fclose(fp);
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
    Free(vargp);
    // echo(connfd);

    struct stat sbuf;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char filename[MAXLINE], pathname[MAXLINE], srcf[MAXLINE];
    int *port = Malloc(sizeof(int)); 

    rio_t rio, rioB;
    int requestfd;
    char request[MAXLINE];

    /*
        Important Note from Dr. Carl:

        The Rio readn, Rio readlineb, and Rio writen error checking wrappers in
        csapp.c are not appropriate for a realistic proxy because they
        terminate the process when they encounter an error. Your proxy should
        be more forgiving. Use the regular RIO routines (lower case first
        letter) for reading and writing. IF you encounter an error reading or
        writing to a socket, simply close it.
    */

    /* Read request line and headers */
    Rio_readinitb(&rio, connfd);
    if (!Rio_readlineb(&rio, buf, MAXLINE))  //line:netp:doit:readrequest
        return NULL;
    printf("%s", buf);
    sscanf(buf, "%s %s %s", method, uri, version);       //line:netp:doit:parserequest
    if (strcasecmp(method, "GET")) {                     //line:netp:doit:beginrequesterr
        printf("error: in request\n");
        return NULL;
    }                                                    //line:netp:doit:endrequesterr
    parse_uri(uri, filename, pathname, port); 
    printf("%s\n", filename);
    
    // Filtering out hosts in the blocked list
    if(blockList != NULL) {
        // printf("Blocklist is not NULL!\n");
        int i = 0;
        while(blockList[i] != NULL) {
            // printf("Blocked Host: %s\n", blockList[i]);
            // printf("Strcmp = %d\n", strcmp(filename, blockList[i]));
            if(strcmp(filename, blockList[i]) == 0) {
                printf("%s is a blocked host! Connection aborted!\n", filename);
                Close(connfd);
                return NULL;
            }
            i++;
        }
    }

    read_requesthdrs(&rio);

    //proxy make request
    char test[100];
    snprintf(test,sizeof(test),"%d",*port);
    requestfd = Open_clientfd(filename, test);

    //change to use http 1.0
    snprintf(request, sizeof(request),"%s /%s %s \r\n\r\n",method, pathname, "HTTP/1.0" );
    Rio_writen(requestfd, request, strlen(request));
  

    //recieve info
   
    strcpy(buf,"");
    for (size_t i = 0; Rio_readn(requestfd, srcf, MAXLINE) > 0; i++){
        strcat(buf,srcf);
    }
    
    printf("%s",buf);
    Rio_writen(connfd, buf, strlen(buf));

    Close(requestfd);

    //sends data recieved from server to client
    //Rio_writen(connfd, srcf, strlen(srcf)); 
    Close(connfd);
    return NULL;
}


void read_requesthdrs(rio_t *rp) {
    char buf[MAXLINE];

    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    while(strcmp(buf, "\r\n")) {          //line:netp:readhdrs:checkterm
        Rio_readlineb(rp, buf, MAXLINE);
        printf("%s", buf);
    }
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
    len = hostend - hostbegin;
    strncpy(hostname, hostbegin, len);
    hostname[len] = '\0';

    
    /* Extract the port number */
    *port = 80; /* default */
    if (*hostend == ':')   
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
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, 
		      char *uri, int size){
    time_t now;
    char time_str[MAXLINE];
    char url[MAXLINE];
    unsigned long host;
    char pathname[MAXLINE];
    int *port = Malloc(sizeof(int)); 

    /* Get a formatted time string */
    now = time(NULL);
    strftime(time_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

    /* 
     * Next, convert the IP address in network byte order to dotted decimal
     * form. Note that we could have used inet_ntoa, but chose not to
     * because inet_ntoa is a Class 3 thread unsafe function that
     * returns a pointer to a static variable (Ch 13, CS:APP).
     */

    // for the student to do...
    
    
    /* Finally, store (and return) the formatted log entry string in logstring */

    // for the student to do...

    //gets URL from uri
    parse_uri(uri,url,pathname,port);

    //creates final string
    snprintf(logstring, MAXLINE, "%s %ld %s %d", time_str, host, url, size);


    return;
}

