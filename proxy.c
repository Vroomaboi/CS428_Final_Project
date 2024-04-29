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

/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400

/* You won't lose style points for including this long line in your code */
static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";

/*
 * Function prototypes
 */
int parse_uri(char *uri, char *target_addr, char *path, int  *port);
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);
void *thread(void *vargp);

/* 
 * main - Main routine for the proxy program 
 */
int main(int argc, char **argv){
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




    return 0;
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

    int is_static;
    struct stat sbuf;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char filename[MAXLINE], cgiargs[MAXLINE];
    rio_t rio;

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
        printf("error: in request");
        return NULL;
    }                                                    //line:netp:doit:endrequesterr
    read_requesthdrs(&rio);

    Close(connfd);
    return NULL;
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
    unsigned char a, b, c, d;

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
    parse_uri(uri,url,NULL,NULL);

    //creates final string
    snprintf(logstring, MAXLINE, "%s %ld %s %d", time_str, host, url, size);


    return NULL;
}

