/* Unit tests replace every socket-related syscall. No sockets are opened. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
static int fake_socket(int,int,int);
static int fake_connect(int,const struct sockaddr *,socklen_t);
static int fake_getpeername(int,struct sockaddr *,socklen_t *);
static int fake_getsockopt(int,int,int,void *,socklen_t *);
static int fake_poll(struct pollfd *,nfds_t,int);
static ssize_t fake_send(int,const void *,size_t,int);
static ssize_t fake_recv(int,void *,size_t,int);
static int fake_close(int);
#define socket fake_socket
#define connect fake_connect
#define getpeername fake_getpeername
#define getsockopt fake_getsockopt
#define poll fake_poll
#define send fake_send
#define recv fake_recv
#define close fake_close
#define CONNECT_PEER_TEST
#include "connect-peer.c"
static const char *reply;
static size_t offset;
static int closed, timed_out, interrupted, wrong_peer, recv_interrupted, send_interrupted;
static int fail_socket, fail_connect, fail_peer, fail_option, fail_send, fail_recv, fail_poll, wrong_port, send_again, recv_again;
static char transmitted[640]; static size_t written;
static int fake_socket(int a,int b,int c) {(void)a;(void)b;(void)c;return fail_socket?-1:42;}
static int fake_connect(int fd,const struct sockaddr *a,socklen_t n) {(void)a;(void)n;assert(fd==42);errno=fail_connect?ECONNREFUSED:EINPROGRESS;return -1;}
static int fake_getsockopt(int fd,int a,int b,void *v,socklen_t *n) {(void)a;(void)b;assert(fd==42);assert(*n==sizeof(int));*(int *)v=fail_option?ECONNREFUSED:0;return 0;}
static int fake_getpeername(int fd,struct sockaddr *p,socklen_t *n) {assert(fd==42);if(fail_peer)return -1;struct sockaddr_in *v=(struct sockaddr_in *)p;v->sin_family=AF_INET;v->sin_port=htons(wrong_port?3129:3128);inet_pton(AF_INET,wrong_peer?"10.0.0.1":"172.30.25.3",&v->sin_addr);*n=sizeof(*v);return 0;}
static int fake_poll(struct pollfd *p,nfds_t n,int t) {assert(n==1&&p->fd==42&&t>0&&t<=5000);if(interrupted){interrupted=0;errno=EINTR;return -1;}if(fail_poll){errno=EBADF;return -1;}if(timed_out)return 0;p->revents=p->events;return 1;}
static ssize_t fake_send(int fd,const void *b,size_t n,int f) {(void)f;assert(fd==42);if(send_interrupted||send_again){errno=send_interrupted?EINTR:EAGAIN;send_interrupted=send_again=0;return -1;}if(fail_send){errno=EPIPE;return -1;}size_t count=n>3?3:n;assert(written+count<sizeof(transmitted));memcpy(transmitted+written,b,count);written+=count;transmitted[written]=0;return (ssize_t)count;}
static ssize_t fake_recv(int fd,void *b,size_t n,int f) {(void)f;assert(fd==42);if(recv_interrupted||recv_again){errno=recv_interrupted?EINTR:EAGAIN;recv_interrupted=recv_again=0;return -1;}if(fail_recv){errno=ECONNRESET;return -1;}size_t count=strlen(reply)-offset;if(count>7)count=7;if(count>n)count=n;memcpy(b,reply+offset,count);offset+=count;return (ssize_t)count;}
static int fake_close(int fd) {assert(fd==42);closed++;return 0;}
static struct evidence check(const char *text) {reply=text;offset=0;closed=0;written=0;return transaction("172.30.25.3",3128,"fixture.test:8080");}
int main(void) {
    const char *valid="HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n";
    interrupted=send_interrupted=recv_interrupted=1;struct evidence e=check(valid);assert(e.complete&&closed==1&&e.peer_port==3128&&!strcmp(e.peer,"172.30.25.3"));assert(strstr(transmitted,"CONNECT fixture.test:8080 HTTP/1.1\r\nHost: fixture.test:8080\r\n"));
    e=check("HTTP/1.1 200 Connection established\r\n\r\n");assert(!e.complete&&e.headers_valid&&e.status==200&&closed==1&&!strcmp(e.error,"UNEXPECTED_TUNNEL"));
    e=check("HTTP/1.1 200 Established\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n");assert(!e.complete&&closed==1&&!strcmp(e.error,"INVALID_REJECTION"));
    e=check("HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\n");assert(!e.complete&&closed==1&&!strcmp(e.error,"INCOMPLETE_RESPONSE"));
    e=check("HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_DNS_FAIL 0\r\n\r\n");assert(!e.complete&&closed==1);
    timed_out=1;e=check(valid);assert(!e.complete&&closed==1&&!strcmp(e.error,"TIMEOUT"));timed_out=0;
    wrong_peer=1;e=check(valid);assert(!e.complete&&closed==1&&written==0&&!strcmp(e.error,"PEER_MISMATCH"));wrong_peer=0;
    e=check("HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n");assert(!e.complete&&closed==1);
    e=check("HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\nX-Fake: value\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n");assert(!e.complete&&closed==1);
    char huge[RESPONSE_LIMIT+1];memset(huge,'A',RESPONSE_LIMIT);huge[RESPONSE_LIMIT]=0;e=check(huge);assert(!e.complete&&closed==1&&!strcmp(e.error,"RESPONSE_TOO_LARGE"));
    assert(!authority_valid("fixture.test:8080\r\nInjected: x"));assert(!authority_valid("-bad.test:1"));assert(!authority_valid("a..b:1"));assert(!authority_valid("a:0"));
    unsigned port;assert(!port_number("65536",&port));assert(!port_number("+3128",&port));
    send_again=recv_again=1;e=check(valid);assert(e.complete&&closed==1);
    int *faults[]={&fail_socket,&fail_connect,&fail_option,&fail_peer,&fail_poll,&fail_send,&fail_recv,&wrong_port};
    const char *codes[]={"SOCKET_FAILED","CONNECT_FAILED","CONNECT_FAILED","PEER_FAILED","POLL_FAILED","SEND_FAILED","RECV_FAILED","PEER_MISMATCH"};
    for(size_t i=0;i<sizeof(faults)/sizeof(faults[0]);i++){*faults[i]=1;e=check(valid);assert(!e.complete&&!strcmp(e.error,codes[i])&&closed==(i==0?0:1));*faults[i]=0;}
    e=check("HTTP/1.1 200 Established\r\nBad header\r\n\r\n");assert(!e.complete&&!e.headers_valid&&!strcmp(e.error,"INVALID_REJECTION"));
    char line[2048];memset(line,'a',sizeof(line));memcpy(line,"HTTP/1.1 403 ",13);memcpy(line+sizeof(line)-5,"\r\n\r\n",5);e=check(line);assert(!e.complete&&closed==1);
    e=check("HTTP/1.1 403 Forbidden\r\nServer: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\nLocation: http://other.test/\r\n\r\n");assert(!e.complete&&closed==1);
    char many[8192]="HTTP/1.1 403 Forbidden\r\n";
    for(unsigned i=0;i<65;i++){char header[32];snprintf(header,sizeof(header),"X-Test-%u: value\r\n",i);strcat(many,header);}
    strcat(many,"Server: squid/6.14\r\nX-Squid-Error: ERR_ACCESS_DENIED 0\r\n\r\n");e=check(many);assert(!e.complete&&closed==1);
    /* Deterministic parser fuzz smoke test: arbitrary bounded ASCII, no I/O. */
    unsigned random=17;
    for(unsigned iteration=0;iteration<10000;iteration++){
        char input[512];size_t length=iteration%sizeof(input);
        for(size_t i=0;i<length;i++){random=random*1664525u+1013904223u;input[i]=(char)(1+random%126u);}
        input[length]=0;struct evidence parsed={0};(void)parse_headers(input,&parsed);
    }
    puts("Native syscall-mocked cases passed; no sockets opened.");
    return 0;
}
