/* Linux-only, one socket, no DNS, no target traffic after CONNECT. */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RESPONSE_LIMIT 16384
#define HEADER_LIMIT 64
#define LINE_LIMIT 1024
#define TIME_LIMIT_MS 5000
struct evidence {
    char peer[INET_ADDRSTRLEN]; unsigned peer_port;
    int status; bool connected, squid, denied, headers_valid, complete;
    const char *error;
};
static long long now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static bool port_number(const char *s, unsigned *out) {
    unsigned value = 0;
    if (!s || !*s || strlen(s) > 5 || (s[0] == '0' && s[1])) return false;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return false;
        value = value * 10 + (unsigned)(*s - '0');
        if (value > 65535) return false;
    }
    if (!value) return false;
    *out = value; return true;
}
static bool authority_valid(const char *s) {
    const char *colon = strrchr(s, ':'); unsigned port;
    size_t label = 0, hostlen;
    if (!colon || colon == s || !port_number(colon + 1, &port)) return false;
    hostlen = (size_t)(colon - s);
    if (hostlen > 253) return false;
    for (size_t i = 0; i < hostlen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '.') {
            if (!label || s[i-1] == '-') return false;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-') || (!label && c == '-') || ++label > 63) return false;
        }
    }
    return label && s[hostlen-1] != '-';
}
static int wait_socket(int fd, short events, long long deadline) {
    for (;;) {
        long long current = now_ms();
        if (current < 0 || current >= deadline) return 0;
        struct pollfd p = { fd, events, 0 };
        int result = poll(&p, 1, (int)(deadline-current));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return result;
        current = now_ms();
        if (current < 0 || current >= deadline) return 0;
        if (p.revents & POLLNVAL) return -1;
        if (p.revents & (events | POLLERR | POLLHUP)) return 1;
        return -1;
    }
}
static bool token_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || strchr("!#$%&'*+-.^_`|~", c) != NULL;
}
static bool parse_headers(char *buffer, struct evidence *e) {
    char *end = strstr(buffer, "\r\n\r\n"), *line_end = strstr(buffer, "\r\n");
    unsigned count = 0, servers = 0, errors = 0;
    char names[HEADER_LIMIT][128];
    if (!end || !line_end || (size_t)(line_end-buffer) > LINE_LIMIT) return false;
    for (char *p = buffer; p < end+4; p++) {
        if ((*p == '\r' && (p+1 >= end+4 || p[1] != '\n')) ||
            (*p == '\n' && (p == buffer || p[-1] != '\r'))) return false;
    }
    *line_end = '\0';
    size_t len = strlen(buffer);
    if (len < 12 || (strncmp(buffer,"HTTP/1.1 ",9) && strncmp(buffer,"HTTP/1.0 ",9)) ||
        buffer[9] < '1' || buffer[9] > '5' || !isdigit((unsigned char)buffer[10]) ||
        !isdigit((unsigned char)buffer[11]) || (len > 12 && buffer[12] != ' ')) return false;
    e->status = (buffer[9]-'0')*100 + (buffer[10]-'0')*10 + buffer[11]-'0';
    char *line = line_end + 2;
    while (line < end) {
        line_end = strstr(line, "\r\n");
        if (!line_end || line_end > end || (size_t)(line_end-line) > LINE_LIMIT || ++count > HEADER_LIMIT) return false;
        *line_end = '\0'; char *colon = strchr(line, ':');
        if (!colon || colon == line) return false;
        for (char *p = line; p < colon; p++) { if (!token_char((unsigned char)*p)) return false; *p = (char)tolower((unsigned char)*p); }
        size_t name_len = (size_t)(colon-line);
        if (name_len >= sizeof(names[0])) return false;
        for (unsigned i = 0; i+1 < count; i++) if (strlen(names[i]) == name_len && !memcmp(names[i],line,name_len)) return false;
        memcpy(names[count-1],line,name_len); names[count-1][name_len] = '\0';
        *colon = '\0'; char *value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;
        char *tail = value + strlen(value);
        while (tail > value && (tail[-1] == ' ' || tail[-1] == '\t')) *--tail = '\0';
        if (!strcmp(line,"server")) {
            if (++servers != 1 || strncmp(value,"squid/",6) || !isdigit((unsigned char)value[6])) return false;
            for (char *p = value+6; *p; p++) if (!isdigit((unsigned char)*p) && (*p != '.' || !isdigit((unsigned char)p[1]))) return false;
            e->squid = true;
        } else if (!strcmp(line,"x-squid-error")) {
            if (++errors != 1 || strcmp(value,"ERR_ACCESS_DENIED 0")) return false;
            e->denied = true;
        } else if (!strcmp(line,"location")) return false;
        line = line_end + 2;
    }
    e->headers_valid = line == end+2;
    return e->headers_valid && e->status == 403 && e->squid && e->denied;
}
static struct evidence transaction(const char *proxy, unsigned port, const char *authority) {
    struct evidence e = { .error = "SOCKET_FAILED" }; int fd = -1;
    long long start = now_ms(), deadline;
    char request[640], response[RESPONSE_LIMIT+1]; size_t sent = 0, used = 0;
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons((unsigned short)port) }, peer;
    if (start < 0) { e.error = "CLOCK_FAILED"; return e; }
    deadline = start + TIME_LIMIT_MS;
    if (inet_pton(AF_INET, proxy, &address.sin_addr) != 1 || !port || port > 65535 || !authority_valid(authority)) { e.error = "INVALID_ARGUMENTS"; return e; }
    int request_len = snprintf(request,sizeof(request),"CONNECT %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",authority,authority);
    if (request_len < 0 || (size_t)request_len >= sizeof(request)) { e.error = "INVALID_ARGUMENTS"; return e; }
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return e;
    if (connect(fd,(struct sockaddr *)&address,sizeof(address)) < 0) {
        if (errno != EINPROGRESS && errno != EINTR) { e.error = "CONNECT_FAILED"; goto done; }
        int ready = wait_socket(fd,POLLOUT,deadline), error = 0; socklen_t size = sizeof(error);
        if (ready <= 0) { e.error = ready == 0 ? "TIMEOUT" : "POLL_FAILED"; goto done; }
        if (getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size) || size != sizeof(error) || error) { e.error = "CONNECT_FAILED"; goto done; }
    }
    socklen_t peer_size = sizeof(peer); memset(&peer,0,sizeof(peer));
    if (getpeername(fd,(struct sockaddr *)&peer,&peer_size) || peer_size != sizeof(peer) || peer.sin_family != AF_INET || !inet_ntop(AF_INET,&peer.sin_addr,e.peer,sizeof(e.peer))) { e.error = "PEER_FAILED"; goto done; }
    e.peer_port = ntohs(peer.sin_port); e.connected = true;
    if (peer.sin_addr.s_addr != address.sin_addr.s_addr || peer.sin_port != address.sin_port) { e.error = "PEER_MISMATCH"; goto done; }
    while (sent < (size_t)request_len) {
        int ready = wait_socket(fd,POLLOUT,deadline);
        if (ready <= 0) { e.error = ready == 0 ? "TIMEOUT" : "POLL_FAILED"; goto done; }
        ssize_t count = send(fd,request+sent,(size_t)request_len-sent,MSG_NOSIGNAL);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count <= 0) { e.error = "SEND_FAILED"; goto done; }
        sent += (size_t)count;
    }
    response[0] = '\0';
    for (;;) {
        if (used == RESPONSE_LIMIT) { e.error = "RESPONSE_TOO_LARGE"; goto done; }
        int ready = wait_socket(fd,POLLIN,deadline);
        if (ready <= 0) { e.error = ready == 0 ? "TIMEOUT" : "POLL_FAILED"; goto done; }
        ssize_t count = recv(fd,response+used,RESPONSE_LIMIT-used,0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (count < 0) { e.error = "RECV_FAILED"; goto done; }
        if (!count) { e.error = "INCOMPLETE_RESPONSE"; goto done; }
        /* Validate header bytes only. Ignore a body received with its terminator. */
        size_t previous = used; used += (size_t)count; response[used] = '\0';
        for (size_t i = previous; i < used; i++) {
            unsigned char ch = (unsigned char)response[i];
            if (!ch || (ch < 32 && ch != '\r' && ch != '\n' && ch != '\t') || ch > 126) { e.error = "MALFORMED_RESPONSE"; goto done; }
            if (i >= 3 && !memcmp(response+i-3,"\r\n\r\n",4)) {
                response[i+1] = '\0';
                if (!parse_headers(response,&e)) { e.error = e.headers_valid && e.status == 200 && !e.denied ? "UNEXPECTED_TUNNEL" : "INVALID_REJECTION"; goto done; }
                e.complete = true; e.error = NULL; goto done;
            }
        }
    }
done:
    if (fd >= 0) close(fd);
    return e;
}
#ifndef CONNECT_PEER_TEST
int main(int argc, char **argv) {
    unsigned port = 0;
    if (argc != 4 || strlen(argv[1]) >= INET_ADDRSTRLEN || !port_number(argv[2],&port) || !authority_valid(argv[3])) {
        puts("{\"schemaVersion\":1,\"complete\":false,\"error\":\"INVALID_ARGUMENTS\"}"); return 2;
    }
    struct evidence e = transaction(argv[1],port,argv[3]);
    printf("{\"schemaVersion\":1,\"peerIp\":\"%s\",\"peerPort\":%u,\"requestedAuthority\":\"%s\",\"responseStatus\":%d,\"connected\":%s,\"squidServer\":%s,\"accessDenied\":%s,\"headersValid\":%s,\"complete\":%s,\"error\":",e.peer,e.peer_port,argv[3],e.status,e.connected?"true":"false",e.squid?"true":"false",e.denied?"true":"false",e.headers_valid?"true":"false",e.complete?"true":"false");
    if (e.error) printf("\"%s\"",e.error); else printf("null");
    puts("}"); return e.complete ? 0 : 1;
}
#endif
