#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <curl/curl.h>
#include <sys/time.h>

#define PACKET_SIZE 64
#define MAX_HOPS 30
#define MAX_URL_LENGTH 256
#define MAX_RESPONSE_SIZE 4096

// ANSI color codes
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

struct string
{
    char *ptr;
    size_t len;
};

void init_string(struct string *s)
{
    s->len = 0;
    s->ptr = malloc(s->len + 1);
    if (s->ptr == NULL)
    {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, new_len + 1);
    if (s->ptr == NULL)
    {
        fprintf(stderr, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size * nmemb;
}

unsigned short calculate_checksum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

char *extract_value(const char *json, const char *key)
{
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\":\"", key);
    char *start = strstr(json, search_key);
    if (start)
    {
        start += strlen(search_key);
        char *end = strchr(start, '"');
        if (end)
        {
            int length = end - start;
            char *value = malloc(length + 1);
            strncpy(value, start, length);
            value[length] = '\0';
            return value;
        }
    }
    return NULL;
}

void get_ip_info(const char *ip_address)
{
    CURL *curl;
    CURLcode res;
    struct string s;
    char url[100];

    init_string(&s);

    curl = curl_easy_init();
    if (curl)
    {
        snprintf(url, sizeof(url), "http://ip-api.com/json/%s", ip_address);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
        res = curl_easy_perform(curl);

        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else
        {
            char *country = extract_value(s.ptr, "country");
            char *region = extract_value(s.ptr, "regionName");
            char *city = extract_value(s.ptr, "city");
            char *isp = extract_value(s.ptr, "isp");
            char *as = extract_value(s.ptr, "as");

            if (country && region && city && isp && as)
            {
                printf(ANSI_COLOR_CYAN "   Location: %s, %s, %s\n" ANSI_COLOR_RESET, city, region, country);
                printf(ANSI_COLOR_YELLOW "   ISP: %s\n" ANSI_COLOR_RESET, isp);
                printf(ANSI_COLOR_MAGENTA "   AS: %s\n" ANSI_COLOR_RESET, as);
            }
            else
            {
                printf("   Unable to parse location information\n");
            }

            free(country);
            free(region);
            free(city);
            free(isp);
            free(as);
        }

        curl_easy_cleanup(curl);
    }

    free(s.ptr);
}

void print_route_visualization(int hop)
{
    printf(ANSI_COLOR_GREEN "   [");
    for (int i = 0; i < hop; i++)
    {
        printf("=");
    }
    printf(">");
    for (int i = hop; i < MAX_HOPS; i++)
    {
        printf(" ");
    }
    printf("]\n" ANSI_COLOR_RESET);
}

char *reverse_dns_lookup(const char *ip_address)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof(sa);
    char host[NI_MAXHOST];

    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_address, &sa.sin_addr);

    if (!getnameinfo((struct sockaddr *)&sa, len, host, sizeof(host), NULL, 0, NI_NAMEREQD))
    {
        return strdup(host);
    }

    return NULL;
}

int main()
{
    char host[MAX_URL_LENGTH];
    printf("Enter the website address to trace: ");
    if (fgets(host, MAX_URL_LENGTH, stdin) == NULL)
    {
        fprintf(stderr, "Error reading input\n");
        exit(1);
    }

    host[strcspn(host, "\n")] = 0;

    struct hostent *he = gethostbyname(host);
    if (he == NULL)
    {
        herror("gethostbyname");
        exit(1);
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    char packet[PACKET_SIZE];
    struct icmp *icmp = (struct icmp *)packet;
    struct sockaddr_in addr;
    int ttl = 1;
    int reached = 0;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);

    printf(ANSI_COLOR_BLUE "Tracing route to %s (%s)\n" ANSI_COLOR_RESET, host, inet_ntoa(addr.sin_addr));

    while (!reached && ttl <= MAX_HOPS)
    {
        memset(packet, 0, PACKET_SIZE);
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_id = getpid();
        icmp->icmp_seq = ttl;
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum = calculate_checksum((unsigned short *)icmp, PACKET_SIZE / 2);

        setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

        struct timeval start, end;
        gettimeofday(&start, NULL);

        int sent = sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (sent < 0)
        {
            perror("sendto");
            exit(1);
        }

        struct sockaddr_in recv_addr;
        socklen_t addr_len = sizeof(recv_addr);
        char recv_packet[PACKET_SIZE];
        int received = recvfrom(sockfd, recv_packet, PACKET_SIZE, 0, (struct sockaddr *)&recv_addr, &addr_len);

        gettimeofday(&end, NULL);

        if (received < 0)
        {
            perror("recvfrom");
            exit(1);
        }

        double elapsed = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;

        printf(ANSI_COLOR_GREEN "%2d" ANSI_COLOR_RESET "  %s", ttl, inet_ntoa(recv_addr.sin_addr));
        printf(ANSI_COLOR_YELLOW " (%.2f ms)\n" ANSI_COLOR_RESET, elapsed);

        char *hostname = reverse_dns_lookup(inet_ntoa(recv_addr.sin_addr));
        if (hostname)
        {
            printf(ANSI_COLOR_BLUE "   Hostname: %s\n" ANSI_COLOR_RESET, hostname);
            free(hostname);
        }

        get_ip_info(inet_ntoa(recv_addr.sin_addr));
        print_route_visualization(ttl);

        if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr)
        {
            reached = 1;
        }

        ttl++;
        printf("\n");
    }

    close(sockfd);
    return 0;
}