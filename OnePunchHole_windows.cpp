// OnePunchHole - RFC 5389 STUN + UDP hole punch via Google STUN. No TURN, no own server.
// MIT License - Copyright (c) 2026 Mohamed A. Yassin - see LICENSE. Provided AS IS, no warranty.
//   OnePunchHole.exe stun  [port] [hosts...]            print your reflex (public) endpoint
//   OnePunchHole.exe check [port] [hosts...]            NAT type probe (needs two STUN servers)
//   OnePunchHole.exe punch [ip:port] [port] [hosts...]  discover reflex, punch, chat
// A bare port binds a FIXED local UDP port (both sides agree in advance) and tries UPnP IGD /
// NAT-PMP mapping, which also defeats symmetric NAT. ONE socket for the whole run, so the printed
// reflex port IS the live punching port.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <thread>
#include <vector>
#pragma comment(lib, "ws2_32.lib")
using namespace std::chrono_literals;

static const char* STUNS[] = {"stun.l.google.com", "stun1.l.google.com", "stun2.l.google.com",
                              "stun3.l.google.com", "stun4.l.google.com"};
static const int MAX_ATTEMPTS = 200, PEER_TIMEOUT = 5;  // 200*250ms = 50s to punch; 5s silence = gone

static void timeout(SOCKET s, DWORD ms) { setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ms, sizeof ms); }

static SOCKET udp_sock(u_short port) {                 // fixed port => predictable NAT mapping
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (!port || s == INVALID_SOCKET) return s;
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons(port);
    if (!bind(s, (SOCKADDR*)&a, sizeof a)) return s;
    closesocket(s);
    fprintf(stderr, "port %u in use, using a random one\n", (unsigned)port);
    return socket(AF_INET, SOCK_DGRAM, 0);
}
static std::string ep(const sockaddr_in& a) {          // "ip:port"
    char t[64]; DWORD n = sizeof t;
    return WSAAddressToStringA((SOCKADDR*)&a, sizeof a, nullptr, t, &n) ? "?" : t;
}
static bool parse_ep(const char* s, sockaddr_in* a) {
    char ip[64]; strncpy(ip, s, sizeof ip - 1); ip[sizeof ip - 1] = 0;
    char* c = strchr(ip, ':'); if (!c) return false;
    *c = 0; a->sin_family = AF_INET; a->sin_port = htons((u_short)atoi(c + 1));
    return inet_pton(AF_INET, ip, &a->sin_addr) == 1;
}
static bool same_ep(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}
static void put(const std::string& m, SOCKET s, const sockaddr_in& to) {
    sendto(s, m.c_str(), (int)m.size(), 0, (const SOCKADDR*)&to, sizeof to);
}
static bool resolve(const char* host, int port, sockaddr_in* out) {
    char ps[8]; snprintf(ps, sizeof ps, "%d", port);
    addrinfo h{}, *r = nullptr; h.ai_family = AF_INET; h.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, ps, &h, &r) || !r) return false;
    *out = *(sockaddr_in*)r->ai_addr; freeaddrinfo(r);   // freed on every path
    return true;
}
// RFC 5389 binding request -> XOR-MAPPED-ADDRESS. Leaves via this socket, so it also
// creates/keeps the socket's own NAT mapping.
static bool stun_query(SOCKET s, const sockaddr_in& srv, sockaddr_in* mapped) {
    timeout(s, 3000);
    unsigned char req[20] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42};
    for (int i = 8; i < 20; i++) req[i] = (unsigned char)rand();
    if (sendto(s, (const char*)req, sizeof req, 0, (const SOCKADDR*)&srv, sizeof srv) < 0) return false;
    unsigned char buf[512]; sockaddr_in from{}; int fl = sizeof from;
    int n = recvfrom(s, (char*)buf, sizeof buf, 0, (SOCKADDR*)&from, &fl);
    if (n < 20 || memcmp(buf + 4, req + 4, 16)) return false;        // transaction id must match
    for (int i = 20; i + 12 <= n; i += 4 + ((buf[i + 2] << 8) | buf[i + 3])) {
        if (buf[i] == 0x00 && buf[i + 1] == 0x20 && buf[i + 5] == 0x01) {   // XOR-MAPPED-ADDRESS, IPv4
            u_short port = (u_short)(((buf[i + 6] << 8) | buf[i + 7]) ^ 0x2112);
            u_long addr = ((u_long)buf[i + 8] << 24 | (u_long)buf[i + 9] << 16 |
                           (u_long)buf[i + 10] << 8 | buf[i + 11]) ^ 0x2112A442UL;
            memset(mapped, 0, sizeof *mapped);
            mapped->sin_family = AF_INET;
            mapped->sin_port = htons(port);            // wire is big-endian
            mapped->sin_addr.s_addr = htonl(addr);
            return true;
        }
    }
    return false;
}
static bool is_num(const char* s) {                    // bare port number vs stun hostname
    if (!*s) return false;
    for (const char* p = s; *p; p++) if (!isdigit((unsigned char)*p)) return false;
    return true;
}
// ---- UPnP IGD / NAT-PMP: endpoint-independent mapping, the non-TURN fix for symmetric NAT ----
static std::string hdr(const std::string& r, const char* key) {
    std::string k = std::string("\r\n") + key;
    size_t p = r.find(k); if (p == std::string::npos) return "";
    p = r.find(':', p + k.size()); if (p == std::string::npos) return "";
    size_t e = r.find("\r\n", p + 1);
    std::string v = r.substr(p + 1, e == std::string::npos ? std::string::npos : e - p - 1);
    size_t a = v.find_first_not_of(" \t");
    return a == std::string::npos ? "" : v.substr(a);
}
static bool http_req(const std::string& ip, int port, const std::string& req, std::string& resp) {
    SOCKET t = socket(AF_INET, SOCK_STREAM, 0);
    if (t == INVALID_SOCKET) return false;
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons((u_short)port);
    inet_pton(AF_INET, ip.c_str(), &a.sin_addr);
    timeout(t, 2000);
    bool ok = !connect(t, (SOCKADDR*)&a, sizeof a) && send(t, req.c_str(), (int)req.size(), 0) > 0;
    for (char b[4096]; ok;) {
        int n = recv(t, b, sizeof b, 0);
        if (n <= 0) break;
        resp.append(b, n);
    }
    closesocket(t);
    return ok && !resp.empty();
}
static bool upnp_map(SOCKET s, u_short port) {
    SOCKET d = socket(AF_INET, SOCK_DGRAM, 0);         // 1. SSDP M-SEARCH for the gateway
    if (d == INVALID_SOCKET) return false;
    int ttl = 2; setsockopt(d, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&ttl, sizeof ttl);
    timeout(d, 2000);
    sockaddr_in dst{}; dst.sin_family = AF_INET; dst.sin_port = htons(1900);
    inet_pton(AF_INET, "239.255.255.255", &dst.sin_addr);
    const char* ms = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.255:1900\r\n"
        "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n";
    if (sendto(d, ms, (int)strlen(ms), 0, (SOCKADDR*)&dst, sizeof dst) < 0) { closesocket(d); return false; }
    char b[2048]; sockaddr_in from{}; int fl = sizeof from;
    int n = recvfrom(d, b, sizeof b - 1, 0, (SOCKADDR*)&from, &fl);
    closesocket(d);
    if (n <= 0) return false;
    b[n] = 0;
    std::string resp(b);
    if (resp.find("WANIPConnection") == std::string::npos && resp.find("WANPPPConnection") == std::string::npos)
        return false;
    std::string loc = hdr(resp, "LOCATION");
    if (loc.substr(0, 7) != "http://") return false;
    size_t slash = loc.find('/', 7); if (slash == std::string::npos) return false;
    std::string host = loc.substr(7, slash - 7), path = loc.substr(slash);
    size_t colon = host.find(':');
    std::string ip = host.substr(0, colon == std::string::npos ? host.size() : colon);
    int cport = colon == std::string::npos ? 80 : atoi(host.c_str() + colon + 1);
    std::string gresp;                                 // 2. GET the device description
    if (!http_req(ip, cport, "GET " + path + " HTTP/1.1\r\nHOST: " + host + "\r\n\r\n", gresp)) return false;
    size_t c = gresp.find("<controlURL>"), e = gresp.find("</controlURL>");
    size_t s2 = gresp.find("<serviceType>"), e2 = gresp.find("</serviceType>");
    if (c == std::string::npos || e == std::string::npos || s2 == std::string::npos || e2 == std::string::npos)
        return false;
    std::string ctrl = gresp.substr(c + 12, e - c - 12), svc = gresp.substr(s2 + 13, e2 - s2 - 13);
    char lip[64] = "0.0.0.0";                          // 3. SOAP AddPortMapping, permanent lease
    sockaddr_in self{}; int sl = sizeof self;
    if (!getsockname(s, (SOCKADDR*)&self, &sl)) inet_ntop(AF_INET, &self.sin_addr, lip, sizeof lip);
    std::string ps = std::to_string(port);
    std::string body = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>"
        "<u:AddPortMapping xmlns:u=\"" + svc + "\">"
        "<NewRemoteHost></NewRemoteHost><NewExternalPort>" + ps + "</NewExternalPort>"
        "<NewProtocol>UDP</NewProtocol><NewInternalPort>" + ps + "</NewInternalPort>"
        "<NewInternalClient>" + lip + "</NewInternalClient><NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>OnePunchHole</NewPortMappingDescription>"
        "<NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>";
    std::string req = "POST " + ctrl + " HTTP/1.1\r\nHOST: " + host +
        "\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"" + svc +
        "#AddPortMapping\"\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    std::string presp;
    if (!http_req(ip, cport, req, presp) || presp.find("200") == std::string::npos) return false;
    printf("upnp: router mapped UDP %u (permanent lease)\n", (unsigned)port);
    return true;
}
// NAT-PMP (RFC 6886), UDP 5351. Many routers disable UPnP but leave NAT-PMP on.
static bool natpmp_map(u_short port) {
    for (const char* gw : {"192.168.1.1", "192.168.0.1", "192.168.1.254", "10.0.0.1"}) {
        SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == INVALID_SOCKET) continue;
        sockaddr_in g{}; g.sin_family = AF_INET; g.sin_port = htons(5351);
        inet_pton(AF_INET, gw, &g.sin_addr);
        timeout(s, 400);
        unsigned char ver[2] = {0, 0}, rep[12];        // v0 query external address
        sockaddr_in from{}; int fl = sizeof from;
        if (sendto(s, (const char*)ver, 2, 0, (SOCKADDR*)&g, sizeof g) != 2 ||
            recvfrom(s, (char*)rep, sizeof rep, 0, (SOCKADDR*)&from, &fl) < 12 || rep[0] != 0) {
            closesocket(s); continue;
        }
        unsigned char req[12] = {0, 1};                // v0, op 1 = UDP map, lifetime 0 = permanent
        req[6] = port >> 8; req[7] = port & 0xff;      // suggested external port
        req[8] = port >> 8; req[9] = port & 0xff;      // internal port
        bool sent = sendto(s, (const char*)req, sizeof req, 0, (SOCKADDR*)&g, sizeof g) == (int)sizeof req;
        unsigned char r2[16];
        if (sent && recvfrom(s, (char*)r2, sizeof r2, 0, (SOCKADDR*)&from, &fl) >= 16 && r2[1] == 128) {
            printf("nat-pmp: gateway %s mapped UDP %u (permanent)\n", gw, (unsigned)port);
            closesocket(s);
            return true;
        }
        closesocket(s);
    }
    return false;
}
static bool port_map(SOCKET s, u_short port) { return port && (upnp_map(s, port) || natpmp_map(port)); }
static bool discover(SOCKET s, const std::vector<sockaddr_in>& srvs, int idx, sockaddr_in* mapped) {
    for (size_t i = 0; i < srvs.size(); i++)
        if (stun_query(s, srvs[(i + idx) % srvs.size()], mapped)) return true;
    return false;
}
int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w)) return 1;
    srand((unsigned)time(nullptr));
    std::vector<const char*> hosts;                    // stun hosts = args that aren't the
    u_short local_port = 0;                            // command, an ip:port peer, or a bare port
    for (int i = 2; i < argc; i++) {
        if (is_num(argv[i])) local_port = (u_short)atoi(argv[i]);
        else if (!strchr(argv[i], ':')) hosts.push_back(argv[i]);
    }
    if (hosts.empty()) hosts.assign(STUNS, STUNS + 5);
    std::vector<sockaddr_in> srvs;
    for (const char* h : hosts) {
        sockaddr_in a{};
        if (resolve(h, 3478, &a)) srvs.push_back(a);
        else fprintf(stderr, "resolve failed: %s\n", h);
    }
    if (srvs.empty()) { puts("no reachable STUN server"); return 1; }
    if (argc > 1 && !strcmp(argv[1], "check")) {       // NAT probe: ONE socket, two servers,
        SOCKET s = udp_sock(local_port);               // else two local ports fake the result
        if (local_port) port_map(s, local_port);
        sockaddr_in a{}, b{};
        bool ok = stun_query(s, srvs[0], &a) && stun_query(s, srvs[srvs.size() > 1 ? 1 : 0], &b);
        closesocket(s);
        if (!ok) { puts("STUN query failed"); return 1; }
        printf("reflex via %-22s %s\n", hosts[0], ep(a).c_str());
        printf("reflex via %-22s %s\n", hosts[srvs.size() > 1 ? 1 : 0], ep(b).c_str());
        puts(same_ep(a, b) ? "NAT: endpoint-independent -> hole punching CAN work"
                           : "NAT: symmetric -> needs port mapping (UPnP/NAT-PMP) or TURN");
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "stun")) {
        SOCKET s = udp_sock(local_port);
        sockaddr_in m{};
        bool ok = discover(s, srvs, 0, &m);
        closesocket(s);
        if (ok) printf("reflex %s\n", ep(m).c_str()); else puts("STUN query failed");
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "punch")) {
        SOCKET s = udp_sock(local_port);               // ONE socket for the entire run
        if (local_port) port_map(s, local_port);       // fix symmetric NAT if the router allows
        sockaddr_in mapped{};
        if (!discover(s, srvs, 0, &mapped)) { closesocket(s); puts("STUN failed - no mapping"); return 1; }
        timeout(s, 0);                                 // punch loop uses select(), no recv deadline
        printf("reflex %s\n", ep(mapped).c_str());
        sockaddr_in peer{};
        if (argc > 2 && parse_ep(argv[2], &peer)) printf("punching %s\n", ep(peer).c_str());
        else {
            char line[128];
            printf("enter peer endpoint (ip:port): ");
            while (!fgets(line, sizeof line, stdin) || !parse_ep(line, &peer)) {
                if (feof(stdin)) { closesocket(s); return 1; }
                printf("bad endpoint, try ip:port: ");
            }
        }
        std::atomic<bool> quit{false};
        std::thread([&] {                               // stdin -> peer, then a BYE on exit
            char line[512];
            while (fgets(line, sizeof line, stdin)) {
                size_t n = strlen(line);
                while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
                if (!n) continue;
                if (!strcmp(line, "quit")) break;
                put(line, s, peer);
            }
            put("BYE", s, peer);
            quit = true;
        }).detach();
        bool connected = false;
        int attempt = 0, seq = 0, rc = 0;
        auto now = std::chrono::steady_clock::now();
        auto next = now, last = now;
        printf("punching %s (every 250ms, up to %d attempts)\n", ep(peer).c_str(), MAX_ATTEMPTS);
        printf("type a message and hit Enter to send; 'quit' to exit\n");
        for (;;) {
            fd_set r; FD_ZERO(&r); FD_SET(s, &r);
            timeval tv{1, 0};
            if (select(0, &r, nullptr, nullptr, &tv) > 0) {
                char b[512]; sockaddr_in from{}; int fl = sizeof from;
                int n = recvfrom(s, b, sizeof b - 1, 0, (SOCKADDR*)&from, &fl);
                if (n > 0 && same_ep(from, peer)) {    // accept ONLY the peer, never a spoofed source
                    b[n] = 0; last = std::chrono::steady_clock::now();
                    if (!connected) { connected = true; puts("HOLE PUNCHED"); }
                    if (!strcmp(b, "BYE")) { puts("peer disconnected"); break; }
                    if (strncmp(b, "KEEP ", 5)) printf("peer> %s\n", b);
                }
            }
            now = std::chrono::steady_clock::now();
            if (quit) break;                                        // we said goodbye
            if (connected && now - last > PEER_TIMEOUT * 1s) {      // silence => peer is gone
                puts("peer disconnected (no packets)"); break;
            }
            if (now >= next) {
                if (!connected && ++attempt > MAX_ATTEMPTS) {
                    printf("gave up after %.0fs (no response from peer)\n", MAX_ATTEMPTS * 0.25);
                    rc = 2; break;
                }
                next = now + (connected ? 1s : 250ms);
                if (!connected && attempt % 20 == 0) printf("  ...still punching (%d/%d)\n", attempt, MAX_ATTEMPTS);
                put(connected ? "KEEP " + std::to_string(++seq) : "PUNCH " + std::to_string(attempt), s, peer);
            }
        }
        closesocket(s);
        WSACleanup();
        return rc;
    }
    puts("usage: OnePunchHole stun|check|punch [ip:port] [port] [hosts...]");
    return 1;
}
