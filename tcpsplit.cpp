/*

This is too simple to go full blown C++, but I need a map so I cannot do it in C.
Hence C like C++. Not my clearest program ever.

Also, I want this to be a simple copy-and-run executable. C++ libs can be assumed,
but Net::Pcap not, so perl is out as well.

(C) 2015 M. Lievaart

Hereby granting license for reproduction under GPL v2

*/


#include <pcap.h>
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <string>
#include <sstream>
#include <map>
#include <deque>
#include <algorithm>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <cassert>

using std::cerr;


std::string version = "v1.0 (work)"; // still figuring out git and release versioning

int debug;
int verbose;
std::string outform("stream-%04d.pcap");   // output format
int llsize = -1;                                // Link Layer size
bool quit;                                 // set from signal handle
int nopen, maxopen;                        // number of files currently open and max we want to have open


void handle_packet(pcap_t *infile, const pcap_pkthdr *pkt_header, const u_char *pkt_data);
pcap_dumper_t *open_new_outfile(pcap_t *infile);

//
// host order uint32 to dotted ip address
//

std::string uint2ipaddress(u_int32_t x)
{
    char buf[16];
    sprintf(buf, "%d.%d.%d.%d", (x >> 24), ((x >> 16) & 0xff), ((x >> 8) & 0xff), (x & 0xff));
    return buf;
}

//
// Class that represents a connection tuple and thus is a key-value for the connection
//

struct connection_key_t {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int16_t sport;
	u_int16_t dport;

    // FIX ME? overload <<
    std::string as_string() const {
        std::stringstream str;
        str << "{" << uint2ipaddress(ntohl(this->saddr)) << ":"
            << uint2ipaddress(ntohl(this->daddr)) << ":"
            << ntohs(this->sport) << ":"
            << ntohs(this->dport) << "}";
        return str.str();
    }
};

bool operator<(const connection_key_t a, const connection_key_t b) {
    return (a.saddr<b.saddr || (a.saddr==b.saddr &&
                                (a.daddr<b.daddr || (a.daddr==b.daddr &&
                                                     (a.sport<b.sport || (a.sport==b.sport &&
                                                                            a.dport<b.dport))))));
}

bool operator==(const connection_key_t a, const connection_key_t b) {
    return a.saddr==b.saddr && a.daddr==b.daddr && a.sport==b.sport && a.dport==b.dport;
}


//
// all information we keep on a connection
//

struct connection_t {
    pcap_dumper_t *outfile;
    bool fin_rst; // a FIN or RST has been seen, so next SYN is a new connection

    connection_t(pcap_dumper_t *of) 
        : outfile(of), fin_rst(false) {}

    void close(const connection_key_t &);
};

//
// Info on the connections we are currently processing
//
std::map<connection_key_t, connection_t> conninfo;

//
// These connections are supposedly dead and their filehandles
// can be reused when we run out of filehandles.
//
// Note that connections on `closed' are also on `conninfo', which
// is more or less the whole idea, to know which connections we can
// reuse and in which order
//
std::deque<connection_key_t> closed;


void connection_t::close(const connection_key_t &key) {
    fin_rst = true;
    if (std::find(closed.begin(), closed.end(), key)==closed.end()) {
        if (debug) cerr << "Pushing on closed: " << key.as_string() << "\n";
        closed.push_back(key);
    }
}


void usage(const char* argv0)
{
    cerr << "tcpsplit " << version << " (c) 2015 M. Lievaart\n";
    cerr << "usage: " << argv0 << " [-h] [-v] [-o format] <capfile>\n"
        "\nformat defaults to '" << outform << "'\n";
    exit(EXIT_FAILURE);
}

void bailout(int signo)
{
    quit = true;
}

//
// Fun starts here
//

int main(int argc, char** argv)
{
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim)) {
        perror("rlimit");
        exit(EXIT_FAILURE);
    }

    rlim.rlim_cur = rlim.rlim_max;
//    rlim.rlim_cur = 256;
    maxopen = rlim.rlim_cur - 10;
    if (setrlimit(RLIMIT_NOFILE, &rlim)) {
        perror("rlimit");
        exit(EXIT_FAILURE);
    }

    // Get the command line options, if any
    int c;
    while ((c = getopt (argc, argv, "hvdo:l:")) != -1)
    {
        switch (c)
        {
        case 'v':
            verbose++;
            break;
        case 'd':
            debug++;
            break;
        case 'o':
            outform = optarg;
            break;
        case 'l':
            llsize = atoi(optarg);
            break;
        case 'h':
        default:
            usage(argv[0]);
            break;
        }
    }

    if (optind >= argc)
        usage(argv[0]);

    std::string fname = argv[optind];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *infile = pcap_open_offline(fname.c_str(), errbuf);
    if (!infile) {
        cerr << "Cannot open infile: " << errbuf << std::endl;
        exit(1);
    }

    if (llsize==-1) {
        int linktype = pcap_datalink(infile);
        switch (linktype) {
        case DLT_RAW: llsize = 0; break;
        case DLT_NULL: llsize = 4; break;
        case DLT_EN10MB: llsize = 14; break;
        case DLT_LINUX_SLL: llsize = 16; break;
            std::cerr << "Cannot determine size of link layer, sorry (https://idea.popcount.org/2013-01-29-stripping-layer-2-in-pcap/)\n";
            std::cerr << "Use -l <llsize> to force a link layer size\n";
            exit(1);
        }
    }

    struct bpf_program fp;      /* hold compiled program     */
    if (pcap_compile(infile, &fp, "tcp", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Error calling pcap_compile\n";
        exit(1);
    }


    if (pcap_setfilter(infile, &fp) == -1) {
        cerr << "Error calling pcap_setfilter\n";
        exit(1);
    }

    signal(SIGINT, bailout);
    signal(SIGTERM, bailout);
    signal(SIGQUIT, bailout);


    int rc;
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    while (!quit && (rc=pcap_next_ex(infile, &pkt_header, &pkt_data))==1) {
        handle_packet(infile, pkt_header, pkt_data);
    }

    for (auto it = conninfo.begin(); it != conninfo.end(); it++) {
        pcap_dump_close(it->second.outfile);
    }

    if (rc==-1) {
        pcap_perror(infile, (char*)"Error reading packet: "); // bloody const error in pcap interface
        exit(1);
    }

}

bool warn_ipv4;
bool warn_tcp;

void handle_packet(pcap_t *infile, const pcap_pkthdr *pkt_header, const u_char *pkt_data)
{

    // Let's test some basic stuff because I have a feeling
    // bpf can be too intelligent and find tcp somewhere down
    // inside some other protocol. We cannot handle that

    const iphdr *iphdr_ = reinterpret_cast<const iphdr*>(pkt_data+llsize); // bloody stupid type names in ip.h and tcp.h
    if (iphdr_->version != 4) {
        if (!warn_ipv4) {
            std::cerr << "I can only handle IPv4, sorry. Ignoring anything else. BTW, you have the source, so it's all your own fault.\n";
            warn_ipv4 = true;
        }
        return;
    }

    if (iphdr_->protocol != IPPROTO_TCP) {
        if (!warn_tcp) {
            std::cerr << "I got something else than tcp from the pcap filter 'tcp'. This is probably benign, but I don't know how to habdle these packets, so I'm goingto ignore them from now on. Nanananana, I cannot hear you!\n";
            warn_tcp = true;
        }
        return;
    }

    const tcphdr *tcphdr_ = reinterpret_cast<const tcphdr*>(pkt_data+llsize+sizeof(iphdr)); // bloody stupid type names in tcp.h 

    connection_key_t key = {
        iphdr_->saddr,
        iphdr_->daddr,
        tcphdr_->source,
        tcphdr_->dest
    };

    if (iphdr_->saddr < iphdr_->daddr) {
        key = {
            iphdr_->daddr,
            iphdr_->saddr,
            tcphdr_->dest,
            tcphdr_->source
        };
    }

    connection_t *conn;

    // FIXME: SYN means new file if previous stream signaled closed or reset
    auto it = conninfo.find(key);
    if (it==conninfo.end()) {
        conn = &(conninfo.insert(std::make_pair(key, connection_t(open_new_outfile(infile)))).first->second);
        if (debug) cerr << "Opened new outfile for " << key.as_string() << "\n";
    } else {
        // There seems to be a connection, but maybe it is just reusing the same key
        conn = &(it->second);
        if (tcphdr_->syn && conn->fin_rst) {
            pcap_dump_close(conn->outfile);
            connection_t newconn = connection_t(open_new_outfile(infile));
            it->second = newconn;
//            auto it = conninfo.find(key);
//            assert(it!=conninfo.end());
            conn = &(it->second);
            if (debug) cerr << "Opened new outfile for reused connection " << key.as_string() << "\n";
        }
    }

    // Write packet to the right file
    pcap_dump((u_char*)conn->outfile, pkt_header, pkt_data);

    if (tcphdr_->fin || tcphdr_->rst) {
        conn->close(key);
    }
}

unsigned curn=0;
pcap_dumper_t *open_new_outfile(pcap_t *infile)
{
    if (debug) cerr << "Opening new dumpfile (" << nopen << ")\n";
    if (nopen>=maxopen) {
        if (debug) cerr << "Closing some file\n";
        if (closed.size()) {
            connection_key_t key = closed.front();
            closed.pop_front();
            auto it = conninfo.find(key);
            if (it==conninfo.end()) {
                cerr << key.as_string();
                assert(it!=conninfo.end());
            }
            if (debug) cerr << "Closing " << it->second.outfile << "\n";
            pcap_dump_close(it->second.outfile);
            assert(conninfo.erase(key));
        } else {
            cerr << "No file to close. Will probably soon run out of filehandles.\n";
            // almost no file handles left but no closed connections yet.
            // havoc will probably ensue, but maybe some stream will close before
            // we are really out of handles
            // so continue, cross fingers and hope for the best
        }
    } else
        nopen++;

    char fname[1024];
    snprintf(fname, sizeof(fname), outform.c_str(), curn++);
    pcap_dumper_t *outfile = pcap_dump_open(infile, fname);
    if (debug)     cerr << "Opened " << outfile << "\n";
    if (!outfile) {
        pcap_perror(infile, (char*)"Cannot open outfile: "); // bloody const error in pcap interface
        exit(1);
    }
    return outfile;
}

