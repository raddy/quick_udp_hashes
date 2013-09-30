import numpy as np
import pandas as pd
import sys
cimport cython
cimport numpy as np
from libc.stdlib cimport malloc, free
from libc.string cimport strlen

from sklearn.utils import murmurhash3_32


ctypedef np.double_t DTYPE_t

cdef extern from *:
    ctypedef char const_char "const char"
    ctypedef void const_void "const void"
    
cdef extern from "string.h" nogil:
    char *strncpy (char *TO, const_char *FROM, size_t SIZE)
    void *memcpy  (void *TO, const_void *FROM, size_t SIZE)

cdef extern from "time.h":
    ctypedef long time_t
    ctypedef long suseconds_t

    struct timeval:
        time_t tv_sec
        suseconds_t  tv_usec
    
    struct tm:
        int	tm_sec
        int	tm_min
        int	tm_hour
        int	tm_mday
        int	tm_mon
        int	tm_year
        int	tm_wday
        int	tm_yday
        int	tm_isdst
        long tm_gmtoff
        char *tm_zone
    tm *localtime(const time_t *)
    
cdef extern from "pcap.h":
    struct pcap_pkthdr:
        timeval ts
    ctypedef struct pcap_t:
        int __xxx
    pcap_t *pcap_open_offline(const char *, char *)
    unsigned char *pcap_next(pcap_t *p, pcap_pkthdr *hdr)
    void pcap_close(pcap_t *)

cdef extern from "netinet/in.h":
    ctypedef unsigned int in_addr_t
    
    ctypedef struct in_addr:
        in_addr_t s_addr
    
cdef extern from "netinet/ip.h":
    struct ip:
        unsigned short ip_len
        unsigned char ip_p
        unsigned int ip_hl #AFAIK cython does NOT support bit fields -- tbh I don't know how these get packed anyways
        in_addr ip_src,ip_dst
cdef extern from "arpa/inet.h":
    cdef enum:
        INET_ADDRSTRLEN
        INET6_ADDRSTRLEN

    int htons (int)
    int htonl (int)
    int ntohl (int)
    int ntohs (int)
    char* inet_ntoa(in_addr)

cdef extern from "netinet/udp.h":
    struct udphdr:
        unsigned short uh_sport
        unsigned short uh_dport

#let's just ignore non-udp for now
@cython.cdivision(True)
@cython.boundscheck(False)
def open_pcap(some_pcap):
    cdef:
        char __ebuf[256] #error buffer for pcap opening
        char *p = some_pcap
        pcap_t *handle = pcap_open_offline(p,__ebuf)
        pcap_pkthdr header
        const unsigned char *packet
        unsigned char* pkt_ptr
        ip *ip_hdr
        udphdr *udpHdr
        char *data
        int data_len
        int ip_hdr_len
        int ether_type
        int ether_offset
        long MAX_SIZE = 30000000
        long pkt_counter=0
        
        
        #let's just colect the size, source port and destination port as doubles and
        #cast back when we build h5 later                
        long * epoch_times = <long *> malloc(sizeof(long)*MAX_SIZE)
        #char ** packet_data = <char**> malloc(sizeof(char*)*MAX_SIZE)
        long KST_TZ_OFFSET = 9 * 60 * 60 * 1000 * 1000 * 1000
        dict hashes = {}
        #np.ndarray[object, ndim=1] hashes = np.empty(MAX_SIZE,dtype=object)
        
    
    while pkt_counter < MAX_SIZE:
        packet = pcap_next(handle,&header)
        if packet is NULL:
            break
        pkt_ptr = <unsigned char *> packet
        ether_type = (<int>(pkt_ptr[12]) << 8) | <int>(pkt_ptr[13])
        if ether_type == 0x0800: #ether type == 2048
            ether_offset = 14 #14 bytes
        pkt_ptr+=ether_offset
        ip_hdr = <ip *>pkt_ptr
        packet_length = ntohs(ip_hdr.ip_len)
        if ip_hdr.ip_p == 17: #UDP == 17 bro
            ip_hdr_len = ip_hdr.ip_hl*4 #is this always 20 bytes since we're v4?
            udpHdr = (<udphdr *> (<char *>ip_hdr + ip_hdr_len))
            data = ((<char *> udpHdr) + sizeof(udphdr))
            data_len = (packet_length - sizeof(udphdr) - ip_hdr_len)
            data[data_len] = 0
            hash_info = murmurhash3_32(data,positive=True)
            if hashes.has_key(hash_info):
                hashes[hash_info] = np.NaN
            else:
                hashes[hash_info] = header.ts.tv_sec * 1000000000 +header.ts.tv_usec*1000 + KST_TZ_OFFSET

    
    return pd.DataFrame(hashes.values(),index=hashes.keys())