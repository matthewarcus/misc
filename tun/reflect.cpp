#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>

// Optionally, compile to use capabilities (to avoid running as root or needind setuid).
// Might need eg. 'sudo apt-get install libcap-dev libcap2-bin' and link with -lcap
// Set capabilities (see Makefile) with:
// sudo setcap cap_net_admin+p ./reflect

#define USE_CAPABILITIES
#if defined USE_CAPABILITIES
#include <sys/capability.h>
#endif

// Some handy macros to help with error checking
#define CHECKAUX(e,s)                            \
 ((e)? \
  (void)0: \
  (fprintf(stderr, "'%s' failed at %s:%d - %s\n", \
           s, __FILE__, __LINE__,strerror(errno)), \
   exit(0)))
#define CHECK(e) (CHECKAUX(e,#e))
#define CHECKSYS(e) (CHECKAUX((e)==0,#e))
#define CHECKFD(e) (CHECKAUX((e)>=0,#e))

#define STRING(e) #e

int verbosity = 0;

// Fairly standard allocation of a temporary tundevice
// A variation of the code at http://www.kernel.org/doc/Documentation/networking/tuntap.txt

// Return the fd of the new tun device
// Sets dev to the actual device name
int tun_alloc(char *dev) 
{
  assert(dev != NULL);
  int fd = open("/dev/net/tun", O_RDWR);
  CHECKFD(fd);

  struct ifreq ifr; 
  memset(&ifr, 0, sizeof(ifr)); 
  //ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, IFNAMSIZ); 
  CHECKSYS(ioctl(fd, TUNSETIFF, (void *) &ifr));
  strncpy(dev, ifr.ifr_name, IFNAMSIZ); 
  return fd;
}

static inline void put32(uint8_t *p, uint32_t n)
{
  memcpy(p,&n,sizeof(n));
}

static inline uint32_t get32(uint8_t *p)
{
  uint32_t n;
  memcpy(&n,p,sizeof(n));
  return n;
}

static inline uint16_t get16(uint8_t *p)
{
  uint16_t n;
  memcpy(&n,p,sizeof(n));
  return n;
}

static inline uint8_t get8(uint8_t *p)
{
  return *p;
}

static void printbytes(uint8_t *p, size_t nbytes)
{
  for (size_t i = 0; i < nbytes; i++) {
    printf("%02x%s",
	   p[i],
	   ((i+1)%16 == 0 || i+1 == nbytes)?"\n":" ");
  }
}

void swap32(uint8_t *p, uint8_t *q)
{
  uint32_t t = get32(p);
  put32(p,get32(q));
  put32(q,t);
}

// Rewrite packet to exchange src and dst addresses
// Compare start and end states
// Raise exceptions to indicate errors rather than exit()
// Leave printing errors to caller.
// Checks: p is non-null, nbytes is big enough for IP header
// check on other fields - eg header length? 
// Check IP checksum afterwards.
// check no other bytes changed by function

#define SRC_OFFSET4 12
#define DST_OFFSET4 16
#define SRC_OFFSET6 8
#define DST_OFFSET6 24
#define HLEN_OFFSET 0
#define PROTO_OFFSET 9
#define PROTO_ICMP 1
#define PROTO_UDP 17
#define PROTO_TCP 6

void describe4(uint8_t *p, size_t nbytes, const char *dev)
{
   char fromaddr[INET_ADDRSTRLEN];
   char toaddr[INET_ADDRSTRLEN];
   int headerlen = 4*(p[HLEN_OFFSET]&0x0f);
   int proto = p[PROTO_OFFSET];
   inet_ntop(AF_INET, p+SRC_OFFSET4, fromaddr, sizeof(fromaddr));
   inet_ntop(AF_INET, p+DST_OFFSET4, toaddr, sizeof(toaddr));
   uint8_t *phdr = p+headerlen;
   if (proto == PROTO_TCP) {
      // Should do this for IPv6 as well
      uint16_t srcport = ntohs(get16(phdr+0));
      uint16_t dstport = ntohs(get16(phdr+2));
      uint16_t flags = 0x0f & get8(phdr+13);
      char flagstring[16];
      snprintf(flagstring, sizeof(flagstring),
               "%s%s%s%s",
               (flags&1)?"F":"",
               (flags&2)?"S":"", 
               (flags&4)?"R":"",
               (flags&8)?"P":"");
      printf("dev=%s src=%s:%hu dst=%s:%hu len=%zu proto=%d flags=%s\n", 
             dev, fromaddr, srcport, toaddr, dstport, nbytes, proto, flagstring);
   } else if (proto == PROTO_UDP) {
      uint16_t srcport = ntohs(get16(phdr+0));
      uint16_t dstport = ntohs(get16(phdr+2));
      printf("dev=%s src=%s:%hu dst=%s:%hu len=%zu proto=%d\n",
             dev, fromaddr, srcport, toaddr, dstport, nbytes, proto);
   } else {
      printf("dev=%s src=%s dst=%s len=%zu proto=%d\n",
             dev, fromaddr, toaddr, nbytes, proto);
   }
}
void reflect(uint8_t *p, size_t nbytes, const char *dev)
{
  uint8_t version = p[0] >> 4;
  switch (version) {
  case 4:
    if (verbosity > 0) {
       describe4(p,nbytes,dev);
    }
    // Swap source and dest of an IPv4 packet
    // No checksum recalculation is necessary
    swap32(p+SRC_OFFSET4,p+DST_OFFSET4);
    break;
  case 6:
    if (verbosity > 0) {
      char fromaddr[INET6_ADDRSTRLEN];
      char toaddr[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, p+SRC_OFFSET6, fromaddr, sizeof(fromaddr));
      inet_ntop(AF_INET6, p+DST_OFFSET6, toaddr, sizeof(toaddr));
      printf("%zu: %s->%s\n", nbytes, fromaddr, toaddr);
    }
    // Swap source and dest of an IPv6 packet
    // No checksum recalculation is necessary
    for (int i = 0; i < 4; i++) {
      swap32(p+SRC_OFFSET6+4*i,p+DST_OFFSET6+4*i);
    }
    break;
  default:
     uint16_t etype;
     memcpy(&etype,p+12,2);
     etype = ntohs(etype);
     printf("Unknown protocol %u: nbytes=%zu etype=%04x\n",
            version, nbytes, etype);
     printf("Addr1: "); printbytes(p,6);
     printf("Addr2: "); printbytes(p+6,6);
     if (etype == 0x0800) {
        describe4(p+14,nbytes-16,dev);
     }
  }
  if (verbosity > 1) {
     printbytes(p, nbytes);
  }
}

int main(int argc, char *argv[])
{
  char *progname = argv[0];
  char *devname = NULL;
  argc--; argv++;
  while (argc > 0 && argv[0][0] == '-') {
    if (strcmp(argv[0],"-v") == 0) {
      verbosity++;
    } else {
      fprintf(stderr, "Usage: %s [-v]\n", progname);
      exit(0);
    }
    argc--; argv++;
  }
  if (argc > 0) devname = argv[0];

  char dev[IFNAMSIZ+1];
  memset(dev,0,sizeof(dev));
  if (devname != NULL) strncpy(dev,devname,sizeof(dev)-1);

#if defined USE_CAPABILITIES
  cap_t caps = cap_get_proc();
  CHECK(caps != NULL);

  cap_value_t cap = CAP_NET_ADMIN;
  const char *capname = STRING(CAP_NET_ADMIN);

  // Check that we have the required capabilities
  // At this point we only require CAP_NET_ADMIN to be permitted,
  // not effective as we will be enabling it later.
  cap_flag_value_t cap_permitted;
  CHECKSYS(cap_get_flag(caps, cap, CAP_PERMITTED, &cap_permitted));
  if (verbosity > 0) {
    cap_flag_value_t cap_effective;
    cap_flag_value_t cap_inheritable;
    CHECKSYS(cap_get_flag(caps, cap, CAP_EFFECTIVE, &cap_effective));
    CHECKSYS(cap_get_flag(caps, cap, CAP_INHERITABLE, &cap_inheritable));
    printf("Capability %s: %d %d %d\n",
	    capname, cap_effective, cap_inheritable, cap_permitted);
  }
  if (!cap_permitted) {
    fprintf(stderr, "%s not permitted, exiting\n", capname);
    exit(0);
  }

  // And retain only what we require
  CHECKSYS(cap_clear(caps));
  // We must leave it permitted
  CHECKSYS(cap_set_flag(caps, CAP_PERMITTED, 1, &cap, CAP_SET));
  // but also make it effective
  CHECKSYS(cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, CAP_SET));
  CHECKSYS(cap_set_proc(caps));
#endif

  // Allocate the tun device
  int fd = tun_alloc(dev);
  if (fd < 0) exit(0);

#if defined USE_CAPABILITIES
  // And before anything else, clear all our capabilities
  CHECKSYS(cap_clear(caps));
  CHECKSYS(cap_set_proc(caps));
  CHECKSYS(cap_free(caps));
#endif

  if (verbosity > 0) {
    printf("Created tun device %s\n", dev);
  }

  uint8_t buf[2048];
  while(true) {
    // Read a packet from fd, reflect addresses and write back to fd.
    ssize_t nread = read(fd,buf,sizeof(buf));
    CHECK(nread >= 0);
    if (nread == 0) break;
    reflect(buf,nread,dev);
    ssize_t nwrite = write(fd,buf,nread);
    CHECK(nwrite == nread);
  }
}
