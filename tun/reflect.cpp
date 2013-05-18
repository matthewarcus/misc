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
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/capability.h>

// Might need eg. 'sudo apt-get install libcap-dev' and link with -lcap
// sudo setcap cap_net_admin+p ./reflect

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
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, IFNAMSIZ); 
  CHECKSYS(ioctl(fd, TUNSETIFF, (void *) &ifr));
  strncpy(dev, ifr.ifr_name, IFNAMSIZ); 
  return fd;
}

static inline void put32(uint8_t *p, size_t offset, uint32_t n)
{
  memcpy(p+offset,&n,sizeof(n));
}

static inline uint32_t get32(uint8_t *p, size_t offset)
{
  uint32_t n;
  memcpy(&n,p+offset,sizeof(n));
  return n;
}

// Rewrite packet to exchange src and dst addresses

void reflect(uint8_t *p, size_t nbytes)
{
  (void)nbytes;
  // Check we have an IPv4 packet
  uint8_t version = p[0] >> 4;
  switch (version) {
  case 4:
    break;
  case 6:
    fprintf(stderr, "IPv6 not implemented yet\n");
    exit(0);
  default:
    fprintf(stderr, "Unknown protocol %u\n", version);
    exit(0);
  }
  // Swap source and dest of an IPV4 packet
  // No checksum recalculation is necessary
  uint32_t src = get32(p,12);
  uint32_t dst = get32(p,16);
  put32(p,12,dst);
  put32(p,16,src);
}

int main(int argc, char *argv[])
{
  char dev[IFNAMSIZ+1];
  memset(dev,0,sizeof(dev));
  if (argc > 1) strncpy(dev,argv[1],sizeof(dev)-1);

  cap_t caps = cap_get_proc();
  CHECK(caps != NULL);

  cap_value_t cap = CAP_NET_ADMIN;
  const char *capname = STRING(CAP_NET_ADMIN);

  // Check that we have the required capabilities
  // At this point we only require CAP_NET_ADMIN to be permitted,
  // not effective as we will be enabling it later.
  cap_flag_value_t cap_permitted;
  CHECKSYS(cap_get_flag(caps, cap, CAP_PERMITTED, &cap_permitted));
  cap_flag_value_t cap_effective;
  cap_flag_value_t cap_inheritable;
  CHECKSYS(cap_get_flag(caps, cap, CAP_EFFECTIVE, &cap_effective));
  CHECKSYS(cap_get_flag(caps, cap, CAP_INHERITABLE, &cap_inheritable));
  fprintf(stderr, "Capability %s: %d %d %d\n",
          capname, cap_effective, cap_inheritable, cap_permitted);
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

  // Allocate the tun device
  int fd = tun_alloc(dev);
  if (fd < 0) exit(0);

  // And before anything else, clear all our capabilities
  CHECKSYS(cap_clear(caps));
  CHECKSYS(cap_set_proc(caps));
  CHECKSYS(cap_free(caps));

  fprintf(stderr, "Created tun device %s\n", dev);
  
  uint8_t buf[2048];
  while(true) {
    // Sit in a loop, read a packet from fd, reflect addresses
    // and write back to fd.
    ssize_t nread = read(fd,buf,sizeof(buf));
    CHECK(nread >= 0);
    if (nread == 0) break;
    reflect(buf,nread);
    ssize_t nwrite = write(fd,buf,nread);
    CHECK(nwrite == nread);
  }
}
