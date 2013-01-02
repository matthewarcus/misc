#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

// Fairly standard allocation of a temporary tun device
int tun_alloc(char *dev) 
{ 
  struct ifreq ifr; 
  int fd, err; 

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) { 
    fprintf(stderr, "Error opening tun device\n"); 
    return -1; 
  } else {
    fprintf(stderr, "Successfully opened TUN device.\n"); 
  }
  memset(&ifr, 0, sizeof(ifr)); 

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
   *        IFF_TAP   - TAP device  
   * 
   *        IFF_NO_PI - Do not provide packet information  
   */ 
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 
  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ); 
  }
     
  if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) { 
    close(fd); 
    fprintf(stderr, "Error ioctl tun device\n"); 
    return err; 
  } else {
    fprintf(stderr, "ioctl successful\n"); 
  }
  strcpy(dev, ifr.ifr_name); 
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

void reflect(uint8_t *p)
{
  // Swap source and dest of an IPV4 packet
  // No checksum recalculation is necessary
  uint32_t src = get32(p,12);
  uint32_t dst = get32(p,16);
  put32(p,12,dst);
  put32(p,16,src);
}

int main(int argc, char *argv[])
{
  char dev1[10] = "tun0";
  int fd = tun_alloc(dev1);
  uint8_t buf[2048];
  while(true) {
    ssize_t n;
    n = read(fd,buf,sizeof(buf));
    if (n <= 0) break;
    reflect(buf);
    n = write(fd,buf,n);
    if (n <= 0) break;
  }
}
