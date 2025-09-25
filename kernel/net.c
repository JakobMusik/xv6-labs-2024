#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15);

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };

static struct spinlock netlock;

#define MAX_PENDING_PACKETS 16
#define MAX_UDP_PORTS 1024
#define PORT_LIMIT 65536

struct pending_packet {
  struct pending_packet *next;
  int len;
  uint32 src_ip;
  uint16 src_port;
  char* data;
};

struct udp_port {
  int in_use;
  int packet_count;
  struct spinlock lock;
  struct pending_packet* head;
  struct pending_packet* tail;
};

struct udp_pcb {
  struct spinlock lock;
  int port_cnt;
  struct udp_port ports[65536];
} udp_pcb_table;

void
netinit(void)
{
  initlock(&netlock, "netlock");
  initlock(&udp_pcb_table.lock, "udp_pcb_table");
  for (int i = 0; i < PORT_LIMIT; i++) {
    initlock(&udp_pcb_table.ports[i].lock, "port_lock");
  }
}


//
// bind(int port)
// prepare to receive UDP packets address to the port,
// i.e. allocate any queues &c needed.
//
uint64
sys_bind(void)
{
  //
  // Your code here.
  //
  int port_num;
  argint(0, &port_num);

  acquire(&udp_pcb_table.lock);
  if (udp_pcb_table.port_cnt >= MAX_UDP_PORTS) {
    release(&udp_pcb_table.lock);
    return -1; // no more ports available
  }
  if (port_num < 0 || port_num >= PORT_LIMIT) {
    release(&udp_pcb_table.lock);
    return -1;
  }

  struct udp_port* bound_port = &udp_pcb_table.ports[port_num];
  if (bound_port->in_use) {
    release(&udp_pcb_table.lock);
    return -1; // port already in use
  }

  bound_port->in_use = 1;
  bound_port->packet_count = 0;
  initlock(&bound_port->lock, "port_lock");
  bound_port->head = 0;
  bound_port->tail = 0;

  release(&udp_pcb_table.lock);
  return 0;
}

//
// unbind(int port)
// release any resources previously created by bind(port);
// from now on UDP packets addressed to port should be dropped.
//
uint64
sys_unbind(void) // implementation not tested
{
  //
  // Optional: Your code here.
  //
  int port_num;
  argint(0, &port_num);
  if (port_num < 0 || port_num >= PORT_LIMIT) {
    release(&udp_pcb_table.lock);
    return -1;
  }

  struct udp_port* bound_port = &udp_pcb_table.ports[port_num];
  acquire(&bound_port->lock);
  if (!bound_port->in_use) {
    release(&bound_port->lock);
    return -1; // port not in use
  }
  bound_port->in_use = 0;

  // free any queued packets
  while (bound_port->head) {
    struct pending_packet* pkt = bound_port->head;
    bound_port->head = pkt->next;
    if (pkt->data) {
      kfree(pkt->data);
      pkt->data = 0;
    }
    kfree(pkt);
    bound_port->packet_count--;
  }

  bound_port->tail = 0;
  release(&bound_port->lock);

  return 0;
}

//
// recv(int dport, int *src, short *sport, char *buf, int maxlen)
// if there's a received UDP packet already queued that was
// addressed to dport, then return it.
// otherwise wait for such a packet.
//
// sets *src to the IP source address.
// sets *sport to the UDP source port.
// copies up to maxlen bytes of UDP payload to buf.
// returns the number of bytes copied,
// and -1 if there was an error.
//
// dport, *src, and *sport are host byte order.
// bind(dport) must previously have been called.
//
uint64
sys_recv(void)
{
  //
  // Your code here.
  //
  int port_num;
  uint64 src;
  uint64 sport;
  uint64 buf;
  struct proc *p = myproc();
  int maxlen;
  argint(0, &port_num);
  argaddr(1, &src);
  argaddr(2, &sport);
  argaddr(3, &buf);
  argint(4, &maxlen);

  if (port_num < 0 || port_num >= 65536)
    return -1;
  struct udp_port* bound_port = &udp_pcb_table.ports[port_num];
  acquire(&bound_port->lock);
  if (!bound_port->in_use)
    return -1; // port not bound

  while (bound_port->head == 0) {
    if (p->killed) {
      release(&bound_port->lock);
      return -1;
    }
    sleep(bound_port, &bound_port->lock); // wait for a packet to arrive
  }
  struct pending_packet* pkt = bound_port->head;
  bound_port->head = bound_port->head->next;
  if (!bound_port->head) {
    bound_port->tail = 0;
  }

  int len;
  int failed = 0;
  if (copyout(p->pagetable, src, (char*)&pkt->src_ip, sizeof(pkt->src_ip)) < 0 ||
      copyout(p->pagetable, sport, (char*)&pkt->src_port, sizeof(pkt->src_port)) < 0 ||
      copyout(p->pagetable, buf, pkt->data, len = pkt->len > maxlen ? maxlen : pkt->len) < 0) {
    failed = 1;
  }

  if (pkt->data) {
    kfree(pkt->data);
    pkt->data = 0;  // important: avoid double free
  }
  kfree(pkt);
  bound_port->packet_count--;
  release(&bound_port->lock);

  return failed ? -1 : len;
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

//
// send(int sport, int dst, int dport, char *buf, int len)
//
uint64
sys_send(void)
{
  struct proc *p = myproc();
  int sport;
  int dst;
  int dport;
  uint64 bufaddr;
  int len;

  argint(0, &sport);
  argint(1, &dst);
  argint(2, &dport);
  argaddr(3, &bufaddr);
  argint(4, &len);

  int total = len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);
  if(total > PGSIZE)
    return -1;

  char *buf = kalloc();
  if(buf == 0){
    printf("sys_send: kalloc failed\n");
    return -1;
  }
  memset(buf, 0, PGSIZE);

  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, host_mac, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45; // version 4, header length 4*5
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp) + len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 100;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = htonl(dst);
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

  struct udp *udp = (struct udp *)(ip + 1);
  udp->sport = htons(sport);
  udp->dport = htons(dport);
  udp->ulen = htons(len + sizeof(struct udp));

  char *payload = (char *)(udp + 1);
  if(copyin(p->pagetable, payload, bufaddr, len) < 0){
    kfree(buf);
    printf("send: copyin failed\n");
    return -1;
  }

  e1000_transmit(buf, total);

  return 0;
}

void
ip_rx(char *buf, int len)
{
  // don't delete this printf; make grade depends on it.
  static int seen_ip = 0;
  if(seen_ip == 0)
    printf("ip_rx: received an IP packet\n");
  seen_ip = 1;

  //
  // Your code here.
  //

  struct eth* in_eth_hdr = (struct eth*)buf;
  struct ip* in_ip_hdr = (struct ip*)(in_eth_hdr + 1);
  uint32 src_ip = ntohl(in_ip_hdr->ip_src);

  // Process the IP packet
  switch (in_ip_hdr->ip_p) {
    case IPPROTO_UDP: {
      struct udp* in_udp_hdr = (struct udp*)(in_ip_hdr + 1);
      int udp_len = ntohs(in_udp_hdr->ulen);
      uint16 in_dport = ntohs(in_udp_hdr->dport);
      uint16 in_sport = ntohs(in_udp_hdr->sport);

      char* payload = (char*)(in_udp_hdr + 1);
      int payload_len = udp_len - sizeof(struct udp);

      if (in_dport < 0 || in_dport >= 65536)
        break;
      struct udp_port* bound_port = &udp_pcb_table.ports[in_dport];
      acquire(&bound_port->lock);
      if (!bound_port->in_use || bound_port->packet_count >= MAX_PENDING_PACKETS) {
        release(&bound_port->lock);
        break; // port not bound or too many queued packets, drop the packet
      }

      struct pending_packet* pkt = (struct pending_packet*)kalloc();
      if (!pkt) {
        release(&bound_port->lock);
        break; // allocation failed, drop the packet
      }
      memset(pkt, 0, sizeof(*pkt)); // important: avoid garbage values

      if ((pkt->data = (char*)kalloc()) == 0) {
        kfree(pkt);
        release(&bound_port->lock);
        break; // allocation failed, drop the packet
      }

      memmove(pkt->data, payload, payload_len);
      pkt->len = payload_len;
      pkt->src_ip = src_ip;
      pkt->src_port = in_sport;
      pkt->next = 0;

      if (bound_port->tail) {
        bound_port->tail->next = pkt;
        bound_port->tail = pkt;
      } else {
        bound_port->head = bound_port->tail = pkt;
      }
      bound_port->packet_count++;

      wakeup(bound_port); // wake up any process waiting in recv()

      release(&bound_port->lock);
      break;
    }
    default:
      // only udp is supported
      break;
  }
  kfree(buf);

  return;
}

//
// send an ARP reply packet to tell qemu to map
// xv6's ip address to its ethernet address.
// this is the bare minimum needed to persuade
// qemu to send IP packets to xv6; the real ARP
// protocol is more complex.
//
void
arp_rx(char *inbuf)
{
  static int seen_arp = 0;

  if(seen_arp){
    kfree(inbuf);
    return;
  }
  printf("arp_rx: received an ARP packet\n");
  seen_arp = 1;

  struct eth *ineth = (struct eth *) inbuf;
  struct arp *inarp = (struct arp *) (ineth + 1);

  char *buf = kalloc();
  if(buf == 0)
    panic("send_arp_reply");
  
  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN); // ethernet destination = query source
  memmove(eth->shost, local_mac, ETHADDR_LEN); // ethernet source = xv6's ethernet address
  eth->type = htons(ETHTYPE_ARP);

  struct arp *arp = (struct arp *)(eth + 1);
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op = htons(ARP_OP_REPLY);

  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  memmove(arp->tha, ineth->shost, ETHADDR_LEN);
  arp->tip = inarp->sip;

  e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));

  kfree(inbuf);
}

void
net_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *) buf;

  if(len >= sizeof(struct eth) + sizeof(struct arp) &&
     ntohs(eth->type) == ETHTYPE_ARP){
    arp_rx(buf);
  } else if(len >= sizeof(struct eth) + sizeof(struct ip) &&
     ntohs(eth->type) == ETHTYPE_IP){
    ip_rx(buf, len);
  } else {
    kfree(buf);
  }
}
