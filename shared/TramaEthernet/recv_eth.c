#include "eth.h"

const byte BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

typedef struct { char nombre[64]; char red; } HostInfo;
typedef struct { char red; char iface[16]; } RedIface;

HostInfo tablaRutas[] = {
  {"pc1", 'A'}, {"pc2", 'A'}, {"pc3", 'A'}, {"pc3", 'B'}, {"pc4", 'B'}, {"pc5", 'B'}, {"", ' '}
};

RedIface tablaIfaces[] = {
  {'A', "eth0"},
  {'B', "eth1"},
  {' ', ""}
};

char* obtenerIface(char red) {
  for (int i = 0; tablaIfaces[i].red != ' '; i++)
    if (tablaIfaces[i].red == red) return tablaIfaces[i].iface;
  return NULL;
}

char obtenerRed(char *nombre) {
  for (int i = 0; tablaRutas[i].nombre[0]; i++)
    if (strcmp(tablaRutas[i].nombre, nombre) == 0) return tablaRutas[i].red;
  return 'X';
}

int esBroadcast(char *t) {
  for (int i = 0; i < LEN_MAC; i++)
    if ((unsigned char)t[TRAMA_DESTINATION + i] != 0xff) return 0;
  return 1;
}

void obtenerMAC(int sockfd, char *iface, struct ifreq *sir) {
  memset(sir, 0, sizeof(*sir));
  strncpy(sir->ifr_name, iface, IFNAMSIZ - 1);
  ioctl(sockfd, SIOCGIFHWADDR, sir);
}

void enviarConsultaARP(int sockfd, char *iface, char *nombre) {
  byte buf[BUF_SIZ] = {0};
  struct ether_header *h = (struct ether_header *)buf;
  struct sockaddr_ll sa = {0};
  struct ifreq sir;
  
  obtenerMAC(sockfd, iface, &sir);
  memcpy(h->ether_shost, sir.ifr_hwaddr.sa_data, 6);
  memset(h->ether_dhost, 0xff, 6);
  h->ether_type = htons(ETHER_TYPE);
  sprintf((char *)(buf + TRAMA_PAYLOAD), "Q%s", nombre);
  
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETHER_TYPE);
  sa.sll_ifindex = if_nametoindex(iface);
  sa.sll_halen = ETH_ALEN;
  memset(sa.sll_addr, 0xff, 6);
  
  sendto(sockfd, buf, TRAMA_PAYLOAD + strlen(nombre) + 5, 0, (struct sockaddr *)&sa, sizeof(sa));
  printf("→ ARP Query [%s]: %s\n", iface, nombre);
}

int esperarRespuestaARP(int sockfd, byte *macDest) {
  byte buf[BUF_SIZ];
  struct sockaddr sa;
  socklen_t len = sizeof(sa);
  struct timeval tv = {3, 0};
  unsigned int v[6];
  
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  while (recvfrom(sockfd, buf, BUF_SIZ, 0, &sa, &len) > 0) {
    if (buf[TRAMA_PAYLOAD] == 'R') {
      sscanf((char *)(buf + TRAMA_PAYLOAD + 1), "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
      for (int i = 0; i < 6; i++) macDest[i] = v[i];
      tv = (struct timeval){0, 0};
      setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      return 1;
    }
  }
  tv = (struct timeval){0, 0};
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  return 0;
}

void reenviarTrama(int sockfd, byte *tramaOrig, char *destNombre, char redDest) {
  byte macDest[6], buf[BUF_SIZ];
  struct ether_header *h = (struct ether_header *)buf;
  struct sockaddr_ll sa = {0};
  struct ifreq sir;
  char *iface = obtenerIface(redDest);
  int payloadLen;
  
  if (!iface) {
    printf("✗ No hay interfaz para red %c\n", redDest);
    return;
  }
  
  enviarConsultaARP(sockfd, iface, destNombre);
  if (!esperarRespuestaARP(sockfd, macDest)) {
    printf("✗ No se encontró %s en red %c\n", destNombre, redDest);
    return;
  }
  
  obtenerMAC(sockfd, iface, &sir);
  memcpy(buf, tramaOrig, BUF_SIZ);
  memcpy(h->ether_dhost, macDest, 6);
  memcpy(h->ether_shost, sir.ifr_hwaddr.sa_data, 6);
  
  payloadLen = strlen((char *)(buf + TRAMA_PAYLOAD));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETHER_TYPE);
  sa.sll_ifindex = if_nametoindex(iface);
  sa.sll_halen = ETH_ALEN;
  memcpy(sa.sll_addr, macDest, 6);
  
  sendto(sockfd, buf, TRAMA_PAYLOAD + payloadLen + 4, 0, (struct sockaddr *)&sa, sizeof(sa));
  printf("→ Reenviado [%s] a %s (%02x:%02x:%02x:%02x:%02x:%02x)\n", iface, destNombre,
         macDest[0], macDest[1], macDest[2], macDest[3], macDest[4], macDest[5]);
}

void enviarRespuesta(int sockfd, struct ifreq *sir, char *tramaRx) {
  byte buf[BUF_SIZ] = {0};
  struct ether_header *h = (struct ether_header *)buf;
  struct sockaddr_ll sa = {0};
  char payload[64];
  
  memcpy(h->ether_dhost, tramaRx + TRAMA_SOURCE, 6);
  memcpy(h->ether_shost, sir->ifr_hwaddr.sa_data, 6);
  h->ether_type = htons(ETHER_TYPE);
  
  sprintf(payload, "R%02x:%02x:%02x:%02x:%02x:%02x",
          (byte)sir->ifr_hwaddr.sa_data[0], (byte)sir->ifr_hwaddr.sa_data[1],
          (byte)sir->ifr_hwaddr.sa_data[2], (byte)sir->ifr_hwaddr.sa_data[3],
          (byte)sir->ifr_hwaddr.sa_data[4], (byte)sir->ifr_hwaddr.sa_data[5]);
  strcpy((char *)(buf + TRAMA_PAYLOAD), payload);
  
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETHER_TYPE);
  sa.sll_ifindex = if_nametoindex(sir->ifr_name);
  sa.sll_halen = ETH_ALEN;
  memcpy(sa.sll_addr, h->ether_dhost, 6);
  
  sendto(sockfd, buf, TRAMA_PAYLOAD + strlen(payload) + 4, 0, (struct sockaddr *)&sa, sizeof(sa));
  printf("→ ARP Reply enviado\n");
}

int main(int argc, char *argv[]) {
  int sockfd;
  byte buf[BUF_SIZ];
  struct sockaddr sa;
  struct ifreq sir;
  socklen_t sa_len;
  char nombreLocal[64], destNombre[64];
  char *p;
  int j;

  if (argc != 2) {
    printf("Uso: recv_eth INTERFACE\n");
    return 1;
  }

  gethostname(nombreLocal, sizeof(nombreLocal));
  printf("Host: %s (Gateway)\n", nombreLocal);

  if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket");
    return -1;
  }

  obtenerMAC(sockfd, argv[1], &sir);
  printf("Escuchando en %s - MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", argv[1],
         (byte)sir.ifr_hwaddr.sa_data[0], (byte)sir.ifr_hwaddr.sa_data[1],
         (byte)sir.ifr_hwaddr.sa_data[2], (byte)sir.ifr_hwaddr.sa_data[3],
         (byte)sir.ifr_hwaddr.sa_data[4], (byte)sir.ifr_hwaddr.sa_data[5]);

  while (1) {
    sa_len = sizeof(sa);
    if (recvfrom(sockfd, buf, BUF_SIZ, 0, &sa, &sa_len) < 0) continue;
    if (!iLaTramaEsParaMi(buf, &sir) && !esBroadcast(buf)) continue;

    p = (char *)(buf + TRAMA_PAYLOAD);
    switch (p[0]) {
      case 'Q':
        printf("ARP Query: %s\n", p + 1);
        if (strcmp(p + 1, nombreLocal) == 0) enviarRespuesta(sockfd, &sir, buf);
        break;
      case 'R':
        printf("ARP Reply: %s\n", p + 1);
        break;
      case 'D':
      /* Extrae el destino final del payload*/
        for (j = 0; p[2 + j] && p[2 + j] != '|' && j < 63; j++)
          destNombre[j] = p[2 + j];
        destNombre[j] = '\0';
        printf("\n[TRAMA] De red %c para %s (Red %c)\n", argv[1][3], destNombre, p[1]);
        printf("Mensaje: %s\n", p + 3 + j);
        
        if (strcmp(destNombre, nombreLocal) == 0) {
          printf("✓ Mensaje para mí\n");
        } else {
          reenviarTrama(sockfd, buf, destNombre, p[1]);
        }
        break;
    }
  }
  close(sockfd);
  return 0;
}