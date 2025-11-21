#include "eth.h"
#include "sys/time.h"
#define GATEWAY "pc3"

const byte BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

typedef struct { char nombre[64]; char red; } HostInfo;

HostInfo tablaRutas[] = {
  {"pc1", 'A'}, {"pc2", 'A'}, {"pc3", 'A'},
  {"pc3", 'B'}, {"pc4", 'B'}, {"pc5", 'B'}, {"", ' '}
};

char obtenerRed(char *nombre) {
  for (int i = 0; tablaRutas[i].nombre[0]; i++)
    if (strcmp(tablaRutas[i].nombre, nombre) == 0) return tablaRutas[i].red;
  return 'X';
}

void enviarConsulta(int sockfd, struct ifreq *sir, int idx, char *nombre) {
  byte buf[BUF_SIZ] = {0};
  struct ether_header *h = (struct ether_header *)buf;
  struct sockaddr_ll sa = {0};

  for (int i = 0; i < 6; i++)
    h->ether_shost[i] = (unsigned char)sir->ifr_hwaddr.sa_data[i];
  for (int i = 0; i < 6; i++)
    h->ether_dhost[i] = 0xff;
  h->ether_type = htons(ETHER_TYPE);
  sprintf((char *)(buf + TRAMA_PAYLOAD), "Q%s", nombre);

  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETHER_TYPE);
  sa.sll_ifindex = idx;
  sa.sll_halen = ETH_ALEN;
  for (int i = 0; i < 6; i++)
    sa.sll_addr[i] = 0xff;

  sendto(sockfd, buf, TRAMA_PAYLOAD + strlen(nombre) + 5, 0, (struct sockaddr *)&sa, sizeof(sa));
  printf("→ ARP Query: %s\n", nombre);
}

int esperarRespuesta(int sockfd, char *macDest) {
  byte buf[BUF_SIZ];
  struct sockaddr sa;
  socklen_t len = sizeof(sa);
  struct timeval tv = {5, 0};

  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  while (recvfrom(sockfd, buf, BUF_SIZ, 0, &sa, &len) > 0) {
    if (buf[TRAMA_PAYLOAD] == 'R') {
      strcpy(macDest, (char *)(buf + TRAMA_PAYLOAD + 1));
      printf("← ARP Reply: %s\n", macDest);
      return 1;
    }
  }
  return 0;
}

void parseMac(byte *dest, char *src) {
  unsigned int v[6];
  sscanf(src, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
  for (int i = 0; i < 6; i++) dest[i] = v[i];
}

int main(int argc, char *argv[]) {
  int sockfd, idx;
  struct ifreq sir;
  byte buf[BUF_SIZ], mac[6];
  struct ether_header *h = (struct ether_header *)buf;
  struct sockaddr_ll sa;
  char macTxt[32], msg[128], nombreLocal[64];
  char redLocal, redDest, *arpTarget;

  if (argc != 3) {
    printf("Uso: send_eth INTERFACE DESTINO\n");
    return 1;
  }

  gethostname(nombreLocal, sizeof(nombreLocal));
  redLocal = obtenerRed(nombreLocal);
  redDest = obtenerRed(argv[2]);

  if (redLocal == 'X') {
    printf("Error: host local no está en tabla\n");
    return 1;
  }
  if (redDest == 'X') {
    printf("Error: destino %s no está en tabla\n", argv[2]);
    return 1;
  }

  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    perror("socket");
    return 1;
  }

  memset(&sir, 0, sizeof(sir));
  strncpy(sir.ifr_name, argv[1], IFNAMSIZ - 1);
  ioctl(sockfd, SIOCGIFINDEX, &sir);
  idx = sir.ifr_ifindex;
  ioctl(sockfd, SIOCGIFHWADDR, &sir);

  printf("Interfaz %s MAC %02x:%02x:%02x:%02x:%02x:%02x\n", argv[1],
         (byte)sir.ifr_hwaddr.sa_data[0], (byte)sir.ifr_hwaddr.sa_data[1],
         (byte)sir.ifr_hwaddr.sa_data[2], (byte)sir.ifr_hwaddr.sa_data[3],
         (byte)sir.ifr_hwaddr.sa_data[4], (byte)sir.ifr_hwaddr.sa_data[5]);

  /* Comparamos redes con las tablas*/
  arpTarget = (redLocal == redDest) ? argv[2] : GATEWAY;
  printf("%s en %s red. ARP → %s\n", argv[2], (redLocal == redDest) ? "misma" : "otra", arpTarget);

  enviarConsulta(sockfd, &sir, idx, arpTarget);
  if (!esperarRespuesta(sockfd, macTxt)) {
    printf("Sin respuesta de %s\n", arpTarget);
    close(sockfd);
    return 1;
  }

  parseMac(mac, macTxt);
  memset(buf, 0, BUF_SIZ);
  for (int i = 0; i < 6; i++)
    h->ether_shost[i] = (unsigned char)sir.ifr_hwaddr.sa_data[i];
  for (int i = 0; i < 6; i++)
    h->ether_dhost[i] = mac[i];
  h->ether_type = htons(ETHER_TYPE);

  /* Red, la pc y el msj*/
  sprintf(msg, "D%c%s|Hola desde %s!", redDest, argv[2], nombreLocal);
  strcpy((char *)(buf + TRAMA_PAYLOAD), msg);

  memset(&sa, 0, sizeof(sa));
  sa.sll_family = AF_PACKET;
  sa.sll_protocol = htons(ETHER_TYPE);
  sa.sll_ifindex = idx;
  sa.sll_halen = ETH_ALEN;
  for (int i = 0; i < 6; i++)
    sa.sll_addr[i] = mac[i];

  sendto(sockfd, buf, TRAMA_PAYLOAD + strlen(msg) + 4, 0, (struct sockaddr *)&sa, sizeof(sa));
  printf("→ Enviado a %s (%s)\n", argv[2], macTxt);

  close(sockfd);
  return 0;
}