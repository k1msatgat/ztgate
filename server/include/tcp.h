#ifndef TCP_H
#define TCP_H

/* TCP 로 오는 세션 (vpn_server -t <port>). UDP 가 막힌 네트워크(호텔, 카페, 일부 회사망)에서도 붙게
 * 한다. 그런 곳도 443/tcp 는 대개 열려 있다.
 *
 * 스트림 위에 UDP 와 똑같은 패킷을 길이와 함께 싣는다:
 *
 *   len(2, 빅엔디언) | 패킷(len)          len 은 1..BUF_SIZE
 *
 * 핸드셰이크, 세션 키, 암호, 재전송 창은 그대로다. 서버는 TCP 연결을 "출발지 주소의 한 종류"로
 * 본다 — 답할 곳(peer->outer)을 sockaddr_in 으로 들고 다니는 코드를 그대로 두려고, TCP 연결이면
 * sin_family 를 AF_UNSPEC 로 표시하고 sin_port 에 연결 번호, sin_zero 에 그 자리의 세대를 적는다
 * (sin_addr 은 상대의 실제 주소). 보낼 때는 net_send 가 둘을 가른다.
 *
 * UDP 주소의 sin_zero 앞 4바이트에는 그 패킷이 도착한 이 서버의 주소를 적는다 (net_recv). 답은 그
 * 주소에서 나간다. 0.0.0.0 에 묶인 소켓은 출발지를 커널이 경로로 고르므로, 주소가 여럿인 서버(두 번째
 * 주소, 이중화의 떠다니는 VIP)는 요청을 받은 주소가 아닌 곳에서 답하게 되고 클라이언트(서버에
 * connect 한 UDP 소켓)는 그 답을 버린다. 같은 상대라도 다른 주소로 오면 다른 끝점이다.
 *
 * TCP 위에 TCP(클라이언트의 연결)를 실으면 손실이 생길 때 두 겹의 재전송이 서로를 늦춘다 (TCP
 * meltdown). 그래서 UDP 가 될 때는 UDP 를 쓰고, 이것은 대체 수단이다. 서버가 못 보낸 것이 쌓이면
 * (상대가 느리다) 그 위로는 버린다 — 터널 안의 패킷은 버려져도 되는 것이다.
 *
 * 읽기와 연결 받기는 워커 0 만 한다. 쓰기는 어느 워커든 하고 연결마다 잠근다. */

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define TCP_CONN_MAX	4096
#define TCP_WBUF	(64 * 1024)	/* 연결마다 못 보내고 쌓아 두는 양. 넘으면 버린다 */
#define TCP_IDLE_SEC	120		/* 이만큼 아무것도 오지 않으면 닫는다 (keepalive 는 10초) */

/* 패킷 하나를 받았을 때 부를 것. udp_in 과 같은 모양이다. */
typedef void (*tcp_packet_fn)(uint8_t *packet, size_t cap, int n,
		const struct sockaddr_in *from, socklen_t fromlen);

/* port 에서 듣는다. 성공하면 듣는 fd. epfd 에는 부르는 쪽이 건다. */
int tcp_listen(uint16_t port);

/* 듣는 fd 에 이벤트가 왔다. 연결을 받아 epfd 에 건다. */
void tcp_accept(int epfd, int lfd);

/* fd 가 TCP 연결이면 그 이벤트를 처리하고 1 (받은 패킷마다 on_packet). 아니면 0. */
int tcp_event(int epfd, int fd, uint32_t events, tcp_packet_fn on_packet);

/* 1초에 한 번. 오래 조용한 연결을 닫는다. */
void tcp_tick(int epfd);

/* to 가 TCP 연결이면 길이를 붙여 그 연결로, 아니면 UDP 소켓 sock 으로 보낸다. 성공 0. */
int net_send(int sock, const void *buf, size_t len, const struct sockaddr_in *to, socklen_t tolen);

/* UDP 소켓이 받은 패킷의 도착 주소를 알려 주게 한다 (IP_PKTINFO). bind 전후 아무 때나. */
int net_udp_init(int sock);

/* recvfrom 과 같고, src 의 sin_zero 에 도착 주소를 적는다 (위의 설명). */
ssize_t net_recv(int sock, void *buf, size_t cap, struct sockaddr_in *src, socklen_t *srclen);

/* 로그와 상태에 쓸 "주소:포트" 또는 "주소 (tcp)". dst 는 INET_ADDRSTRLEN + 16 이상. */
const char *endpoint_str(const struct sockaddr_in *ep, char *dst, size_t cap);

int tcp_conn_count(void);

#endif
