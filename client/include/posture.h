#ifndef POSTURE_H
#define POSTURE_H

/* 단말 보안 상태(posture) 수집 — Linux.
 *
 * 읽는 것까지만 하고 판단하지 않는다. 무엇이 통과인지는 서버의 기기 정책이 정한다.
 * 와이어 형식(posture_report_t)은 Windows 클라이언트와 같고, 칸마다 Linux 에서 뜻이
 * 있는 값을 넣는다. 억지로 Windows 항목을 흉내 내지 않는다.
 *
 *   os_build   커널 버전. 커널 헤더의 LINUX_VERSION_CODE 와 같은 모양이다:
 *              (major << 16) | (minor << 8) | min(patch, 255).  5.14.0 -> 331264
 *              서버 정책은 그대로 min-build=N 으로 건다.
 *
 *   firewall   nftables 에 인바운드를 막는 설정이 있는가.
 *                ON       input 훅에 걸린 체인 중 policy drop 인 것이 있다, 또는
 *                         firewalld 의 표(table inet firewalld)가 있다
 *                OFF      규칙셋은 읽었는데 둘 다 없다
 *                UNKNOWN  nft 가 없거나 읽지 못했다
 *              firewalld 의 input 체인은 policy accept 이고 마지막 규칙이 reject 라서
 *              policy 만 보면 꺼진 것으로 읽힌다. 그래서 firewalld 의 표를 따로 본다.
 *              iptables-legacy 로만 건 규칙은 보지 못한다 (nft 에 나타나지 않는다).
 *
 *   antivirus  Linux 에는 대응하는 OS 기본 장치가 없어 늘 UNKNOWN 이다. Linux 기기의
 *              정책에 antivirus=on 을 걸면 그 기기는 늘 거절된다.
 *
 *   disk       / 가 놓인 블록 장치가 dm-crypt(LUKS) 위에 있는가. / 의 장치에서 시작해
 *              /sys/dev/block 의 slaves 를 따라 내려가며 dm/uuid 가 "CRYPT-" 로 시작하는
 *              장치를 찾는다 (LVM 위의 LUKS, LUKS 위의 LVM 모두).
 *                ON       찾았다
 *                OFF      끝까지 내려갔는데 없다
 *                UNKNOWN  / 의 장치가 블록 장치가 아니다 (btrfs 의 부속 볼륨, overlay, 네트워크
 *                         파일 시스템 등) 또는 sysfs 를 읽지 못했다
 *
 * 0 이 UNKNOWN 이라 못 읽은 항목은 통과로 읽히지 않는다. */

#include "proto.h"

void posture_collect(posture_report_t *out);

/* nft 의 절대 경로. 없으면 NULL. 셸이나 PATH 를 거치지 않으려고 정해 둔 곳만 본다
 * (커넥터도 쓴다). */
const char *nft_path(void);

#endif
