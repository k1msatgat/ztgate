#include "framework.h"
#include "PacketText.h"

namespace pkt {

CString TimeText(ULONGLONG t_ms)
{
	CString s;

	s.Format(_T("%llu:%02llu.%03llu"), t_ms / 60000, (t_ms / 1000) % 60, t_ms % 1000);

	return s;
}

CString DirName(const tunnel_packet_t &p)
{
	return (p.dir == TUNNEL_DIR_TX) ? _T("\x2191 송신") : _T("\x2193 수신");
}

CString TypeName(const tunnel_packet_t &p)
{
	switch (p.msg_type) {
	case MSG_TYPE_REQ_HANDSHAKE:	return _T("REQ_HS");
	case MSG_TYPE_RES_HANDSHAKE:	return _T("RES_HS");
	case MSG_TYPE_DATA:		return _T("DATA");
	case MSG_TYPE_KEEPALIVE:	return _T("KEEPALIVE");
	case MSG_TYPE_CHALLENGE:	return _T("CHALLENGE");
	case MSG_TYPE_AUTH:		return _T("AUTH");
	case MSG_TYPE_DENY:		return _T("DENY");
	case MSG_TYPE_LOGIN:		return _T("LOGIN");
	default:			return _T("-");
	}
}

CString PostureStateName(int state)
{
	switch (state) {
	case POSTURE_STATE_ON:		return _T("켜짐");
	case POSTURE_STATE_OFF:		return _T("꺼짐");
	default:			return _T("확인 불가");
	}
}

CString DenyReasonName(int reason)
{
	switch (reason) {
	case DENY_UNKNOWN_DEVICE:	return _T("등록되지 않은 기기");
	case DENY_BAD_AUTH:		return _T("인증 실패");
	case DENY_TUN_IP:		return _T("이 기기에 배정되지 않은 터널 IP");
	case DENY_POSTURE:		return _T("포스처가 정책에 못 미침");
	default:			return _T("알 수 없는 사유");
	}
}

CString PostureText(const posture_report_t &r)
{
	CString s;

	s.Format(_T("빌드 %u  방화벽 %s  백신 %s"), r.os_build,
			(LPCTSTR)PostureStateName(r.firewall), (LPCTSTR)PostureStateName(r.antivirus));

	return s;
}

CString VerdictName(int verdict)
{
	switch (verdict) {
	case TUNNEL_PASS:		return _T("전달");
	case TUNNEL_DROP_NON_IPV4:	return _T("IPv4 아님");
	case TUNNEL_DROP_NON_UNICAST:	return _T("비유니캐스트");
	case TUNNEL_DROP_TOO_LONG:	return _T("길이 초과");
	case TUNNEL_DROP_NOT_SERVER:	return _T("서버 아닌 출발지");
	case TUNNEL_DROP_BAD_HEADER:	return _T("헤더 불량");
	case TUNNEL_DROP_WRONG_SESSION:	return _T("세션 불일치");
	case TUNNEL_DROP_UNKNOWN_TYPE:	return _T("알 수 없는 타입");
	case TUNNEL_DROP_IO_ERROR:	return _T("전달 실패");
	case TUNNEL_DROP_DENIED:	return _T("접근 거부");
	case TUNNEL_DROP_BAD_TAG:	return _T("위조 / 손상");
	case TUNNEL_DROP_REPLAY:	return _T("재전송");
	default:			return _T("?");
	}
}

CString ProtoName(const tunnel_packet_t &p)
{
	switch (p.proto) {
	case 1:		return _T("ICMP");
	case 2:		return _T("IGMP");
	case 6:		return _T("TCP");
	case 17:	return _T("UDP");
	default:	break;
	}

	CString s;
	s.Format(_T("%u"), (unsigned)p.proto);

	return s;
}

CString Summary(const tunnel_packet_t &p)
{
	/* 인증 메시지는 inner 패킷이 없다. 대신 실어 온 내용을 요약한다. */
	if (p.msg_type == MSG_TYPE_DENY && p.deny_reason != 0) {
		return _T("거부: ") + DenyReasonName(p.deny_reason);
	}
	if (p.has_posture) {
		return PostureText(p.posture);
	}

	if (!p.has_inner) {
		return _T("");
	}

	TCHAR src[64] = { 0 };
	TCHAR dst[64] = { 0 };
	InetNtopW(AF_INET, &p.inner_src, src, 64);
	InetNtopW(AF_INET, &p.inner_dst, dst, 64);

	CString s;
	s.Format(_T("%s \x2192 %s  %s"), src, dst, (LPCTSTR)ProtoName(p));

	if (p.has_l4) {
		CString t;
		if (p.proto == 1) {
			if (p.icmp_type == 8) {
				t = _T(" echo request");
			}
			else if (p.icmp_type == 0) {
				t = _T(" echo reply");
			}
			else {
				t.Format(_T(" type=%u"), (unsigned)p.icmp_type);
			}
		}
		else {
			t.Format(_T(" %u\x2192%u"), (unsigned)p.sport, (unsigned)p.dport);
		}
		s += t;
	}

	return s;
}

CString ColumnText(const tunnel_packet_t &p, int col)
{
	CString s;

	switch (col) {
	case COL_SEQ:
		s.Format(_T("%llu"), p.seq);
		return s;
	case COL_TIME:
		return TimeText(p.t_ms);
	case COL_DIR:
		return DirName(p);
	case COL_TYPE:
		return TypeName(p);
	case COL_SESSION:
		if (p.session_idx == 0) {
			return _T("-");
		}
		s.Format(_T("%08x"), p.session_idx);
		return s;
	case COL_COUNTER:
		if (!p.has_counter) {
			return _T("-");
		}
		s.Format(_T("%llu"), p.counter);
		return s;
	case COL_SUMMARY:
		return Summary(p);
	case COL_LENGTH:
		s.Format(_T("%u"), p.wire_len);
		return s;
	case COL_VERDICT:
		return VerdictName(p.verdict);
	default:
		return _T("");
	}
}

CString DetailText(const tunnel_packet_t &p)
{
	CString s;
	CString t;

	/* 우리가 설계한 16바이트를 필드별로 되짚는다. */
	if (p.msg_type != 0) {
		t.Format(_T("msg_header   version=%u  type=%u (%s)\r\n"),
				(unsigned)PROTOCOL_VERSION, (unsigned)p.msg_type,
				(LPCTSTR)TypeName(p));
		s += t;
		t.Format(_T("             session_idx=0x%08x\r\n"), p.session_idx);
		s += t;
	}
	else {
		s += _T("msg_header   (읽지 못함)\r\n");
	}

	if (p.has_counter) {
		t.Format(_T("data_header  counter=%llu\r\n"), p.counter);
		s += t;
	}

	if (p.has_posture) {
		t.Format(_T("posture      os_build=%u  firewall=%u (%s)  antivirus=%u (%s)\r\n"),
				p.posture.os_build,
				(unsigned)p.posture.firewall, (LPCTSTR)PostureStateName(p.posture.firewall),
				(unsigned)p.posture.antivirus, (LPCTSTR)PostureStateName(p.posture.antivirus));
		s += t;
		/* AUTH 의 포스처는 평문이고 기기 키의 mac 이 덮는다. KEEPALIVE 의 것은 세션 키로
		 * 감싸여 오가고 끝에 GCM tag 가 붙는다 (아래 16진수는 푼 모습). */
		if (p.msg_type == MSG_TYPE_AUTH) {
			s += _T("             (평문. 뒤의 32바이트는 기기 키로 만든 mac, HMAC-SHA256)\r\n");
		}
		else {
			s += _T("             (와이어에서는 세션 키로 암호화, 뒤에 GCM tag 16바이트)\r\n");
		}
	}

	if (p.msg_type == MSG_TYPE_DENY && p.deny_reason != 0) {
		t.Format(_T("deny         reason=%u (%s)\r\n"),
				(unsigned)p.deny_reason, (LPCTSTR)DenyReasonName(p.deny_reason));
		s += t;
	}

	if (p.has_inner) {
		TCHAR src[64] = { 0 };
		TCHAR dst[64] = { 0 };
		InetNtopW(AF_INET, &p.inner_src, src, 64);
		InetNtopW(AF_INET, &p.inner_dst, dst, 64);

		t.Format(_T("inner IPv4   %s -> %s  proto=%u (%s)  len=%u\r\n"),
				src, dst, (unsigned)p.proto, (LPCTSTR)ProtoName(p), p.inner_len);
		s += t;

		if (p.has_l4) {
			if (p.proto == 1) {
				LPCTSTR icmp = _T("");
				if (p.icmp_type == 8) {
					icmp = _T(" (echo request)");
				}
				else if (p.icmp_type == 0) {
					icmp = _T(" (echo reply)");
				}
				t.Format(_T("ICMP         type=%u%s  code=%u\r\n"),
						(unsigned)p.icmp_type, icmp, (unsigned)p.icmp_code);
			}
			else {
				t.Format(_T("%-12s sport=%u  dport=%u\r\n"),
						(LPCTSTR)ProtoName(p), (unsigned)p.sport, (unsigned)p.dport);
			}
			s += t;
		}
	}

	t.Format(_T("결과         %s  (와이어 %u 바이트)\r\n"),
			(LPCTSTR)VerdictName(p.verdict), p.wire_len);
	s += t;

	/* 세션 패킷의 덤프는 헤더 16바이트 뒤가 암호문이 아니라 감싸기 전 / 푼 뒤의 내용이다.
	 * 그렇다고 적지 않으면 "암호화가 안 된다"로 읽힌다. */
	if (p.has_counter) {
		s += _T("16진수       헤더 16바이트 뒤는 암호를 푼(보낼 때는 감싸기 전) 내용\r\n");
	}
	s += _T("\r\n");

	/* hex 덤프. 앞 TUNNEL_SNAP_LEN 바이트만 떠 두었다. */
	for (int off = 0; off < p.snap_len; off += 16) {
		CString hex;
		CString asc;

		for (int i = 0; i < 16; i++) {
			if (off + i < p.snap_len) {
				BYTE b = p.snap[off + i];
				t.Format(_T("%02x "), b);
				hex += t;
				asc += (b >= 0x20 && b < 0x7f) ? (TCHAR)b : _T('.');
			}
			else {
				hex += _T("   ");
			}
			if (i == 7) {
				hex += _T(" ");
			}
		}
		t.Format(_T("%04x  %s %s\r\n"), off, (LPCTSTR)hex, (LPCTSTR)asc);
		s += t;
	}

	return s;
}

} /* namespace pkt */
