#include "framework.h"
#include "PacketStore.h"

CPacketStore::CPacketStore()
	: m_dir(PKT_FILTER_ALL)
	, m_hideKa(false)
	, m_onlyDrops(false)
{
	ZeroMemory(&m_stats, sizeof(m_stats));
	m_all.reserve(PACKET_STORE_MAX);
}

/* 목록만 비운다. 집계는 남긴다 — 주 창의 "주고받은 데이터" 도 이 집계를 본다. */
void CPacketStore::Clear()
{
	m_all.clear();
	m_view.clear();
}

void CPacketStore::CountRehandshake()
{
	m_stats.rehandshakes++;
}

void CPacketStore::SetLost(ULONGLONG n)
{
	m_stats.lost = n;
}

void CPacketStore::Add(const tunnel_packet_t &p)
{
	/* 상한을 넘으면 앞에서 뭉치로 버린다. 한 건씩 버리면 매번 뷰를 다시 만들어야
	 * 하므로, 드물게 한 번 크게 버리고 그때만 다시 만든다. */
	if (m_all.size() >= PACKET_STORE_MAX) {
		m_all.erase(m_all.begin(), m_all.begin() + PACKET_STORE_TRIM);
		RebuildView();
	}

	m_all.push_back(p);

	/* 집계는 필터와 무관하게 전부 센다. 필터는 보기만 바꾼다. */
	if (p.verdict != TUNNEL_PASS) {
		if (p.verdict < TUNNEL_VERDICT_COUNT) {
			m_stats.drops[p.verdict]++;
		}
	}

	if (p.dir == TUNNEL_DIR_RX) {
		/* 폐기됐더라도 와이어로는 도착했으므로 수신으로 센다. */
		m_stats.rx_packets++;
		m_stats.rx_bytes += p.wire_len;
		if (p.msg_type == MSG_TYPE_KEEPALIVE && p.verdict == TUNNEL_PASS) {
			m_stats.ka_recv++;
		}
	}
	else if (p.verdict == TUNNEL_PASS) {
		/* 송신은 실제로 보낸 것만 센다. 폐기된 것은 소켓에 나가지 않았다. */
		m_stats.tx_packets++;
		m_stats.tx_bytes += p.wire_len;
		if (p.msg_type == MSG_TYPE_KEEPALIVE) {
			m_stats.ka_sent++;
		}
	}

	if (Match(p)) {
		m_view.push_back(static_cast<int>(m_all.size()) - 1);
	}
}

bool CPacketStore::Match(const tunnel_packet_t &p) const
{
	if (m_dir == PKT_FILTER_TX && p.dir != TUNNEL_DIR_TX) {
		return false;
	}
	if (m_dir == PKT_FILTER_RX && p.dir != TUNNEL_DIR_RX) {
		return false;
	}
	if (m_hideKa && p.msg_type == MSG_TYPE_KEEPALIVE) {
		return false;
	}
	if (m_onlyDrops && p.verdict == TUNNEL_PASS) {
		return false;
	}

	return true;
}

void CPacketStore::RebuildView()
{
	m_view.clear();
	m_view.reserve(m_all.size());

	for (size_t i = 0; i < m_all.size(); i++) {
		if (Match(m_all[i])) {
			m_view.push_back(static_cast<int>(i));
		}
	}
}

void CPacketStore::SetFilter(int dir, bool hideKeepalive, bool onlyDrops)
{
	m_dir = dir;
	m_hideKa = hideKeepalive;
	m_onlyDrops = onlyDrops;
	RebuildView();
}

int CPacketStore::ViewCount() const
{
	return static_cast<int>(m_view.size());
}

const tunnel_packet_t *CPacketStore::ViewAt(int i) const
{
	if (i < 0 || i >= static_cast<int>(m_view.size())) {
		return nullptr;
	}

	return &m_all[m_view[i]];
}

ULONGLONG CPacketStore::TotalDrops() const
{
	ULONGLONG n = 0;

	for (int i = 1; i < TUNNEL_VERDICT_COUNT; i++) {
		n += m_stats.drops[i];
	}

	return n;
}
