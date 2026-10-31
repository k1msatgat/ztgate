# packaging/build.sh connector-rpm 이 @VERSION@, @RELEASE@, @STAGE@ 를 채운다. 파일은 packaging/connector-stage.sh 가 놓은 그대로다.
Name:           ztgate-connector
Version:        @VERSION@
Release:        @RELEASE@
Summary:        ztgate app connector
License:        Proprietary
URL:            https://github.com/k1msatgat/ztgate
Requires:       openssl-libs >= 3.0, nftables, bash
# 미리 빌드한 실행 파일을 담는다. 하드닝 플래그는 Makefile 이 넣고 디버그 정보는 connector-stage.sh 가 뗀다.
%global debug_package %{nil}
%global __strip /bin/true
%global _build_id_links none

%description
Runs inside a protected network and opens an outbound session to the ztgate
server, which relays traffic for that network to it. No inbound port is opened.

%install
cp -a @STAGE@/. %{buildroot}/

%post
/opt/ztgate-connector/libexec/postinst.sh

%preun
# 지울 때만 (업그레이드는 $1 = 1). 신원과 connector.env 는 남긴다.
if [ "$1" = 0 ] && command -v systemctl > /dev/null 2>&1; then
	systemctl disable --now ztgate-connector.service 2>/dev/null || true
fi

%files
/opt/ztgate-connector
/usr/sbin/ztgate-connector
/usr/lib/systemd/system/ztgate-connector.service
/usr/share/doc/ztgate-connector
