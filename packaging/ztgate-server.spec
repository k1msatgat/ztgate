# packaging/build.sh rpm 이 @VERSION@ 과 @STAGE@ 를 채운다. 파일은 packaging/stage.sh 가 놓은 그대로다.
Name:           ztgate-server
Version:        @VERSION@
Release:        1
Summary:        ztgate ZTNA server
License:        Proprietary
URL:            https://github.com/k1msatgat/ztgate
Requires:       openssl-libs >= 3.0, iproute, python3
Recommends:     nftables, nodejs
# 미리 빌드한 실행 파일을 담는다. 하드닝 플래그는 Makefile 이 넣고 디버그 정보는 stage.sh 가 뗀다.
%global debug_package %{nil}
%global __strip /bin/true
%global _build_id_links none
# ztgate_ctl 의 #!/usr/bin/node 가 node 를 필수로 끌어오지 않게 한다 (위의 Recommends 로 둔다).
%global __requires_exclude ^/usr/bin/node$

%description
Device-authenticated, posture-checked tunnel server with per-destination ACL,
user login (OIDC tokens), app connectors and an audit log.

%install
cp -a @STAGE@/. %{buildroot}/

%post
/opt/ztgate/libexec/postinst.sh

%preun
# 지울 때만 (업그레이드는 $1 = 1). /etc/ztgate 는 남긴다.
if [ "$1" = 0 ] && command -v systemctl > /dev/null 2>&1; then
	systemctl disable --now ztgate.service ztgate-exporter.service ztgate-console.service ztgate-jwks.timer 2>/dev/null || true
fi

%files
/opt/ztgate
/usr/sbin/ztgate_ctl
/usr/bin/ztgate
/usr/lib/systemd/system/ztgate.service
/usr/lib/systemd/system/ztgate-exporter.service
/usr/lib/systemd/system/ztgate-console.service
/usr/lib/systemd/system/ztgate-jwks.service
/usr/lib/systemd/system/ztgate-jwks.timer
