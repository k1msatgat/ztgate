# test/deploy_check.sh 와 packaging/migrate-to-package.sh 를 Rocky 9 (운영 서버와 같은 배포판) 에서 돌리는 장비.
# systemd 가 PID 1 이다 (배포기는 작업과 빌드를 systemd-run 의 유닛으로 돌린다). 배포기가 빌드에 쓰는 것과
# MCP 서버의 node 20 이 들어 있다. 저장소는 넣지 않는다 (시험이 git archive 로 넣는다).
#
#   docker build -t zt-deploy-rocky9 docker/deploy
#   docker run -d --name zt-deploy-rpm --privileged --tmpfs /run --tmpfs /run/lock zt-deploy-rocky9
FROM rockylinux:9
RUN dnf -y -q module enable nodejs:20 \
	&& dnf -y -q install systemd sudo git gcc make openssl-devel rpm-build nodejs npm python3 iproute nftables \
		procps-ng findutils diffutils hostname \
	&& dnf clean all \
	&& useradd -m zt \
	&& echo 'zt ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/zt
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
