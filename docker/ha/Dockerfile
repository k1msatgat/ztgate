# docker/ha.sh 의 서버 이미지: ztgate 이미지에 ssh, rsync, sudo 와 tools/sync/ztgate-sync 를 더한다.
# Debian 12 의 rsync 는 프로토콜 32 다. 개발 장비와 Rocky 9 의 rsync(31)에서는 나지 않는 실패가 여기서 난다.
FROM ztgate
RUN apt-get update \
	&& apt-get install -y --no-install-recommends openssh-server openssh-client rsync sudo \
	&& rm -rf /var/lib/apt/lists/*
COPY ztgate-sync /usr/local/sbin/ztgate-sync
