FROM ubuntu:latest

ARG TARGET_IP
ENV TARGET_IP=${TARGET_IP}

RUN apt update -y
RUN apt install arping net-tools tcpdump iputils-ping ftp -y
RUN mkdir -p /var/run/vsftpd/empty

COPY run.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

ENTRYPOINT ["/usr/local/bin/start.sh"]
