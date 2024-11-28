FROM debian:bullseye

RUN apt update && apt install -y vsftpd net-tools

COPY vsftpd.conf /etc/vsftpd.conf

RUN mkdir -p /var/run/vsftpd/empty

RUN useradd -m -s /bin/bash ftpuser && \
    echo "ftpuser:password" | chpasswd && \
    mkdir -p /home/ftpuser/ftp && \
    chmod 750 /home/ftpuser/ftp && \
    chown ftpuser:ftpuser /home/ftpuser/ftp

EXPOSE 20 2121

COPY run.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

ENTRYPOINT ["/usr/local/bin/start.sh"]
