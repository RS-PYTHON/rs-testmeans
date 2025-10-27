FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y vsftpd openssl && rm -rf /var/lib/apt/lists/*

ENV FTP_USER=ftpuser
ENV FTP_PASS=ftppass

RUN useradd -m -d /home/$FTP_USER -s /bin/bash $FTP_USER && \
    echo "$FTP_USER:$FTP_PASS" | chpasswd

RUN mkdir -p /etc/ssl/private && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/vsftpd.key \
        -out /etc/ssl/private/vsftpd.pem \
        -subj "/CN=localhost"

RUN mkdir -p /var/run/vsftpd/empty && chmod 755 /var/run/vsftpd/empty

COPY vsftpd.conf /etc/vsftpd.conf

EXPOSE 21 21100-21110

#  Keep vsftpd running forever
CMD /usr/sbin/vsftpd /etc/vsftpd.conf & tail -f /dev/null
