FROM debian:bullseye-slim

COPY ./layer-cleanup.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/layer-cleanup.sh

RUN apt-get update && apt-get install -y vsftpd openssl iproute2 db5.3-util coreutils && layer-cleanup.sh

ENV FTP_USER=**String**
ENV FTP_PASS=**Random**
ENV PASV_ADDRESS=**IPv4**
ENV PASV_ADDR_RESOLVE=NO
ENV PASV_ENABLE=YES
ENV PASV_MIN_PORT=21100
ENV PASV_MAX_PORT=21110
ENV XFERLOG_STD_FORMAT=NO
ENV LOG_FTP_PROTOCOL=NO
ENV FILE_OPEN_MODE=0666
ENV LOCAL_UMASK=077
ENV REVERSE_LOOKUP_ENABLE=YES
ENV PASV_PROMISCUOUS=NO
ENV PORT_PROMISCUOUS=NO
ENV SSL_ENABLE=YES
ENV SSL_GENERATE=YES
ENV FORCE_LOCAL_DATA_SSL=NO
ENV REQUIRE_SSL_REUSE=NO
ENV SRV_CERT=server.crt
ENV SRV_KEY=server.key
ENV CA_CERT=ca.crt

RUN mkdir -p /app/vsftpd/cert/

WORKDIR /app/vsftpd/cert/

RUN useradd -d /app/vsftpd -s /bin/false vsftpduser

COPY vsftpd.conf /app/vsftpd/vsftpd.conf
COPY vsftpd_virtual /etc/pam.d/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY data/NOMINAL /app/vsftpd/NOMINAL

RUN chmod +x /usr/local/bin/entrypoint.sh

RUN mkdir -p /app/vsftpd/users
RUN chown -R vsftpduser:vsftpduser /app/vsftpd/users
RUN mkdir -p /var/run/vsftpd/empty
RUN chmod 755 /var/run/vsftpd/empty

# Remove custom scripts
RUN rm -f /usr/local/bin/layer-cleanup.sh /usr/local/bin/restore-apt.sh

EXPOSE 21 21100-21110

ENTRYPOINT ["entrypoint.sh"]

WORKDIR /app/vsftpd