#!/bin/bash

# If no env var for FTP_USER has been specified, use 'admin':
if [ "$FTP_USER" = "**String**" ]; then
    export FTP_USER='admin'
fi

# If no env var has been specified, generate a random password for FTP_USER:
if [ "$FTP_PASS" = "**Random**" ]; then
    export FTP_PASS=$(cat /dev/urandom | tr -dc A-Z-a-z-0-9 | head -c${1:-16})
fi

# Create home dir and update rspy user db:
mkdir -p "/app/vsftpd/users/${FTP_USER}"
if [ ! -e "/app/vsftpd/users/${FTP_USER}/NOMINAL" ]; then
    mv /app/vsftpd/NOMINAL "/app/vsftpd/users/${FTP_USER}/"
fi
chown -R vsftpduser:vsftpduser "/app/vsftpd/users/${FTP_USER}"
chmod 755 "/app/vsftpd/users/${FTP_USER}"

echo -e "${FTP_USER}\n${FTP_PASS}" > /app/vsftpd/virtual_users.txt
db5.3_load -T -t hash -f /app/vsftpd/virtual_users.txt /app/vsftpd/virtual_users.db

# Set passive mode parameters:
if [ "$PASV_ADDRESS" = "**IPv4**" ]; then
    #export PASV_ADDRESS=$(/sbin/ip route|awk '/default/ { print $3 }')
    export PASV_ADDRESS=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
fi

CONFIG_TMP="/tmp/vsftpd.conf"
CONFIG_FINAL="/app/vsftpd/vsftpd.conf"

cp "$CONFIG_FINAL" "${CONFIG_TMP}"

# Append dynamic settings
echo "pasv_address=${PASV_ADDRESS}" >> "${CONFIG_TMP}"
echo "pasv_max_port=${PASV_MAX_PORT}" >> "${CONFIG_TMP}"
echo "pasv_min_port=${PASV_MIN_PORT}" >> "${CONFIG_TMP}"
echo "pasv_addr_resolve=${PASV_ADDR_RESOLVE}" >> "${CONFIG_TMP}"
echo "pasv_enable=${PASV_ENABLE}" >> "${CONFIG_TMP}"
echo "file_open_mode=${FILE_OPEN_MODE}" >> "${CONFIG_TMP}"
echo "local_umask=${LOCAL_UMASK}" >> "${CONFIG_TMP}"
echo "xferlog_std_format=${XFERLOG_STD_FORMAT}" >> "${CONFIG_TMP}"
echo "log_ftp_protocol=${LOG_FTP_PROTOCOL}" >> "${CONFIG_TMP}"

echo "pasv_promiscuous=${PASV_PROMISCUOUS}" >> "${CONFIG_TMP}"
echo "port_promiscuous=${PORT_PROMISCUOUS}" >> "${CONFIG_TMP}"

if [ "${SSL_ENABLE}" = "YES" ]; then

    if [ "${SSL_GENERATE}" = "YES" ]; then

cat <<EOF > /app/vsftpd/cert/san.cnf
        [ req ]
        default_bits       = 2048
        prompt             = no
        default_md         = sha256
        req_extensions     = req_ext
        distinguished_name = dn

        [ dn ]
        C  = FR
        O  = RSPY
        CN = ${HOSTNAME}

        [ req_ext ]
        subjectAltName = @alt_names

        [ alt_names ]
        DNS.1 = ${HOSTNAME}
        IP.1  = ${PASV_ADDRESS}
EOF

        echo "Generate CA Key and Certificate (used to sign both server and client certs)"
        openssl genrsa -out /app/vsftpd/cert/ca.key 4096 > /dev/null 2>&1
        openssl req -x509 -new -nodes -key /app/vsftpd/cert/ca.key -sha256 -days 3650 -out /app/vsftpd/cert/${CA_CERT} -subj "/C=FR/O=RSPY/CN=RSPY" > /dev/null 2>&1

        echo "Generate Server Key and Certificate"
        openssl genrsa -out /app/vsftpd/cert/${SRV_KEY} 2048 > /dev/null 2>&1
        openssl req -new -key /app/vsftpd/cert/${SRV_KEY} -out /app/vsftpd/cert/server.csr -config /app/vsftpd/cert/san.cnf > /dev/null 2>&1

        echo "Generate Client Key and Certificate"
        openssl genrsa -out /app/vsftpd/cert/client.key 2048 > /dev/null 2>&1
        openssl req -new -key /app/vsftpd/cert/client.key -out /app/vsftpd/cert/client.csr -subj "/C=FR/O=RSPY/CN=ftpclient" > /dev/null 2>&1
        openssl x509 -req -in /app/vsftpd/cert/client.csr -CA /app/vsftpd/cert/${CA_CERT} -CAkey /app/vsftpd/cert/ca.key -CAcreateserial -out /app/vsftpd/cert/client.crt -days 365 -sha256 > /dev/null 2>&1
        openssl x509 -req -in /app/vsftpd/cert/server.csr -CA /app/vsftpd/cert/${CA_CERT} -CAkey /app/vsftpd/cert/ca.key -CAcreateserial -out /app/vsftpd/cert/${SRV_CERT} -days 365 -sha256 -extfile /app/vsftpd/cert/san.cnf -extensions req_ext > /dev/null 2>&1
    fi

    echo "ssl_enable=YES" >> "${CONFIG_TMP}"
    echo "allow_anon_ssl=NO" >> "${CONFIG_TMP}"
    echo "force_local_data_ssl=${FORCE_LOCAL_DATA_SSL}" >> "${CONFIG_TMP}"
    echo "force_local_logins_ssl=YES" >> "${CONFIG_TMP}"
    echo "ssl_tlsv1=YES" >> "${CONFIG_TMP}"
    echo "ssl_sslv2=NO" >> "${CONFIG_TMP}"
    echo "ssl_sslv3=NO" >> "${CONFIG_TMP}"
    echo "require_ssl_reuse=${REQUIRE_SSL_REUSE}" >> "${CONFIG_TMP}"
    echo "ssl_ciphers=HIGH" >> "${CONFIG_TMP}"
    echo "rsa_cert_file=/app/vsftpd/cert/${SRV_CERT}" >> "${CONFIG_TMP}"
    echo "rsa_private_key_file=/app/vsftpd/cert/${SRV_KEY}" >> "${CONFIG_TMP}"
    echo "ca_certs_file=/app/vsftpd/cert/${CA_CERT}" >> "${CONFIG_TMP}"
fi

# Move and fix ownership
mv "${CONFIG_TMP}" "${CONFIG_FINAL}"
chown root:root "${CONFIG_FINAL}"
chmod 644 "${CONFIG_FINAL}"

# stdout server info:
echo "FTP User: ${FTP_USER}"
echo "FTP Password: ${FTP_PASS}"
touch /var/log/vsftpd.log

# Run vsftpd:
echo "Starting vsftpd..."
/usr/sbin/vsftpd /app/vsftpd/vsftpd.conf &
tail -F /var/log/vsftpd.log
