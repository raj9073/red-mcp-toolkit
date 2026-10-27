# Vulnerable Samba Active Directory DC for the redlab — AUTHORIZED LAB USE ONLY.
# Domain: REDLAB.LOCAL  |  DC: dc1  |  intentionally weak (roastable accounts, weak policy)
FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
        samba samba-ad-provision samba-dsdb-modules samba-vfs-modules \
        smbclient krb5-user winbind libnss-winbind ldb-tools \
        python3-samba dnsutils procps iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# DNS, Kerberos, RPC, LDAP(S), SMB, kpasswd, global catalog
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 135/tcp 139/tcp 389/tcp 389/udp 445/tcp 464/tcp 636/tcp 3268/tcp 3269/tcp

ENTRYPOINT ["/entrypoint.sh"]
