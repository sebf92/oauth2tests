# One-shot container that generates the CA + agent certificate used by UC3a.
# Alpine is enough — openssl is the only requirement.
FROM alpine:3.20

RUN apk add --no-cache openssl

COPY setup.sh /opt/cert-init/setup.sh
RUN chmod +x /opt/cert-init/setup.sh

# The generated PKI lands in /pki, which is bind-mounted to a named volume
# shared with the agent-cert container (read-only on that side).
VOLUME ["/pki"]

ENTRYPOINT ["/opt/cert-init/setup.sh"]
