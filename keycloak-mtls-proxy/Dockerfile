# UC2-Hardened mTLS proxy in front of Keycloak.
#
# Terminates mTLS using a SPIRE-issued X.509-SVID for the server cert and
# validates the client cert against the SPIRE trust-domain bundle.
# Forwards the verified client cert PEM to Keycloak so its x509cert-lookup
# nginx provider can map it to a client.
#
# The proxy is itself a SPIFFE workload (UID 1002 → spiffe://demo.local/keycloak-mtls-proxy)
# so it fetches its own SVID + the trust bundle from the SPIRE Workload API
# at startup.  No static PKI material is baked into the image.

# Stage 1 — copy the spire-agent CLI out of the official image.  The CLI is
# what we use to call the Workload API at startup (simpler than embedding the
# Python/Go SDK in the proxy image).
FROM ghcr.io/spiffe/spire-agent:1.10.0 AS spire-cli

FROM nginx:1.27-alpine

# openssl: read cert metadata for the startup log.
# bash:    safer scripting than POSIX sh for the entrypoint.
# su-exec: drop to UID 1002 when calling the SPIRE Workload API (so SPIRE
#          attests the call as keycloak-mtls-proxy, not as the root entrypoint).
RUN apk add --no-cache openssl bash su-exec

COPY --from=spire-cli /opt/spire/bin/spire-agent /usr/local/bin/spire-agent

# UID 1002 — must match the SPIRE workload entry's unix:uid:1002 selector
# (see spire/setup.sh).  Without this, SPIRE refuses to issue a SVID.
RUN adduser -D -u 1002 -s /bin/sh spireworker

COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8443

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
