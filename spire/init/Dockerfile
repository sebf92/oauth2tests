FROM ghcr.io/spiffe/spire-server:1.10.0 AS spire
FROM alpine:3.19
# SPIRE server binary is statically compiled — no shared libs needed
COPY --from=spire /opt/spire/bin/spire-server /opt/spire/bin/spire-server
# setup.sh is mounted at runtime via a bind mount
ENTRYPOINT ["/bin/sh"]
