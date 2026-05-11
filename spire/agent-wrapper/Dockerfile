FROM ghcr.io/spiffe/spire-agent:1.10.0 AS spire
FROM alpine:3.19
# SPIRE agent binary is statically compiled — no shared libs needed
COPY --from=spire /opt/spire/bin/spire-agent /opt/spire/bin/spire-agent
# agent-start.sh is mounted at runtime via a bind mount
ENTRYPOINT ["/bin/sh"]
