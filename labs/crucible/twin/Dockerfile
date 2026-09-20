# ---------------------------------------------------------------------------
# The Crucible twin.
#
# A disposable replica of the *security properties* of an audited device: the
# management services it exposes, the algorithms its SSH offers, the community
# its SNMP answers, and who its packet filter lets near any of it. It is not a
# replica of any vendor's operating system, and it is not trying to be
# (ADR 0008).
#
# Alpine because the whole image is a few tens of megabytes, boots in about a
# second, and carries nothing that is not probed. Python is here because the
# probes and the entrypoint are Python; there is no other runtime.
#
# The container is never given network access beyond its sandbox bridges, and
# it is torn down after every run.
# ---------------------------------------------------------------------------
FROM alpine:3.20

RUN apk add --no-cache \
      busybox-extras \
      openssh-server \
      net-snmp \
      iptables \
      python3 \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh operator \
 && echo 'operator:crucible-twin' | chpasswd

COPY entrypoint.py /twin/entrypoint.py
RUN chmod +x /twin/entrypoint.py

# The spec is mounted or written in at run time; without one the twin does
# nothing at all rather than guessing at a default posture.
ENTRYPOINT ["python3", "/twin/entrypoint.py"]
CMD ["run"]
