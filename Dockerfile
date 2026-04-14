FROM ubuntu:22.04

RUN apt-get update && apt-get install -y rsyslog && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/aegisfa

COPY rsyslog-config/rsyslog.conf /etc/rsyslog.conf

EXPOSE 514/udp
EXPOSE 514/tcp

CMD ["rsyslogd", "-n", "-f", "/etc/rsyslog.conf"]