#!/bin/bash
#
# dns-soa-check.sh - Query SOA serials from all authoritative nameservers
# and write Prometheus textfile metrics for serial consistency monitoring.
#
# All servers are queried via IPv6
#
# Run via systemd timer/cron every 5 minutes. Metrics consumed by node_exporter
# textfile collector; alert fires if serials diverge for longer than the grace
# period in the Prometheus rule (to allow time for zone transfers to complete).

OUTFILE=/var/lib/node_exporter/textfile_collector/dns_soa_serial.prom
TMPFILE=$(mktemp /tmp/dns_soa_serial.XXXXXX)

ZONES=(
  example.com
  example1.com
  example2.com
)

SERVERS=(
  ns1.example.com
  ns2.example.com
  ns3.example.com
  ns4.example.com
)

cat >> "$TMPFILE" <<'EOF'
# HELP dns_soa_serial SOA serial number reported by each authoritative nameserver
# TYPE dns_soa_serial gauge
EOF

for zone in "${ZONES[@]}"; do
  for server in "${SERVERS[@]}"; do
    serial=$(dig -6 +short +time=5 +tries=1 @"$server" "$zone" SOA 2>/dev/null | awk '{print $3}')
    if [[ "$serial" =~ ^[0-9]+$ ]]; then
      echo "dns_soa_serial{zone=\"$zone\",server=\"$server\"} $serial" >> "$TMPFILE"
    fi
  done
done

chmod 644 "$TMPFILE"
mv "$TMPFILE" "$OUTFILE"
