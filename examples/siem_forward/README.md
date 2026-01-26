# SIEM Forward

Forward AI traffic events to Graylog (or other SIEMs) via GELF.

## Run

```bash
# stdout only
sudo go run ./examples/siem_forward

# with graylog
cd examples/siem_forward && docker-compose up -d
# wait ~60s, then http://localhost:9000 (admin/admin)
# create GELF UDP input on port 12201
GRAYLOG_ADDR=localhost:12201 sudo go run ./examples/siem_forward
```
