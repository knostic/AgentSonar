# SIEM Forwarding Example

Forwards agentsonar events to Graylog (or other SIEMs) using GELF format.

## Testing with Graylog

1. Start Graylog:
```bash
docker compose up -d
```

2. Wait ~60s for startup, then create the GELF HTTP input:
```bash
curl -u admin:admin -X POST http://localhost:9000/api/system/inputs -H "Content-Type: application/json" -H "X-Requested-By: cli" -d '{"title":"GELF HTTP","type":"org.graylog2.inputs.gelf.http.GELFHttpInput","global":true,"configuration":{"bind_address":"0.0.0.0","port":12202}}'
```

3. Run the example (from repo root):
```bash
sudo GRAYLOG_URL=http://localhost:12202/gelf go run ./examples/siem_forward
```

4. Generate AI traffic and check Graylog at http://localhost:9000 (admin/admin) > Search

5. Cleanup:
```bash
docker compose down -v
```
