# Phase 4: Deploying

Deployment installs the integration onto the Wazuh manager (or agent) and activates it in the SIEM pipeline. The process is the same regardless of which vendor API the integration targets.

---

## Deployment targets

The wodle can run on three hosts — the choice does not affect the code:

| Target | When to use | Credential location |
|---|---|---|
| **Wazuh manager** (default) | Simplest deployment. Single-node or master in a cluster. | On the manager host |
| **Dedicated agent host** | Credentials isolated from manager. Polling independent of manager restarts. | On the agent host |
| **Existing agent** | Any agent with network access to the vendor API (SOAR server, jump host). | On the agent host |

---

## Standard deployment steps

### 1. Copy wodle files

```bash
# Create wodle directory
sudo mkdir -p /var/ossec/wodles/vendorname/

# Copy Python and shell files
sudo cp wodle/* /var/ossec/wodles/vendorname/

# Set permissions
sudo chown -R root:wazuh /var/ossec/wodles/vendorname/
sudo chmod 750 /var/ossec/wodles/vendorname/run.sh
sudo chmod 750 /var/ossec/wodles/vendorname/vendorname.py
sudo chmod 640 /var/ossec/wodles/vendorname/vendorname_*.py
```

### 2. Configure credentials

```bash
# Create secrets file from template
sudo cp /var/ossec/wodles/vendorname/.secrets.example /var/ossec/wodles/vendorname/.secrets

# Edit with your credentials
sudo nano /var/ossec/wodles/vendorname/.secrets

# Lock down permissions
sudo chown root:wazuh /var/ossec/wodles/vendorname/.secrets
sudo chmod 640 /var/ossec/wodles/vendorname/.secrets
```

### 3. Install decoder and rules

```bash
# Copy decoder
sudo cp rules/vendorname_decoder.xml /var/ossec/etc/decoders/

# Copy rules
sudo cp rules/vendorname_rules.xml /var/ossec/etc/rules/
```

### 4. Add wodle stanza to ossec.conf

Add the wodle block from `artifacts/configs/ossec_vendorname.conf` to `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>vendorname</tag>
    <command>/var/ossec/wodles/vendorname/run.sh</command>
    <interval>5m</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>120</timeout>
  </wodle>
</ossec_config>
```

Key settings:
- `interval` — polling frequency. 5 minutes is the standard default. Adjust based on rate limit budget.
- `timeout` — maximum execution time. Set to 2-3x the expected run duration. Prevents hung processes.
- `run_on_start` — execute immediately on manager start, do not wait for first interval.
- `ignore_output` — must be `no` for events to enter the pipeline.

### 5. Restart Wazuh manager

```bash
sudo systemctl restart wazuh-manager
```

### 6. Verify

```bash
# Check manager started cleanly
sudo systemctl status wazuh-manager

# Watch for integration events
tail -f /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.groups[] == "vendorname")'
```

---

## Docker deployment

For Wazuh running in Docker, volume-mount the wodle directory and add the config:

### docker-compose override

```yaml
services:
  wazuh.manager:
    volumes:
      - ./wodle:/var/ossec/wodles/vendorname:ro
      - ./wodle/.secrets:/var/ossec/wodles/vendorname/.secrets:ro
      - ./rules/vendorname_decoder.xml:/var/ossec/etc/decoders/vendorname_decoder.xml:ro
      - ./rules/vendorname_rules.xml:/var/ossec/etc/rules/vendorname_rules.xml:ro
      - vendorname_state:/var/ossec/wodles/vendorname/state

volumes:
  vendorname_state:
```

Use a named volume for state to persist across container recreations. The wodle files themselves are mounted read-only.

### ossec.conf injection

Mount a custom ossec.conf or use Wazuh's config overlay mechanism to add the wodle stanza.

---

## Dashboards (optional)

If the integration includes pre-built dashboards:

1. Open **Wazuh Dashboard > Stack Management > Saved Objects**
2. Click **Import**
3. Upload the `.ndjson` file(s) from `artifacts/objects/`
4. Navigate to the imported dashboard

---

## Post-deployment verification

- [ ] Events appear in OpenSearch within one polling interval
- [ ] Rule IDs and severity levels match expectations
- [ ] State file is being created and updated (check timestamps)
- [ ] No errors in `/var/ossec/logs/ossec.log` related to the wodle
- [ ] Credential file permissions are `640` with `root:wazuh` ownership
- [ ] Wodle process runs as the `wazuh` user (not root)
