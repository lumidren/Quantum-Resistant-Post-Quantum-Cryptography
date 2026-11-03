# QuantumShield Operations Runbook

This runbook covers day-2 operations for the KMS, relay and gateway. Every procedure lists the
alert that triggers it, the diagnosis steps, and the remediation. Commands assume `kubectl` is
pointed at the production cluster and the Helm release is named `quantumshield`.

## 1. Service overview

| Service | Port | Health | Metrics | Dependencies |
|---------|------|--------|---------|--------------|
| `kms` | 8443 (REST, mTLS), 9443 (gRPC, mTLS) | `/healthz`, `/readyz` | `/metrics` on 9090 | Postgres `kms`, KEK provider |
| `relay` | 8080 (behind gateway) | `/healthz`, `/readyz` | `/metrics` on 9090 | Postgres `relay` |
| `gateway` | 443 | `/gw-health` | exporter on 9113 | kms, relay, web |
| `web` | 3000 (behind gateway) | `/api/health` | | relay, kms |

## 2. Alerts and procedures

### 2.1 `QShieldPrekeyPoolLow` / `QShieldPrekeyPoolExhausted`

**Trigger.** `qshield_relay_prekey_pool_depth < 20` for 10 minutes (warning) or `== 0`
(critical) for any active device.

**Diagnosis.**

```bash
kubectl logs deploy/quantumshield-relay | grep prekey
curl -s https://relay.internal/metrics | grep qshield_relay_prekey_pool_depth | sort -t' ' -k2 -n | head
```

Check whether one device is being drained (possible T12 attack): look at
`qshield_relay_bundle_fetches_total{target_device=...}`.

**Remediation.**

1. If a single requester dominates fetches, add its device id to the deny list
   (`QSHIELD_RELAY_DENY_DEVICES`) and roll the deployment.
2. Clients replenish automatically when they come online; nudge the owner if the device is offline.
3. Service continues via the last-resort PQ prekey; no manual intervention is needed for availability.

### 2.2 `QShieldKeyRotationFailed`

**Trigger.** `increase(qshield_key_rotation_failures_total[15m]) > 0`.

**Diagnosis.**

```bash
kubectl logs deploy/quantumshield-kms | jq 'select(.event=="rotation_failed")'
curl --cert ops.crt --key ops.key https://kms.internal:8443/v1/keys/<id>
```

Common causes: KEK provider unreachable (Vault sealed, AWS KMS throttling), algorithm deprecated
(rotation into a deprecated algorithm is refused by design), database connectivity.

**Remediation.**

* Vault sealed: follow §3.2.
* Deprecated algorithm: rotate with an explicit `algorithm` body to an active one:
  `POST /v1/keys/<id>/rotate {"algorithm": "ml-kem-1024"}`.
* Database: check RDS status; the KMS retries idempotently.

### 2.3 `QShieldHighErrorRate`

**Trigger.** 5xx ratio > 1 % over 5 minutes on kms or relay.

**Diagnosis.** Grafana dashboard *QuantumShield / Service health*, panel *Errors by route*.
Correlate with traces in Tempo/Jaeger by `trace_id` from the JSON logs.

**Remediation.** Roll back with `helm rollback quantumshield <previous revision>` if the error
rate started with a deploy (the CD pipeline does this automatically when health checks fail for
5 minutes after a rollout).

### 2.4 `QShieldClassicalNegotiationRatioHigh`

**Trigger.** More than 50 % of gateway handshakes negotiated a non-hybrid group for 30 minutes.

**Diagnosis.** `qshield_gateway_handshakes_total` by `group`. Determine whether a large client
population lacks PQ support or whether a middlebox is interfering.

**Remediation.** Not a security incident in hybrid mode (classical clients are allowed), but
investigate sudden shifts. If the deployment requires PQ, enable the `strict` gateway profile.

### 2.5 `QShieldAuditChainBroken`

**Trigger.** `GET /v1/audit/verify` returns `ok: false` (checked every 5 minutes by the
`audit-verify` CronJob).

**Procedure.** Treat as a security incident. Preserve the database (snapshot), rotate all API keys,
compare against the latest clean backup, and follow the incident response plan.

## 3. Key Encryption Key operations

### 3.1 KEK rotation (Vault Transit)

```bash
vault write -f transit/keys/qshield-kek/rotate
# Re-wrap all DEKs under the new KEK version (online, idempotent):
curl --cert ops.crt --key ops.key -X POST https://kms.internal:8443/v1/admin/rewrap
```

### 3.2 Unsealing the local Shamir KEK (DR / air-gapped)

The local KEK is split 3-of-5. Three custodians each submit their share:

```bash
curl --cert custodian1.crt --key custodian1.key -X POST https://kms.internal:8443/v1/unseal \
     -d '{"share": "<base64 share>"}'
# repeat for custodians 2 and 3; the third call returns {"sealed": false}
```

Shares are never stored on the KMS host. Test the procedure quarterly with `scripts/test_restore.sh`.

## 4. Backup and restore

### 4.1 Postgres

Nightly `pg_dump --format=custom` of both databases, encrypted with `age` to the backup recipient
key, stored in the versioned S3 bucket (`deploy/compose/backup/backup.sh`). Restore:

```bash
age -d -i backup.key kms-2026-11-03.dump.age | pg_restore -d kms --clean --if-exists
```

### 4.2 Key material

Sealed keys live in the `kms` database; restoring the database restores the sealed blobs. They are
useless without the KEK: Vault/AWS KMS restore follows the provider's procedure, the local KEK
requires the 3-of-5 unseal (§3.2). `scripts/test_restore.sh` performs a full restore into a scratch
database, unseals, and decapsulates with a restored key; CI runs it on every main build.

## 5. Deployments and rollback

* CD deploys to staging on every merge to `main`, runs the smoke suite and interop test, then waits
  for the manual `production` environment approval.
* Rollout uses `maxUnavailable: 0`; readiness requires DB and KEK provider reachability.
* Automatic rollback: the post-deploy job polls `/readyz` and the error-rate query for 5 minutes and
  runs `helm rollback` on failure.

## 6. Certificate operations

* Server certificates are issued by cert-manager (`ClusterIssuer: letsencrypt-prod` or the internal
  CA for mTLS). Renewal is automatic 30 days before expiry.
* The internal CA for mTLS clients is rotated yearly: issue the new CA, add it to
  `QSHIELD_KMS_CLIENT_CA` as a second bundle entry, re-issue client certificates, remove the old CA.

## 7. Algorithm deprecation

1. Open a PR changing `registry/algorithms.toml` status to `deprecated` with the date.
2. Add a migration marking affected keys `rotation_required = true`.
3. Deploy; the console shows affected keys; rotate them (`POST /v1/keys/<id>/rotate`).
4. After all keys are rotated, set status `disabled` in a second PR.
