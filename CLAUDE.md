# Context: OpenShift Alertmanager → authenticated webhook (OAuth2)

## Goal
Switch OpenShift Alertmanager notifications from an unauthenticated webhook to
an authenticated one using a token server (OAuth2 `client_credentials`).
README.md is the full guide (reference procedure + lab); keep it the single
source of truth.

## Key facts
- Natively supported: Alertmanager `webhook_configs[].http_config.oauth2`
  (client_id, client_secret / client_secret_file, token_url, scopes,
  endpoint_params, tls_config, proxy_url). Token is cached and refreshed
  automatically; sent as `Authorization: Bearer`.
- Platform Alertmanager (central monitoring, what the lab implements): secret
  `alertmanager-main` in `openshift-monitoring`. Credentials mounted via
  `cluster-monitoring-config` → `alertmanagerMain.secrets: [am-oauth2]`
  → `/etc/alertmanager/secrets/am-oauth2/`.
- Per-namespace `AlertmanagerConfig` CRD (monitoring.coreos.com/v1beta1),
  documented as reference only, no lab:
  `webhookConfigs[].httpConfig.oauth2` referencing Secrets. Limited to alerts of
  its own namespace (operator injects a `namespace` matcher), not for platform
  alerts.
- User Workload Monitoring Alertmanager (if enabled) is configured separately
  (`openshift-user-workload-monitoring`, secret `alertmanager-user-workload`).
- Migration: new OAuth2 receiver in parallel with legacy (`continue: true`),
  validate 24-48h, remove legacy, collector switches to strict mode last.
- Alertmanager 0.33 webhook metrics carry `integration` only, no receiver label.

## Repo layout
- `lab/`: `oc apply -k lab/` deploys namespace `am-oauth2-lab` with Keycloak
  (`start-dev`, HTTPS via service CA, realm `monitoring`, clients `ocp-allowed` and
  `ocp-not-allowed`, scope `alerting` → aud `alert-collector`) and a
  JWT-validating receiver (stdlib + PyJWT). Needs Secret `keycloak-lab` first.
- `platform-alertmanager/cluster-monitoring-config.yaml`: minimal ConfigMap,
  only for clusters without one. Working files created by README steps:
  `platform-alertmanager/backup/` (original config) and
  `platform-alertmanager/alertmanager.yaml` (edited copy).
- `tests/token_tests.py`: piped to `python3 -` in a pod in `openshift-monitoring`,
  secrets via stdin.
