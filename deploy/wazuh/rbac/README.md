# Applying the sentinel_ingest RBAC policy

**Correccion post-prueba real (T3):** Wazuh rechaza la creacion de esta politica
por ser identica a la nativa `events_ingest_resourceless` (accion `event:ingest`,
recurso `*:*:*`, efecto `allow`) -- error 4009 "already exists". En la practica,
usa la politica nativa existente en vez de crear `sentinel_ingest.json`:

    curl -k -X GET "https://<manager>:55000/security/policies" \
      -H "Authorization: Bearer $ADMIN_TOKEN" | grep -A2 events_ingest

Toma el `id` devuelto y usalo directamente en el paso 3 de abajo
(`policy_ids=<id>`), saltando el paso de creacion de politica.

Wazuh RBAC has no declarative file format -- `sentinel_ingest.json` must be
POSTed to a running manager. Never version the technical account's password;
it lives in the secrets referenced by SENTINEL_WAZUH__USERNAME_FILE /
SENTINEL_WAZUH__PASSWORD_FILE (see .env.example).

1. Authenticate as an admin user to get a JWT (see auth flow in
   app/infrastructure/wazuh/auth.py for the same pattern).
2. Create the policy:
   curl -k -X POST "https://<manager>:55000/security/policies" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d @deploy/wazuh/rbac/sentinel_ingest.json
3. Create a role (e.g. "sentinel_ingest_role") and attach the policy's
   returned id to it via POST /security/roles and
   POST /security/roles/{role_id}/policies?policy_ids={policy_id}.
4. Create the sentinel_ingest user (or reuse an existing one) and attach
   the role via POST /security/users/{user_id}/role/{role_id}.

This grants exactly `event:ingest` on all resources -- no read, write, or
management access to agents, rules, or anything else on the manager.