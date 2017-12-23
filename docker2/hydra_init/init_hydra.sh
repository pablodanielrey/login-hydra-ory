#!/bin/bash

#seguir este tutorial.
#https://www.ory.am/run-oauth2-server-open-source-api-security

# y se ejecuta a mano ahi adentro la migración de la base
hydra migrate sql $DATABASE_URL

#y se crea la app de consent
hydra clients create --skip-tls-verify \
  --id consent-app \
  --secret consent-secret \
  --name "Consent App Client" \
  --grant-types client_credentials \
  --response-types token \
  --allowed-scopes hydra.keys.get

#le doy permisos configurando la politica de acceso
hydra policies create --skip-tls-verify \
  --actions get \
  --allow \
  --id consent-app-policy \
  --resources "rn:hydra:keys:hydra.consent.<.*>" \
  --subjects consent-app
