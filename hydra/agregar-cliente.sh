#!/bin/bash

#se crean credenciales para aplicacion cliente
sudo docker exec -ti hydra \
hydra clients create --skip-tls-verify \
  --id some-consumer \
  --secret consumer-secret \
  --grant-types authorization_code,refresh_token,client_credentials,implicit \
  --response-types token,code,id_token \
  --allowed-scopes openid,offline,hydra.clients \
  --callbacks http://192.168.0.3:7000/oidc_callback



