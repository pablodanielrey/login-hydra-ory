#!/bin/bash

#primero hay que conectar el cliente hydra usando los datos configurados cuando
#se corre el contenedor docker.
sudo  docker exec -ti hydra \
hydra connect \
  --id admin \
  --secret admin \
  --url https://127.0.0.1:4444

#Cluster URL []: https://127.0.0.1:4444
#Client ID []: admin
#Client Secret [empty]: admin
#Persisting config in file /root/.hydra.yml


#se crea credenciales para la app consent
sudo docker exec -ti hydra \
hydra clients create --skip-tls-verify \
  --id consent-app \
  --secret consent-secret \
  --name "Consent App Client" \
  --grant-types client_credentials \
  --response-types token \
  --allowed-scopes hydra.keys.get

#ahora se setean las policies para que el consent-app pueda
#acceder a las claves
sudo docker exec -ti hydra \
hydra policies create --skip-tls-verify \
  --actions get \
  --description "Allow consent-app to access the cryptographic keys for signing and validating the consent challenge and response" \
  --allow \
  --id consent-app-policy \
  --resources rn:hydra:keys:hydra.consent.challenge:public,rn:hydra:keys:hydra.consent.response:private \
  --subjects consent-app


#se crean las politicas para que la app cliente pueda acceder a autentificar
sudo docker exec -ti hydra \
hydra policies create --skip-tls-verify \
  --actions get \
  --description "Allow everyone to read the OpenID Connect ID Token public key" \
  --allow \
  --id openid-id_token-policy \
  --resources rn:hydra:keys:hydra.openid.id-token:public \
  --subjects "<.*>"


