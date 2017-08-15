#!/bin/bash
sudo docker exec -ti hydra \
hydra token user --skip-tls-verify \
  --auth-url https://localhost:4444/oauth2/auth \
  --token-url https://localhost:4444/oauth2/token \
  --id some-consumer \
  --secret consumer-secret \
  --scopes openid,offline,hydra.clients \
  --redirect http://192.168.0.3:10000/callback

