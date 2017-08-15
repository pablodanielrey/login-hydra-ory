#!/bin/bash
sudo docker run -e "DATABASE_URL=memory" \
		-e "ISSUER=https://localhost:4444/" \
		-e "SYSTEM_SECRET=super_secreto" \
		-e "CONSENT_URL=http://192.168.0.3:10000/consent" \
		-e "FORCE_ROOT_CLIENT_CREDENTIALS=admin:admin" \
		-d --name hydra -p 4444:4444 oryd/hydra
