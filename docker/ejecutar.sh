#!/bin/bash
sudo docker run -ti -d --name login-consent -v $(pwd)/src:/src -p 5000:5000 -p 5001:5001 -p 5002:5002 -p 5003:5003 --env-file /home/pablo/gitlab/fce/produccion/login-consent login-consent
sudo docker exec -t login-consent bash instalar.sh

