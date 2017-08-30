#!/bin/bash
sudo docker run -ti --rm -d --name login-consent -v $(pwd)/src:/src -p 5000:5000 -p 5001:5001 -p 5002:5002 -p 5003:5003 --env-file $HOME/gitlab/fce/produccion/login-consent login-consent
sudo docker exec -t login-consent bash instalar.sh

