#!/bin/bash
sudo docker run -ti --name login-consent -p 5000:5000 -p 5001:5001 -p 5002:5002 -p 5003:5003 --rm --env-file /home/pablo/gitlab/fce/produccion/login-consent login-consent
