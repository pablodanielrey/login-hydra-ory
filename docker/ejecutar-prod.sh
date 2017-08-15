#!/bin/bash
sudo docker run -ti --name $1 -p 5000:5000 --rm --env-file ../../environment $1 $2
