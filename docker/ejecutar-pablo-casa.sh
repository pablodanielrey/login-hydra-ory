sudo docker run -ti --name login-consent -v $(pwd)/src:/src -p 10000:5000 -p 10001:5001 -p 10002:5002 --env-file /home/pablo/gitlab/fce/pablo/casa/login-consent login-consent
