#!/bin/bash
tar -cvzf src.tar.gz ./src
docker build -t login-consent-hydra .
