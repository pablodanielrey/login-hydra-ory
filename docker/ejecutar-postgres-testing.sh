#!/bin/bash
docker run --name postgresXXX -e POSTGRES_PASSWORD=clavesecreta -p 5432:5432 -d postgres
