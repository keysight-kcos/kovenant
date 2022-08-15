#!/bin/bash

DEPLOYMENT_NAME="tetragon-grafana"

./with_dotenv.sh helmfile apply

kubectl wait deployment $DEPLOYMENT_NAME --for condition=Available=True
sleep 1 # give the api a second to become available

cd ./dashboard_templating 
./generate_dashboard.py

