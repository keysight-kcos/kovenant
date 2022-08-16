#!/bin/bash

DEPLOYMENT_NAME="tetragon-grafana"
RES=""

./with_dotenv.sh helmfile apply

echo "Waiting for Grafana deployment to finish rollout..."
kubectl wait deployment $DEPLOYMENT_NAME --for condition=Available=True

RES=$(curl -s -o /dev/null -I -w "%{http_code}" localhost/grafana)
until [ $RES -eq "302" ]
do
	echo "Grafana API server responded with ${RES}."
	sleep 2
	RES=$(curl -s -o /dev/null -I -w "%{http_code}" localhost/grafana)
done

echo "Attempting to generate and upload dashboard..."
cd ./dashboard_templating 
./generate_dashboard.py
