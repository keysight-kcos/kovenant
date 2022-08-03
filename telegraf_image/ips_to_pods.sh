#!/bin/bash

kubectl get nodes -o wide | awk '/control-plane/ { print $6}'
kubectl get pods -A -o wide | awk 'NR==2, NR==length() { print $2" "$(NF-3)} '
