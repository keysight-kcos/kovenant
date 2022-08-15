#!/bin/bash

kubectl get namespaces | awk 'NR==2, NR==length() { print $1 }'
