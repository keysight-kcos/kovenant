#!/bin/bash

kubectl exec my-testing-kcos-sample-go-app-pod -- curl my-kcos-sample-go-app-deployment/v2/checksum/info
