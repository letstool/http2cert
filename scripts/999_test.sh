#!/bin/bash

curl -s -X POST http://localhost:8080/api/v1/certinfo \
	-H 'Content-Type: application/json' \
	-d '{"socket": "www.google.fr:443"}' | jq
