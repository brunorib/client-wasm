#!/bin/bash

API_GATEWAY_SERVICE_IP=$1
USER=$2
EMAIL=$3
PASS=$4
k=$5
ITERATIONS=$6
QUANTITY=$7

curl --location -s --request POST "http://$API_GATEWAY_SERVICE_IP:8080/users" \
--header 'Content-Type: application/json' \
--data-raw '{
	"username": "'$USER'",
	"email": "'$EMAIL'",
	"password": '$PASS'
}'

echo ""

auth=$(curl -s --location --request POST "http://$API_GATEWAY_SERVICE_IP:8080/login" \
--header 'Content-Type: application/json' \
--data-raw '{
	"username": "'$USER'",
	"password": '$PASS'
}')

echo "./target/debug/commit-calculator http://$API_GATEWAY_SERVICE_IP:8080 $USER $PASS $QUANTITY $ITERATIONS $k worker-sign.pem tokens/"

cargo run http://$API_GATEWAY_SERVICE_IP:8080 $USER $PASS $QUANTITY $ITERATIONS $k worker-sign.pem tokens/

auth=$(curl -s --location --request POST "http://$API_GATEWAY_SERVICE_IP:8080/login" \
--header 'Content-Type: application/json' \
--data-raw '{
	"username": "'$USER'",
	"password": '$PASS'
}')

prefix='{"token":"'
suffix='"}'
token=${auth#"$prefix"}
token=${token%"$suffix"}

body=$(echo $token | grep -o -P '(?<=\.).*(?=\.)')

decoded=$(echo $body | base64 -d 2>/dev/null)
USER_ID=$(echo $decoded | grep -Po '(?<=\"iss\":\").*(?=\",)')

echo "Consuming tokens for user: $USER_ID"

for filename in tokens/token_$USER_ID*.json; do
    start=`date +%s%3N`
    res=$(curl -o -s -w "%{http_code}\n" --request POST "http://$API_GATEWAY_SERVICE_IP:8080/balances/token" \
    --header 'Authorization: Bearer '$token'' \
    --header 'Content-Type: application/json' \
    --data-raw '{
        "user_id": '$USER_ID',
        "token": '$(cat $filename)'
    }' 2>/dev/null )
    end=`date +%s%3N`
    runtime=$(($end-$start))
    success="false"
    if [ "$res" = "200" ]; then
        success="true"
    fi
    timestamp=`date +%s%3N`
    echo "/balances/token,$runtime,$success,$timestamp" >> stats.csv
done



