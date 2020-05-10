# client-wasm
Load testing client for bank platform

## Modify the variables on the script executeMultiUser.sh
N = the number of concurrent clients.
AG = IP of the kubernetes api-gateway service, can be seen with -> $kubectl get all

This will output a stats.csv file that can be inputed in the python script on:
https://github.com/brunorib/stats

With the options available a set of plots and stats can be seen from the test.
