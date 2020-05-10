#!/bin/bash

N=100
userbase="bruno"
AG=10.152.183.109

rm -rf tokens/ nohup.out stats.csv

for ((n=0;n<$N;n++))
do
   user=$userbase$n
   nohup ./executeSingleUser.sh $AG $user $user@gmail.com 1234 100 100 1000 &
   sleep 0.3
done

tail -f nohup.out