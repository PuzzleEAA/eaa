#!/bin/bash

N_array=(3000000 5000000 7000000 10000000) # Number of users
T_array=(200) # Number of trails
E_array=(0.1) # Number of trails


for n in "${!N_array[@]}";   
do  
	for t in "${!T_array[@]}";   
	do  
        for e in "${!E_array[@]}";   
        do
            ./crypto_sum.x -n ${N_array[$n]} -t ${T_array[$t]} -e ${E_array[$e]}
	done
	done
done	
