#!/bin/bash

N_array=(3000000 5000000 7000000 10000000) # Number of users
T_array=(400) # Number of trails
E_array=(0.5 0.2 0.1 0.01) # Number of trails
k_array=(1 2 3 4 5) # Number of blankets



for n in "${!N_array[@]}";   
do  
	for t in "${!T_array[@]}";   
	do  
        for e in "${!E_array[@]}";   
        do
	for k in "${!k_array[@]}";   
        do
            ./Euro_real.x -n ${N_array[$n]} -t ${T_array[$t]} -e ${E_array[$e]} -k ${k_array[$k]}
        done
	done
	done
done	
