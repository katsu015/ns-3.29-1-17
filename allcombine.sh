#!/bin/bash
Seed=1
read Scenario
#simulation finish seed
# Seed=$input_s_seed
Finish_Seed=11
filenum=0
Finish_filenum=10
Runset=1
Finish_Runset=11
paste -d , all${Scenario}p-run[${Seed}-$((Finish_filenum-1))].csv all${Scenario}p-run${Finish_filenum}.csv > "all${Scenario}p.csv"
