#!/bin/bash
Seed=1
#simulation finish seed
# Seed=$input_s_seed
Finish_Seed=10
Finish_filenum=9
: > allmydsrp.csv
for Seed in $(seq 1 $Finish_filenum);
  do
     wc -l < mydsrp-seed$Seed-node7.csv >> "allmydsrp.csv"
  done
