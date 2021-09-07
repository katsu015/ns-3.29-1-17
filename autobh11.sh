#!/bin/bash
#simulation start seed

#echo -n INPUT_PROTOCOL_1=SIGO_0=LSGO
#read protocol
#echo $protocol
#echo -n NODE_NUM
#read node_num
#echo -n $node_num
# echo -n START_SEED
# read input_s_seed
# echo $input_s_seed
Seed=1
#simulation finish seed
# Seed=$input_s_seed
Finish_Seed=10
filenum=0
Finish_filenum=9
while true
do
  echo 'simulation run seed'
  echo $Seed
  if [ $Seed -eq $Finish_Seed ]; then
    : > alldsr11p.csv
    for Seed in $(seq 1 $Finish_filenum);
      do
         wc -l < dsr11p-seed$Seed-node7.csv >> "alldsr11p.csv"
      done
    exit 0
  fi
  #./waf build
  ./waf --run "dsr11 --seed=$Seed"
#  for filenum in $(seq 0 $Finish_filenum);
#  do
#    tshark -r "dsr11p-$filenum-0.pcap" -Y "wlan.fc.type_subtype == 0x001b and wlan.ta==00:00:00:00:00:08" -T fields -E header=y -E separator=',' -e "frame.number" -e "frame.time_relative" -e "wlan.ta" -e "wlan.ra" > "dsr11p-seed$Seed-node$filenum.csv"
#  done
#  cat "dsr11p-seed$Seed-node"*.csv | head -n 1 > "alldsr11p$Seed.csv" && find -name "dsr11p-seed$Seed-node*.csv" -exec sed -e '1d' {} \; >> "alldsr11p$Seed.csv"
  tshark -r "dsr11p-7-0.pcap" -Y "wlan.fc.type_subtype == 0x001b and wlan.ta==00:00:00:00:00:08" -T fields -E header=n -E separator=',' -e "frame.number" -e "frame.time_relative" -e "wlan.ta" -e "wlan.ra" > "dsr11p-seed$Seed-node7.csv"
  Seed=`echo "$Seed+1" | bc`

done