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
Finish_filenum=12
while true
do
  echo 'simulation run seed'
  echo $Seed
  if [ $Seed -eq $Finish_Seed ]; then
    exit 0
  fi
  #./waf build
  #./waf --run "mydsr --seed=$Seed"
  for filenum in $(seq 0 $Finish_filenum);
  do
    tshark -r "mydsrp-$filenum-0.pcap" -Y "wlan.fc.type_subtype == 0x001b and wlan.ta==00:00:00:00:00:08" -T fields -E header=n -E separator=',' -e "frame.number" -e "frame.time_relative" -e "wlan.ra" -e "wlan.ta" > "mydsrp-seed$Seed-node$filenum.csv"
  done
    cat "mydsrp-seed$Seed-node"*.csv | head -n 1 > "all$Seed.csv" && find -name "mydsrp-seed$Seed-node*.csv" -exec sed -e '1d' {} \; >> "all$Seed.csv"
  Seed=`echo "$Seed+1" | bc`

done