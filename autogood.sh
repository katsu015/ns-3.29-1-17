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
    : > alldsrgoodp.csv
    for Seed in $(seq 1 $Finish_filenum);
      do
         wc -l < dsrgoodp-seed$Seed-node7.csv >> "alldsrgoodp.csv"
      done
    exit 0
  fi
  #./waf build
  ./waf --run "dsrgood --seed=$Seed"
#  for filenum in $(seq 0 $Finish_filenum);
#  do
#    tshark -r "dsrgoodp-$filenum-0.pcap" -Y "wlan.fc.type_subtype == 0x001b and wlan.ta==00:00:00:00:00:08" -T fields -E header=y -E separator=',' -e "frame.number" -e "frame.time_relative" -e "wlan.ta" -e "wlan.ra" > "dsrgoodp-seed$Seed-node$filenum.csv"
#  done
#  cat "dsrgoodp-seed$Seed-node"*.csv | head -n 1 > "alldsrgoodp$Seed.csv" && find -name "dsrgoodp-seed$Seed-node*.csv" -exec sed -e '1d' {} \; >> "alldsrgoodp$Seed.csv"
  tshark -r "dsrgoodp-7-0.pcap" -Y "wlan.fc.type_subtype == 0x001b and wlan.ta==00:00:00:00:00:08" -T fields -E header=n -E separator=',' -e "frame.number" -e "frame.time_relative" -e "wlan.ta" -e "wlan.ra" > "dsrgoodp-seed$Seed-node7.csv"
  Seed=`echo "$Seed+1" | bc`

done
