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
read Scenario
Seed=1
#simulation finish seed
# Seed=$input_s_seed
Finish_Seed=10
filenum=0
Finish_filenum=9

Runset=1
Finish_Runset=3
while true
do
if [ $Seed -eq $Finish_Seed ]; then
Runset=`echo "$Runset+1" | bc`
    Seed=1
fi
if [ $Runset -eq $((Finish_Runset+1)) ]; then
exit 0
fi
  echo 'simulation run seed'
  echo $Seed
 
  #./waf build
  ./waf --run "${Scenario} --seed=$Seed --Runset=$Runset" > "route$Seed$Runset.txt"
#  for filenum in $(seq 0 $Finish_filenum);
#  do
#    tshark -r "dsrp-$filenum-0.pcap" -Y "wlan.fc.type_subtype == 0x001b and wlan.ta==00:00:00:00:00:08" -T fields -E header=y -E separator=',' -e "frame.number" -e "frame.time_relative" -e "wlan.ta" -e "wlan.ra" > "dsrp-seed$Seed-node$filenum.csv"
#  done
#  cat "dsrp-seed$Seed-node"*.csv | head -n 1 > "alldsrp$Seed.csv" && find -name "dsrp-seed$Seed-node*.csv" -exec sed -e '1d' {} \; >> "alldsrp$Seed.csv"
  
  Seed=`echo "$Seed+1" | bc`

done
