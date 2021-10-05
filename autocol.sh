#!/bin/bash
#simulation start seed

#echo -n INPUT_PROTOCOL_1=SIGO_0=LSGO
read Scenario
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
Finish_Seed=11
filenum=0
Finish_filenum=10
Runset=1
Finish_Runset=3
while true
do

  if [ $Seed -eq $Finish_Seed ]; then
    : > all${Scenario}p-run${Runset}.csv
    for Seed in $(seq 1 $Finish_filenum);do
      wc -l < ${Scenario}p-seed$Seed-node7.csv >> "all${Scenario}p-run${Runset}.csv"
      wc -l < "rtcheck${Scenario}p-seed$Seed-run$Runset-node7.csv" >> "allrtcheck${Scenario}p-run$Runset.csv"
    done
    Runset=`echo "$Runset+1" | bc`
    Seed=1
  fi
  if [ $Runset -eq $((Finish_Runset+1)) ]; then
  paste -d , all${Scenario}p-run[${Seed}-$((Finish_Runset-1))].csv all${Scenario}p-run${Finish_Runset}.csv > "all${Scenario}p.csv"
  paste -d , allrtcheck${Scenario}p-run[${Seed}-$((Finish_Runset-1))].csv allrtcheck${Scenario}p-run${Finish_Runset}.csv > "allrtcheck${Scenario}p.csv"
    exit 0
  fi
  echo 'simulation run seed'
  echo $Seed
  #./waf build
  ./waf --run "${Scenario} --seed=$Seed --Runset=$Runset"
#  for filenum in $(seq 0 $Finish_filenum);
#  do
#    tshark -r "${Scenario}p-$filenum-0.pcap" -Y "wlan.fc.type_subtype == 0x001b and wlan.ta==00:00:00:00:00:08" -T fields -E header=y -E separator=',' -e "frame.number" -e "frame.time_relative" -e "wlan.ta" -e "wlan.ra" > "${Scenario}p-seed$Seed-node$filenum.csv"
#  done
#  cat "${Scenario}p-seed$Seed-node"*.csv | head -n 1 > "all${Scenario}p$Seed.csv" && find -name "${Scenario}p-seed$Seed-node*.csv" -exec sed -e '1d' {} \; >> "all${Scenario}p$Seed.csv"
  tshark -r "${Scenario}p-7-0.pcap" -Y "wlan.fc.type_subtype == 0x001b and wlan.ra==00:00:00:00:00:08" -T fields -E header=n -E separator=',' -e "frame.number" -e "frame.time_relative" -e "wlan.ta" -e "wlan.ra" > "${Scenario}p-seed$Seed-node7.csv"

  awk -F "," '{print $3}' "${Scenario}p-seed$Seed-node7.csv" | sort -n | uniq > "rtcheck${Scenario}p-seed$Seed-run$Runset-node7.csv"

  Seed=`echo "$Seed+1" | bc`


done
