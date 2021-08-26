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
Seed=10000
#simulation finish seed
# Seed=$input_s_seed
Finish_Seed=10070
while true
do
  echo 'simulation run seed'
  echo $Seed
  Seed=`echo "$Seed+1" | bc`
  if [ $Seed -eq $Finish_Seed ]; then
    exit 0
  fi
    if [ $protocol -eq 1 ]; then
      ./waf build
      ./waf --run "Lsgo-SimulationScenario --buildings=1  --protocol=8 --lossModel=4 --scenario=3 --nodes=$node_num --seed=$Seed"
      tshark -r mydsrp-12-0.pcap -Y "wlan.fc.type_subtype == 0x001b and wlan.ra==00:00:00:00:00:08" -T fields -E header=y -E separator=',' -e "frame.number" -e "frame.time_relative" -e "ip.src" -e "ip.dst" > Test1.csv
    else
      ./waf build
      ./waf --run "Lsgo-SimulationScenario --buildings=1  --protocol=6 --lossModel=4 --scenario=3 --nodes=$node_num --seed=$Seed"
    fi
done
tshark -r mydsrp-12-0.pcap -Y "wlan.fc.type_subtype == 0x001b and wlan.ra==00:00:00:00:00:08" -T fields -E header=y -E separator=',' -e "frame.number" -e "frame.time_relative" -e "ip.src" -e "ip.dst" > Test1.csv
