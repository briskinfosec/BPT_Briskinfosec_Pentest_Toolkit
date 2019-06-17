#!/usr/bin/env bash

#This colour
cyan='\e[0;36m'
green='\e[0;34m'
okegreen='\033[92m'
lightgreen='\e[1;32m'
white='\e[1;37m'
red='\e[1;31m'
yellow='\e[1;33m'
BlueF='\e[1;34m'
Magenta='\e[35m' 
bold='\e[1m'
blink='\e[5m'
nr='\e[25m'


echo -e $cyan"#########################################################################"
echo -e $cyan"#                            UPDATING SYSTEM                            #"
echo -e $cyan"#########################################################################"$green
echo
apt-get update
echo
echo

echo -e $green"#########################################################################"
echo -e $green"################         UPDATED.....                     ###############"
echo -e $green"#########################################################################"$white

apt install ncat
pip install webtech
echo -e $cyan"#########################################################################"
echo -e $cyan"################          CLONING TOOLS        ##########################"
echo -e $cyan"#########################################################################"$white

echo -e $cyan"#########################################################################"
echo -e $cyan"################          CLONING NETTACKER         ####################"
echo -e $cyan"#########################################################################"$white
sudo mkdir handler output tools
sudo git clone https://github.com/zdresearch/OWASP-Nettacker.git tools/OWASP-Nettacker
sudo pip install --upgrade pip
sudo pip install -r tools/OWASP-Nettacker/requirements.txt && sudo python tools/OWASP-Nettacker/setup.py
echo
echo -e $cyan"#########################################################################"
echo -e $cyan"################        NETTACKER  CLONED            ####################"
echo -e $cyan"#########################################################################"$white
echo
echo
echo -e "#########################################################################"
echo -e "################          CLONING TESTSSL            ####################"
echo -e "#########################################################################"$white
echo
sudo git clone https://github.com/drwetter/testssl.sh.git tools/testssl && chmod +x tools/testssl/testssl.sh
echo
echo -e $cyan"#########################################################################"
echo -e $cyan"################        TESTSSL  CLONED            ####################"
echo -e $cyan"#########################################################################"$white





