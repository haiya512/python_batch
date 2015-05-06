#!/bin/sh

EvnPath="/data/download/down/domestic/games/tenyear2/uuzu"

source "${EvnPath}/installscript/0.evn_init.sh" || { echo -ne "\033[31m"Error: source 0.evn_init.sh fail "\033[0m\n" && exit ;}

Args=($@)
if [[ "${#Args[@]}" != 1 ]];then 
    echo $"Usage: $0 hostfile"
    echo 
    echo "e.g. $0 hostfile";
    echo "######## HostFile Format ########"
    echo "## ServerID ServerIP SSHPort PassWord"
    echo "## e.g."
    echo "192081001	10.0.24.17	57522	Sxxxxxxxxxxxxxxx"	
    echo "192081005	10.0.24.21	57522	Hxxxxxxxxxxxxxxx"
    echo 
    echo "########"
    echo
    exit 1;
fi
HostListServerID="${1}"
HostList="${HostListServerID}_`date +"%Y%m%d%H%M%S"`"
BatchInstallFile="installcmd.txt"

[[ `cat ${HostListServerID} | awk '{print $2}' | sort | uniq -c | sort -n | awk 'END {print $1}'` -gt 1 ]] && { echored "Error: There are duplicate host in ${HostListServerID} " && exit;}

>${HostList}
cat ${HostListServerID} | awk '{print $2,$3,$4}' >>${HostList}

#check hotbak
HotbakStatus="True"
echo "Check hot bak..."
for ServerHost in `cat ${HostList} | awk '{print $1}'`;do
     [[ `curl -q "http://dbbak.uuzuonline.net/api/api.php?ip=${ServerHost}" 2>/dev/null` == "ok" ]] || { echored "Error: === ${ServerHost} === this server did not add to mysql backup system." && HotbakStatus="False" ;}
     [[ `curl -q "http://redisbak.uuzuonline.net/api/api.php?ip=${ServerHost}" 2>/dev/null` == "ok" ]] || { echored "Error: === ${ServerHost} === this server did not add to mysql backup system." && HotbakStatus="False" ;}
done
[[ "${HotbakStatus}" == "False" ]] && rm -f ${HostList} && exit

/bin/cp "${HostListServerID}" "${EvnPath}/installscript"

echo "wget -q -O /tmp/install_${Name}.tgz ${SourceDir}/installscript/install_${Name}.tgz || echo -ne 033[31m Error: get install_${Name}.tgz fail. 033[0m;
wget -q -O /tmp/${HostListServerID} ${SourceDir}/installscript/${HostListServerID} || echo -ne 033[31m Error: get ${HostListServerID} fail. 033[0m;
cd /tmp;
rm -rf include_script;
tar zxvf install_${Name}.tgz;
sleep 0.5;
LocalInnerIP=\$(ifconfig|grep -E '([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})' | awk '{print \$2}' | cut -d: -f2 | grep -E '^192\.|^10\.');
ServerID=\$(grep \"\b\${LocalInnerIP}\b\" ${HostListServerID} | awk '{print \$1}');
sh ${Name}_dep.sh \${ServerID};
rm -f /tmp/${HostListServerID}" >${BatchInstallFile}

echo 
cat ${BatchInstallFile}
echo 
read -p "Are you sure to exec command before?(yes or no)" ANSWER
if [ "X${ANSWER}X" != "XyesX" ] 2>/dev/null;then
echo exit
exit 2;
fi

/usr/local/python2.7/bin/python batchcmd.py -f ${HostList} -C ${BatchInstallFile}

rm -f "${EvnPath}/installscript/${HostListServerID}"
rm -f "${HostList}"
