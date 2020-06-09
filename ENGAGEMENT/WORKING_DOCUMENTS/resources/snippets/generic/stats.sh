#!/usr/bin/env bash
function showScanStats(){
    FILE=$1;
    for p in "53" "135" "137" "139" "445" "80" "443" "3389" "386" "636" "5985" "2701" "1433" "1961" "1962"; do
    TOTAL=`strings service_scans.gnmap|grep $p|wc -l`;
    printf "SERVICE ${p} TOTAL ${TOTAL}\n";
    done;

    for OS in "xp" "nt" "7" "8" "10"; do
    TOTAL=`strings $FILE|grep -i "windows ${OS}"|wc -l`;
    printf "OS windows ${OS} TOTAL ${TOTAL}\n";
    done;

    for OS in "03" "08" "12" "16" "19"; do
    TOTAL=`strings $FILE|grep -i "server 20${OS}"|wc -l`;
    printf "OS windows server ${OS} TOTAL ${TOTAL}\n";
    done;
    return;
}
