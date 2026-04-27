import os, sys, time
pid = os.fork()
if pid > 0: sys.exit(0)
os.setsid()
pid = os.fork()
if pid > 0: sys.exit(0)
while True:
    with open('daemon.marker', 'w') as f: f.write('running')
    time.sleep(0.1)
