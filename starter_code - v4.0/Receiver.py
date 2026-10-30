import socket
import getopt
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import Checksum

class Connection():
    def __init__(self,host,port,start_seq,filename,debug=False):
        self.debug = debug
        self.updated = time.time()
        self.current_seqno = start_seq - 1 # expect to ack from the start_seqno
        self.host = host
        self.port = port
        self.max_buf_size = 7
        safe_filename = os.path.basename(filename.replace("\\", "/"))
        if safe_filename in ("", ".", ".."):
            raise ValueError("Invalid filename in SYN packet")
        received_dir = Path(__file__).resolve().parent / "received"
        received_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
        prefix = f"{host.replace('.', '_')}_{port}_{timestamp}"
        self.output_path = received_dir / f"{prefix}_{safe_filename}"
        suffix = 1
        while True:
            try:
                self.outfile = self.output_path.open("xb")
                break
            except FileExistsError:
                self.output_path = received_dir / f"{prefix}_{suffix}_{safe_filename}"
                suffix += 1
        self.seqnums = {} # enforce single instance of each seqno

    def ack(self, seqno, data, sackMode = False):
        res_data = []
        sacks = []
        self.updated = time.time()
        if seqno > self.current_seqno and seqno <= self.current_seqno + self.max_buf_size:
            self.seqnums[seqno] = data
            for n in sorted(self.seqnums.keys()):
                if n == self.current_seqno + 1:
                    self.current_seqno += 1
                    res_data.append(self.seqnums[n])
                    del self.seqnums[n]
                else:
                    break # when we find out of order seqno, quit and move on

        if self.debug:
            print ("Receiver.py:next seqno should be %d" % (self.current_seqno+1))

        # note: we return the /next/ sequence number we're expecting
        if sackMode:
            for n in sorted(self.seqnums.keys()):
                sacks.append(n)
            return "%s;%s" % (self.current_seqno+1, ','.join(map(str, sacks))), res_data
        else:
            return str(self.current_seqno+1), res_data


    def record(self,data):
        self.outfile.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        self.outfile.flush()

    def end(self):
        self.outfile.close()

class Receiver():
    def __init__(self,listenport=33122,debug=False,timeout=10, sackMode=False):
        self.debug = debug
        self.timeout = timeout
        self.sackMode = sackMode
        self.last_cleanup = time.time()
        self.port = listenport
        self.host = ''
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.settimeout(timeout)
        self.s.bind((self.host,self.port))
        self.connections = {} # schema is {(address, port) : Connection}
        self.MESSAGE_HANDLER = {
            b'syn' : self._handle_syn,
            b'dat' : self._handle_dat,
            b'fin' : self._handle_fin,
            b'ack' : self._handle_ack
        }

    def start(self):
        while True:
            try:
                message, address = self.receive()
                msg_type, seqno, data, checksum = self._split_message(message)
                try:
                    seqno = int(seqno)
                except:
                    raise ValueError
                if debug:
                    print ("Receiver.py: received %s|%d|%s|%s" % (msg_type, seqno, data[:5], checksum))
                if Checksum.validate_checksum(message):
                    self.MESSAGE_HANDLER.get(msg_type,self._handle_other)(seqno, data, address)
                elif self.debug:
                    print ("Receiver.py: checksum failed: %s|%d|%s|%s" % (msg_type, seqno, data[:5], checksum))

                if time.time() - self.last_cleanup > self.timeout:
                    self._cleanup()
            except socket.timeout:
                self._cleanup()
            except (KeyboardInterrupt, SystemExit):
                exit()
            except ValueError as e:
                if self.debug:
                    print ("Receiver.py:" + str(e))
                pass # ignore

    # waits until packet is received to return
    def receive(self):
        return self.s.recvfrom(4096)

    # sends a message to the specified address. Addresses are in the format:
    #   (IP address, port number)
    def send(self, message, address):
        self.s.sendto(message, address)

    # this sends an ack message to address with specified seqno
    def _send_ack(self, seqno, address):
        if self.sackMode:
            m = "sack|%s|" % seqno
        else:
            m = "ack|%s|" % seqno
        checksum = Checksum.generate_checksum(m.encode("utf-8"))
        message = "%s%s" % (m, checksum)
        if self.debug:
            print ("Receiver.py: send ack %s" % m)
        self.send(message.encode("utf-8"), address)

    def _handle_syn(self, seqno, data, address):
        if not address in self.connections:
            try:
                filename = data.decode("utf-8") if data else "received_file"
            except UnicodeDecodeError as error:
                raise ValueError("Filename in SYN packet is not valid UTF-8") from error
            self.connections[address] = Connection(
                address[0], address[1], seqno, filename, self.debug
            )
        conn = self.connections[address]
        ackno, res_data = conn.ack(seqno,data,self.sackMode)
        #for l in res_data:
            #if self.debug:
            #    print data
            #conn.record(l)
        self._send_ack(ackno, address)

    # ignore packets from uninitiated connections
    def _handle_dat(self, seqno, data, address):
        if address in self.connections:
            conn = self.connections[address]
            ackno,res_data = conn.ack(seqno,data,self.sackMode)
            for l in res_data:
                #if self.debug:
                #    print l
                conn.record(l)
            self._send_ack(ackno, address)

    # handle end packets
    def _handle_fin(self, seqno, data, address):
        if address in self.connections:
            conn = self.connections[address]
            ackno, res_data = conn.ack(seqno,data,self.sackMode)
            for l in res_data:
                #if self.debug:
                #    print l
                conn.record(l)
            self._send_ack(ackno, address)

    # I'll do the ack-ing here, buddy
    def _handle_ack(self, seqno, data, address):
        pass

    # handler for packets with unrecognized type
    def _handle_other(self, seqno, data, address):
        pass

    def _split_message(self, message):
        pieces = message.split(b'|')
        if len(pieces) < 3:
            raise ValueError("Malformed packet")
        msg_type, seqno = pieces[0:2] # first two elements always treated as msg type and seqno
        checksum = pieces[-1] # last is always treated as checksum
        data = b'|'.join(pieces[2:-1]) # everything in between is considered data
        return msg_type, seqno, data, checksum

    def _cleanup(self):
        if self.debug: 
            print ("Receiver.py: clean up time")
        now = time.time()
        for address in list(self.connections.keys()).copy():
            conn = self.connections[address]
            if now - conn.updated > self.timeout:
                if self.debug:
                    print ("Receiver.py: killed connection to %s (%.2f old)" % (address, now - conn.updated))
                conn.end()
                del self.connections[address]
        self.last_cleanup = now

if __name__ == "__main__":
    def usage():
        print ("BEARS-TP Receiver")
        print ("-p PORT | --port=PORT The listen port, defaults to 33122")
        print ("-t TIMEOUT | --timeout=TIMEOUT Receiver timeout in seconds")
        print ("-d | --debug Print debug messages")
        print ("-h | --help Print this usage message")
        print ("-k | --sack Enable selective acknowledgement mode")

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "p:dt:k", ["port=", "debug=", "timeout=", "sack="])
    except:
        usage()
        exit()

    port = 33122
    debug = False
    timeout = 10
    sackMode = False

    for o,a in opts:
        if o in ("-p", "--port="):
            port = int(a)
        elif o in ("-t", "--timeout="):
            timeout = int(a)
        elif o in ("-d", "--debug="):
            debug = True
        elif o in ("-k", "--sack="):
            sackMode = True
        else:
            print (usage())
            exit()
    r = Receiver(port, debug, timeout, sackMode)
    r.start()
