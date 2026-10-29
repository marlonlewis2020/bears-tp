import time
import sys
import getopt

import Checksum
import BasicSender

import inspect, random
from pathlib import Path

'''
This is a skeleton sender class. Create a fantastic transport protocol here.
'''
class Sender(BasicSender.BasicSender):
    def __init__(self, dest, port, filename, debug=False, sackMode=False):
        super(Sender, self).__init__(dest, port, filename, debug)
        self.sackMode = sackMode
        self.debug = debug
        self.debug_counter = 0
        self.base_seqno = None
        self.sqno_init = random.randint(0, (2 ** 32) - 1)
        self.sqno_counter = self.sqno_init
        self.msg_table = {}
        self.msg_size = 1472 - len("DAT|0000000000||0000000000") # 1472 bytes - header size
        self.timeout = 0.5
        self.unacked_packets = {}
        self.swnd = 7 # sliding window size
        self.ack_tracker = {}
        self.final_seqno = None

    def debug_print(self, message:str, function:str=None):
        '''
        This is the method that will be used to output debug messages when debug mode is enabled.
        '''
        # only print if debug is enabled
        self.debug_counter += 1
        print(f"{self.debug_counter}: [Sender (Class)][DEBUG] {function or inspect.stack()[1].function} (function), line: {inspect.stack()[1].lineno} - {message}") if self.debug else print(end="")

    def _get_next_seqno(self):
        '''
        This method returns the sequence numbers to assign to packets when creating the initia; message table.
        This should only be used by the build_msg_table function.
        '''
        sqno = self.sqno_counter
        self.sqno_counter = (self.sqno_counter + 1) % (2 ** 32)
        return sqno

    def _add_to_msg_table(self, seqno:int, msg:bytes):
        '''
        This is another helper function to build the initial message table used when sending out packets.
        '''
        self.msg_table[seqno] = msg
        return seqno

    def build_msg_table(self, file: bytes):
        '''
        This methos is for building the message table based on the file selected. 
        The message table is use for tracking all file packets to be sent.
        '''
        # take a file and break it into chunks of msg_size, add each chunk to the msg_table with a unique sequence number and return the sequence number of the last chunk added
        self.msg_table = {}
        seqno = None
        prior_chunk = None
        while True:
            chunk = file.read(self.msg_size).decode("utf-8")
            if not chunk:
                self.final_seqno = seqno
                packet = self.make_packet("fin", seqno, prior_chunk)
                self._add_to_msg_table(seqno, packet)
                self.debug_print(f"Reached end of file. Final sequence number is {self.final_seqno}.")
                break
            else:
                seqno = self._get_next_seqno()
                prior_chunk = chunk
                # if the sequence number is equal to the initial sequence number, set the message type to SYN, else set it to DATA
                if seqno == self.sqno_init:
                    packet = self.make_packet("syn", seqno, chunk)
                else:
                    packet = self.make_packet("dat", seqno, chunk)
                self._add_to_msg_table(seqno, packet)
                self.debug_print(f"Added packet with seqno {seqno} to msg_table.")
        return seqno

    def run(self):
        '''
        This function get the initial compltion checks and file sending started
        '''
        # Function starts the app - populate the unacked_packets with the next swnd chunks from the msg_table, 
        # update the ack_tracker with the sequence numbers of the chunks added to the unacked_packets.
        # check if file sending is complete
        complete = self.is_file_sending_complete()
        if complete:
            self.close_app()
        else:
            # handle incoming responses
            self.handle_response()

    def populate_unacked_packets(self):
        '''
        This function is called to stage all outstanding messages from the message table to prepare them to be sent.
        '''
        # populate the unacked_packets with the next swnd chunks from the msg_table, update the ack_tracker with the sequence numbers of the chunks added to the unacked_packets
        for seqno in sorted(self.msg_table.keys())[:self.swnd]:
            if len(self.unacked_packets) < self.swnd:
                self.unacked_packets[seqno] = {}
                self.unacked_packets[seqno]['packet'] = self.msg_table.pop(seqno)
                self.unacked_packets[seqno]['time_out'] = time.monotonic() + self.timeout
                self.unacked_packets[seqno]['timeout_retransmit_limit'] = 5
                self.ack_tracker[seqno] = 0
            else:
                break
        self.base_seqno = min(self.unacked_packets.keys()) if self.unacked_packets else None
        self.debug_print(f"Populated unacked_packets with next {self.swnd} chunks from msg_table. Base sequence number is now {self.base_seqno}.")

    def validate_ack(self, ack_seqno:str|int):
        '''
        The method is to validate received acks.
        It performs selective acknowledgements of selective acks, if sackmode is enabled.
        It then does cumulative acknowledgements after checking if the cumulative acl belongs to an unacked packet.
        '''
        # validate the ack_seqno received from the receiver, if it is in the unacked_packets, remove all cumulative acknowledgments and return the counter value for the expected sequence number, else return None
        if self.sackMode:
            ack_seqno, sack_seqnos = ack_seqno.split(';')  # Extract the cumulative ACK and SACK sequence number
            ack_seqno = int(ack_seqno)
            sack_seqnos = [int(s) for s in sack_seqnos.split(',')] if len(sack_seqnos.split(',')) > 1 else []  # Extract selective ACK sequence numbers
            self.debug_print(f"Received SACK sequence no: {ack_seqno}.")
            
            for sack_seqno in sack_seqnos:
                self.selective_ack_packet(sack_seqno)
            self.debug_print(f"Processed SACK sequence numbers: {sack_seqnos}.")
        
        if ack_seqno in self.unacked_packets.keys() or ack_seqno == self.final_seqno+1:
            self.debug_print(f"Valid ACK received for seqno {ack_seqno}.")
            return self.cumulative_ack_packets(ack_seqno)
        else:
            self.debug_print(f"Invalid ACK received for seqno {ack_seqno}. Not in unacked_packets.")
            return False

    def _cumulative_ack_tracker(self, ack_seqno:int):
        '''
        This method checks cumulative ack numbers to determine if all packets were successfully received to close the connection and app.
        It also tracks duplicate ack numbers and retransmits if triple duplicate acks occur.
        '''
        # increment the counter and check the ack_tracker if the ack_seqno counter is 3 or more, if it is, retransmit packet
        # if the counter is 3 or more, it retransmits the packet andresets the counter to 0
        if ack_seqno == self.final_seqno+1:
            self.debug_print(f"Final ACK received for seqno {ack_seqno}. Closing socket.")
            self.close_app()
            return
        
        self.ack_tracker[ack_seqno] += 1
        if self.ack_tracker[ack_seqno] >= 3:
            # fast retransmit
            self.debug_print(f"ACK for seqno {ack_seqno} received 3 times, retransmitting packet.")
            self.retransmit_packet(ack_seqno)

    def cumulative_ack_packets(self, ack_seqno:int):
        '''
        This method is responsible for acknowledging all packets waiting to be acknowledged in the queue based on the largest ack received.
        '''
        # remove all packets from the unacked_packets and ack_tracker with sequence numbers less than the ack_seqno
        for seqno in sorted(list(self.unacked_packets.keys())):
            if seqno < ack_seqno:
                self.unacked_packets.pop(seqno)
                self.ack_tracker.pop(seqno)
            else:
                break
        self.debug_print(f"Cumulative ACK received for seqno {ack_seqno}. Removed packets with sequence numbers less than {ack_seqno} from unacked_packets and ack_tracker.")
        self._cumulative_ack_tracker(ack_seqno)
        return True

    def selective_ack_packet(self, sack_seqno:int):
        '''
        This method performs selective acknowledgements.
        '''
        # remove the packet from the unacked_packets and ack_tracker with the sequence number equal to the sack_seqno
        if sack_seqno in self.unacked_packets.keys():
            self.unacked_packets.pop(sack_seqno)
            self.ack_tracker.pop(sack_seqno)
            self.debug_print(f"Selective ACK received for seqno {sack_seqno}. Packet removed from unacked_packets.")
        else:
            self.debug_print(f"Selective ACK received for seqno {sack_seqno}, but packet not found in unacked_packets.")

    def send_into_window(self):
        '''
        This method manages the transmission of messages into the receiver based on the sliding window.
        '''
        # send all packets in the unacked_packets and start the retransmit timer for each packet
        for seqno in sorted(self.unacked_packets.keys())[:self.swnd]:
            self.single_send(seqno)
        self.debug_print(f"All packets in unacked_packets sent. Last sequence number sent: {max(self.unacked_packets.keys()) if self.unacked_packets else None}. Waiting for ACKs.")

    def is_file_sending_complete(self):
        '''
        This method is responsible to reload the staging object.
        It checks if all packets have already been staged and acknowledged, and immediately transmits new packets that have been staged.
        It returns the completion status of the file send and acknowledgement process.
        '''
        # check if the msg_table and unacked_packets are empty, if they are, return True, else return False
        if not self.msg_table and not self.unacked_packets:
            # all packets have been sent and acknowledged, return True
            self.debug_print("All packets have been sent and acknowledged.")
            return True
        elif self.msg_table and not self.unacked_packets:
            # all sent packets have been acknowledged, but there are still packets in the msg_table to be sent, return False
            self.debug_print("Packets in the msg_table are being staged to be sent.")
            self.populate_unacked_packets()
            # send the packets in the unacked_packets and start the retransmit timer for each packet
            # use threading for concurrent sending of packets in the unacked_packets
            
            self.send_into_window()

            return False
        elif not self.msg_table and self.unacked_packets:
            # app only needs to wait for all sent packets to be acknowledged, return False
            self.debug_print("All packets have been sent, but there are still packets in the unacked_packets to be acknowledged.")
            return False
        else:
            # app waits for all sent packets to be acknowledged before unacked_packets can be populated with the next swnd chunks from the msg_table, return False
            self.debug_print("There are still packets in the msg_table and unacked_packets to be sent and acknowledged.")
            return False

    def single_send(self, seqno: int):
        '''
        This method is responsible for sending a packet to the receiver.
        '''
        packet = self.unacked_packets[seqno]['packet']
        if packet is None:
            self.debug_print(f"Packet with seqno {seqno} not found in unacked_packets.")
            return

        super().send(packet)
        return

    def handle_response(self):
        '''
        This method is responsible for logical handling of all responses from the receiver/server.
        '''
        response = self.receive(timeout=self.timeout)
        end = False
        while True:
            try:
                # time-out occurred
                if response is None:
                    # cycle through time-out limit for each packet
                    for (seqno, item) in self.unacked_packets.items():
                        if not self.unacked_packets[seqno]['timeout_retransmit_limit']: 
                            end = True
                            break
                        if time.monotonic() > item.get('time_out'):
                            self.retransmit_packet(seqno)
                    
                    # continue to wait after retransmitting, if retransmission limit hasn't been reached
                    if end: 
                        break
                    continue

                # no time-out, so check checksum and message type
                response_text = response.decode("utf-8")
                msg_type, ack_value, _ = response_text.split("|")
                expected_msg_type = "sack" if self.sackMode else "ack"
                if msg_type != expected_msg_type or not Checksum.validate_checksum(
                    f"{response_text}"
                ):
                    self.debug_print(f"Received invalid response: {response_text}. Ignoring and waiting for valid ACK.")
                    continue

                # validate ack and check if file completely sent and acknowledged
                self.debug_print(f"Received valid response: {response_text}")
                ack = ack_value if self.sackMode else int(ack_value)
                if self.validate_ack(ack):
                    completed = self.is_file_sending_complete()
                    if completed:
                        break
                    else:
                        continue
                    
                self.debug_print(f"Waiting for valid ACK. Current unacked_packets: {list(self.unacked_packets.keys())}")
            except Exception as e:
                self.debug_print(f"Error sending or receiving message: {e}. Retrying...")
        # close connection and app
        self.close_app()

    def retransmit_packet(self, seqno:int):
        '''
        This method is responsible for time-out and triple ack packet retransmisions.
        It enforces the use of a retransmission limit and verifies that the packet response is expected and has not yet been acknowledged
        '''
        # check if packet still unacknowledged and the time-out retransmit limit
        item = self.unacked_packets.get(seqno, None)
        if item and item.get('timeout_retransmit_limit'):
            self.unacked_packets[seqno]['timeout_retransmit_limit'] -= 1
            self.debug_print("Timeout or triple ACK occurred.")
        else:
            if not item: 
                self.debug_print(f"Packet with seqno {seqno} not found in unacked_packets. Unable to retransmit.")
            else: 
                self.debug_print(f"Max of time-out retransmissions has been reached")
                self.close_app()
            return False

        # retransmit the packet with the given sequence number from the unacked_packets, and reset the ack_tracker counter for that sequence number to 0
        self.debug_print(f"Retransmitting packet with seqno {seqno}.")
        self.single_send(seqno)
        self.ack_tracker[seqno] = 0
        self.handle_response()

    def close_app(self):
        '''
        This method is called to tear down the connection and gracefully close the Sender app.
        '''
        # closing socket and app
        self.debug_print("Closing client connection and app")
        self.sock.close()
        sys.exit(1)
        # pass

    # Main sending loop.
    def start(self):
        # add things here
        try:
            if self.debug and self.debug_print:
                print("[Debug mode is enabled]")
                self.debug_print(f"SACK mode enabled: {self.sackMode}")
                self.debug_print("Starting the sender.")
        except Exception as e:
            print(f"Error in debug_print: {e}")

        # try to get and open file using filename, if not found, exit with error message
        try:
            if self.infile == sys.stdin:
                self.debug_print("Reading from standard input.")
                filename = Path(input("Enter filename: ")).as_posix()
                if not Path(filename).is_file():
                    self.debug_print(f"File not found: {filename}")
                    sys.exit(1)
                self.infile = open(filename, "rb")

            self.debug_print(f"Opening file: {self.infile.name}")
            self.build_msg_table(self.infile)
            self.run()
        except Exception as e:
            self.debug_print(f"Error opening file: {e}")
            sys.exit(1)
'''
This will be run if you run this script from the command line. You should not
change any of this; the grader may rely on the behavior here to test your
submission.
'''
if __name__ == "__main__":
    def usage():
        print("BEARS-TP Sender")
        print("-f FILE | --file=FILE The file to transfer; if empty reads from STDIN")
        print("-p PORT | --port=PORT The destination port, defaults to 33122")
        print("-a ADDRESS | --address=ADDRESS The receiver address or hostname, defaults to localhost")
        print("-d | --debug Print debug messages")
        print("-h | --help Print this usage message")
        print("-k | --sack Enable selective acknowledgement mode")

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "f:p:a:dk", ["file=", "port=", "address=", "debug=", "sack="])
    except:
        usage()
        exit()

    # Set default values for arguments.
    port = 33122
    dest = "localhost"
    filename = None
    debug = False
    sackMode = False

    # Parse command line arguments and override defaults.
    for o,a in opts:
        if o in ("-f", "--file="):
            filename = a
        elif o in ("-p", "--port="):
            port = int(a)
        elif o in ("-a", "--address="):
            dest = a
        elif o in ("-d", "--debug="):
            debug = True
        elif o in ("-k", "--sack="):
            sackMode = True

    # run Sender.start() function created above, else exit for specific errors
    print(f"Starting Sender with destination: {dest}, port: {port}, file: {filename}, debug: {debug}, sackMode: {sackMode}")
    s = Sender(dest,port,filename,debug,sackMode)
    try:
        s.start()
    except (KeyboardInterrupt, SystemExit):
        exit()
