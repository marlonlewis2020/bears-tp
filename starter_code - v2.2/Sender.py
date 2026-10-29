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
        print(f"{self.debug_counter}: [DEBUG] func: {function or inspect.stack()[1].function}, line: {inspect.stack()[1].lineno} - {message}") if self.debug else print(end="")

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
        print("Sender.py: Making packets and building packets table.")
        # take a file and break it into chunks of msg_size, add each chunk to the msg_table with a unique sequence number and return the sequence number of the last chunk added
        self.msg_table = {}

        # initialize first packet as empty syn packet
        seqno = self._get_next_seqno()
        packet = self.make_packet("syn", seqno, "")
        self._add_to_msg_table(seqno, packet)
        self.debug_print(f"Added initial syn packet with seqno {seqno} to msg_table.")

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
                # Set msg type for packets to DAT
                packet = self.make_packet("dat", seqno, chunk)
                self._add_to_msg_table(seqno, packet)
                self.debug_print(f"Added packet with seqno {seqno} to msg_table.")
        return seqno

    def run(self):
        '''
        This function get the initial compltion checks and file sending started
        '''
        # Function starts the app - adds and sends the first syn packet and awaits ack before sending the rest.

        # Send syn and way for ack before proceeding
        # set window size temporarily to one
        self.populate_unacked_packets(1)
        self.send_into_window()

        # Wait for response - if syn acked, proceed, else stop
        # Proceed - populate the unacked_packets object with the next swnd chunks from the msg_table.
        #   update the ack_tracker with the sequence numbers of the chunks added to the unacked_packets.
        #   check if file sending is complete, if complete - stop
        # stop - close after complete, timeout or triple ack
        self.handle_response()

    def populate_unacked_packets(self, size=None):
        '''
        This function is called to stage all outstanding messages from the message table to prepare them to be sent.
        '''
        if not size:
            size = self.swnd
        # populate the unacked_packets with the next swnd chunks from the msg_table, update the ack_tracker with the sequence numbers of the chunks added to the unacked_packets
        for seqno in sorted(self.msg_table.keys())[:size]:
            if len(self.unacked_packets) < self.swnd:
                self.unacked_packets[seqno] = {}
                self.unacked_packets[seqno]['packet'] = self.msg_table.pop(seqno)
                self.unacked_packets[seqno]['time_out'] = time.monotonic() + self.timeout
                self.unacked_packets[seqno]['timeout_retransmit_limit'] = 5
                self.ack_tracker[seqno] = 0
            else:
                break
        self.base_seqno = min(self.unacked_packets.keys()) if self.unacked_packets else None
        self.debug_print(f"Populated unacked_packets with {size} chunks from msg_table. Base sequence number is now {self.base_seqno}.")

    def get_sack_seqnos(self, sack_seqnos:bytes):
        return [int(s) for s in sack_seqnos.decode("utf-8").split(',')] if sack_seqnos else []

    def sack_packets(self, sack_seqnos:list):
        # validate the ack_seqno received from the receiver, if it is in the unacked_packets, 
        # remove all cumulative acknowledgments and return the counter value for the expected sequence number, else return None
        if self.sackMode:
            print(f"Processing SACK sequence numbers: {sack_seqnos}.")
            for sack_seqno in sack_seqnos:
                self.selective_ack_packet(sack_seqno)
            self.debug_print(f"Processed SACK sequence numbers: {sack_seqnos}.")
    
    def validate_ack(self, ack_seqno:str|int, msg_type:bytes, response:bytes):
        '''
        The method is to validate received acks.
        It performs selective acknowledgements of selective acks, if sackmode is enabled.
        It then does cumulative acknowledgements after checking if the cumulative acl belongs to an unacked packet.
        '''
        largest_seq = ack_seqno - 1
        print(f"Sender.py: Validating cumulative ack {ack_seqno} for sequence no {largest_seq}.")
        response_text = response.decode("utf-8")
        expected_msg_type = "sack" if self.sackMode else "ack"
        
        # check for correct ack/sack message type from receiver, 
        # ignore and continue to wait for correct ack if no matching msg type received
        if msg_type.decode("utf-8") != expected_msg_type or not Checksum.validate_checksum(
            f"{response_text}"
        ):
            self.debug_print(f"Received invalid response: {response_text}. Ignoring and waiting for valid ACK.")
            print(f"Sender.py: [error] Incorrect message type (sack/ack mode).\r\nSender expected {expected_msg_type} from receiver, but received {msg_type.decode("utf-8")} instead.")
            return False

        # correct message type received
        self.debug_print(f"Received valid message type: {response_text}")
        
        if largest_seq in self.unacked_packets.keys() or largest_seq == self.final_seqno:
            self.debug_print(f"Valid ACK received for seqno {largest_seq}.")
            return self.cumulative_ack_packets(ack_seqno)
        else:
            self.debug_print(f"Invalid ACK {ack_seqno} received for seqno {largest_seq}. Not in unacked_packets.")
            return False

    def _cumulative_ack_tracker(self, ack_seqno:int):
        '''
        This method checks cumulative ack numbers to determine if all packets were successfully received to close the connection and app.
        It also tracks duplicate ack numbers and retransmits if triple duplicate acks occur.
        '''
        # increment the counter and check the ack_tracker if the ack_seqno counter is 3 or more, if it is, retransmit packet
        # if the counter is 3 or more, it retransmits the packet andresets the counter to 0
        # if ack covers final sequence number sent, close app
        largest_seq = ack_seqno-1
        if largest_seq == self.final_seqno:
            self.debug_print(f"Final ACK {ack_seqno} received for seqno {largest_seq}. Closing socket.")
            return True

        # if ack was for last unacked packet in unacked_packets object - tracker now empty. Populate the object with remaining packets if any
        in_queue = self.ack_tracker.get(largest_seq, None)
        if not in_queue:
            # completed, _ = self.is_file_sending_complete()
            return True

        # if not syn packer
        self.ack_tracker[largest_seq] += 1
        if self.ack_tracker[largest_seq] >= 3:
            # fast retransmit
            self.debug_print(f"ACK {ack_seqno} for seqno {largest_seq} received 3 times, retransmitting packet.")
            self.retransmit_packet(largest_seq)
        return True

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
        self.debug_print(f"Cumulative ACK {ack_seqno} received for seqno {ack_seqno-1}. Removed packets with sequence numbers less than {ack_seqno} from unacked_packets and ack_tracker.")
        self._cumulative_ack_tracker(ack_seqno)
        return True

    def selective_ack_packet(self, sack_seqno:int):
        '''
        This method performs selective acknowledgements.
        '''
        # remove the packet from the unacked_packets and ack_tracker with the sequence number equal to the sack_seqno
        if sack_seqno in sorted(self.unacked_packets.keys()):
            self.unacked_packets.pop(sack_seqno)
            self.ack_tracker.pop(sack_seqno)
            self.debug_print(f"Selective ACK received for seqno {sack_seqno}. Packet removed from unacked_packets.")
        else:
            self.debug_print(f"Selective ACK received for seqno {sack_seqno}, but packet not found in unacked_packets.")

    def send_into_window(self):
        '''
        This method manages the transmission of messages into the receiver based on the sliding window.
        '''
        print(f"Sender.py: Sending burst of packets into receiver's buffer.")
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
            return True, False
        elif self.msg_table and not self.unacked_packets:
            # all sent packets have been acknowledged, but there are still packets in the msg_table to be sent, return False
            self.debug_print("Packets in the msg_table are being staged to be sent.")
            self.populate_unacked_packets()
            # send the packets in the unacked_packets and start the retransmit timer for each packet
            self.send_into_window()
            return False, True
        elif not self.msg_table and self.unacked_packets:
            # app only needs to wait for all sent packets to be acknowledged, return False
            self.debug_print("All packets have been sent, but there are still packets in the unacked_packets to be acknowledged.")
            return False, False
        else:
            # app waits for all sent packets to be acknowledged before unacked_packets can be populated with the next swnd chunks from the msg_table, return False
            self.debug_print("There are still packets in the msg_table and unacked_packets to be sent and acknowledged.")
            return False, False # TODO: choose which method works best (False, False) or (False, True)

    def single_send(self, seqno: int):
        '''
        This method is responsible for sending a packet to the receiver.
        '''
        packet = self.unacked_packets[seqno]['packet']
        if packet is None:
            self.debug_print(f"Packet with seqno {seqno} not found in unacked_packets.")
            return

        super().send(packet)
        self.unacked_packets[seqno]['time_out'] = time.monotonic() + self.timeout
        return

    def get_ackno(self, ack_byte:bytes|str):
        return int(ack_byte) if type(ack_byte)==str else int(ack_byte.decode("utf-8"))

    def is_timed_out(self, unacked_item):
        return time.monotonic() >= unacked_item.get('time_out')
    
    def get_responses(self):
        response = self.receive(timeout=self.timeout)
        mtype,ack,chk = (None, None, None) if response is None else response.split(b"|")
        return mtype, ack, chk, response

    def get_largest(self, mtype, msg_type, ack, current_ack_value, res):
        ack_value = ack if self.get_ackno(ack) > self.get_ackno(current_ack_value) else current_ack_value
        msg_type = mtype if ack == ack_value else msg_type
        
        largest = ack_value
        largest_decoded = self.get_ackno(ack_value)
        largest_seq = largest_decoded - 1
        return ack_value, msg_type, res, largest, largest_decoded, largest_seq

    def split_sack(self, sack):
        if len(sack.split(b";")) > 1:
            ack, sack = sack.split(b";")
            sack = self.get_sack_seqnos(sack)
        else:
            ack = sack
            sack = []
        return ack, sack
    
    def handle_response(self):
        '''
        This method is responsible for logical handling of all responses from the receiver/server.
        This method tracks responses only for the burst of messages sent.
        '''
        print("Sender.py: Handling responses from sender for previous burst of packets sent.")
        end = False
        responses = {}
        response = b''
        msg_type = b''
        ack_value = b'0'
        seqnos = b''
        largest_timeout_ack = 0
        # get and save all responses
        # now = time.monotonic()
        # deadline = now + self.timeout
        count = 0

        # get expected responses from receiver/server
        while True:
            if count >= len(self.unacked_packets):
                # get as many responses as sent packets and then continue to response examination
                break

            mtype,ack,_,res = self.get_responses()

            if res is not None:
                ack, seqnos = self.split_sack(ack)
                count += 1
                ack_value,msg_type,responses[self.get_ackno(ack)],largest,largest_decoded,largest_seq= self.get_largest(mtype, msg_type, ack, ack_value, res)

                print(f"Sender.py: response received {res} for seq no {self.get_ackno(ack)-1}")
            else:
                break # response is None - i.e., time-out or packet loss.

        # check if the cumulative ack 
        if largest_seq == self.final_seqno:
            if self.validate_ack(ack, msg_type, response):
                self.unacked_packets = {}
                self.msg_table = {}
                self.ack_tracker = {}
                self.close_app()

        # Examine responses to ensure acknowledgement/reliability via responses
        end = False
        while True:
            # check if responses have been received, if not - retransmit and check against first retransmit limit
            if not len(responses):
                completed, open_receiver = self.is_file_sending_complete()
                if completed: 
                    print("All packets have been sent and acknowledged.")
                    break
                else:
                    # get response for all unacked packets, and add response to responses
                    for seqno in sorted(self.unacked_packets.keys()):
                        mtype,ack,_,res = self.get_responses()
                        if res is not None:
                            ack, seqnos = self.split_sack(ack)
                            ack_value, msg_type, responses[self.get_ackno(ack)], largest, largest_decoded, largest_seq = self.get_largest(mtype,msg_type,ack,ack_value,res)
                            print(f"Sender.py: response received {res} for seq no {self.get_ackno(ack)-1}")
                        else:
                            if self.unacked_packets[seqno]['timeout_retransmit_limit']:
                                self.retransmit_packet(seqno)
                            else:
                                print(f"Retransmit limit reached - closing app.")
                                end=True
                            break
                    if end: 
                        break
                continue

            # TODO: DONE: check if ack is invalid, if not - pop from responses and update response, and "largest" values again
            # TODO: DONE: check for retransfer limit to close app, 
            # TODO: DONE: check for time-out to re-transmit.
            try:
                # check if time-out occurred
                # cycle through "time-out limit" for each packet
                for (seqno, item) in self.unacked_packets.items():
                    # close app if retransfer limit is reached for any packet
                    if not self.unacked_packets[seqno]['timeout_retransmit_limit']: 
                        end = True
                        break
                    # set largest_changed param to later retransmit, if time-out occurs
                    if self.is_timed_out(item) and seqno > largest_seq:
                        largest_timeout_ack = seqno + 1

                if end:
                    # if retransmit limit is reached, close app
                    print("Program closing - maximum retransmission limit reached.\r\nPlease retry later!")
                    break

                # re-transmit if time-out reached for a larger expected sequence_no 
                # update response after retransmitting
                if largest_timeout_ack > self.get_ackno(ack_value):
                    success = self.retransmit_packet(largest_timeout_ack-1)
                    if success:
                        mtype,ack,_,res = self.get_responses()
                        if res is not None:
                            ack, seqnos = self.split_sack(ack)
                            ack_value,msg_type,responses[self.get_ackno(ack)],largest,largest_decoded,largest_seq = self.get_largest(mtype, msg_type, ack, ack_value, res)
                        else:
                            if self.unacked_packets[seqno]['timeout_retransmit_limit']:
                                self.retransmit_packet(seqno)
                            else:
                                print(f"Retransmit limit reached - closing app.")
                                end=True
                            break

                # check ack validity
                # check checksum, message type
                # validate/ack relevant sequence numbers
                response = responses.get(largest_decoded, None)
                ack = self.get_ackno(ack_value)
                if self.validate_ack(ack, msg_type, response):
                    # check if complete file completely sent and acknowledged via responses, 
                    # all selective acks are removed
                    self.sack_packets(seqnos)
                    for _ in seqnos:
                        responses.pop(_+1)

                    # all applicale cumulatively acknowledged unaked_packets cleared
                    # all cumulatively acknowledged responses cleared
                    for _ in sorted(responses.keys()):
                        if _ <= ack:
                            responses.pop(_)
                    
                # if not - send remaining packets and await remaining acks, else end
                if (not self.sackMode and msg_type.decode("utf-8") == "sack") \
                    or (self.sackMode and not msg_type.decode("utf-8") == "sack"):
                    print("Invalid message type - closing app.")
                    break

                self.debug_print(f"Waiting for valid/remaining ACKs. Current unacked_packets: {list(self.unacked_packets.keys())}")
                continue
            except Exception as e:
                self.debug_print(f"Error sending or receiving message: {e}. Retrying...")
                break # TODO: consider other means for handling errors without closing app with break
        # close connection and app
        print(f"Closing app")
        self.close_app()

    def retransmit_packet(self, seqno:int):
        '''
        This method is responsible for time-out and triple ack packet retransmisions.
        It enforces the use of a retransmission limit and verifies that the packet response is expected and has not yet been acknowledged
        '''
        print(f"Sender.py: Retransmitting packet with sequence nu {seqno}.")
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
        return True

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
            print(f"Error opening file: {e}")
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
