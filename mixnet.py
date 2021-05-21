import time, queue, os, struct, collections, threading, socket, sys, math, datetime, logging

MESSAGE_LENGTH = 1211
ENCRYPTED_METHOD_LENGTH = 1211 + 1212
ENVELOPE_LENGTH = 2435
PAD_LENGTH = 3635 # bytes, 1211+1212+1212
logging.basicConfig(level=logging.DEBUG)

class InvalidMac(Exception):
    pass

def xor(bytes1, bytes2):
    return bytes(a^b for a,b in zip(bytes1, bytes2))

class Mixnet():
    def __init__(self):
        dirs = ["messages-to-send", "messages-sent", "messages-received", "pads"]
        for d in dirs:
            try:
                os.mkdir(d)
            except FileExistsError:
                pass

        self.ips = {} # id -> ip
        self.names = {} # id -> human-readable name
        self.ids = {} # human-readable name -> id
        self.message_queue = {} # node_id -> [ message_bytes ]
        self.load_nodes()

        self.load_me()
        self.scheduled_envelopes = collections.defaultdict(list) # time in seconds -> [ (integer node id, envelope_bytes) ]
        self.send_queue = queue.Queue()    # (integer node id, envelope_bytes)
        self.received_queue = queue.Queue() # (float time in seconds, envelope_bytes)
        self.PERIOD = 1 # Some main loop assumptions rely on this being 1, don't adjust
        self.PORT = 17928
        self.ALLOWABLE_DRIFT = 300 # sender and receiver clock are allowed to disagree by 5 minutes
        self.FILE_CHECK_PERIOD = 10 # How often to check for new outgoing files
        self.p = 2**9689 - 1
        self.DATE_FORMAT = "%Y-%m-%d-%H:%M:%SZ"
        self.MINIMUM_TIME = 600 # 10 minutes

        self.rejected_messages = set()

    def pad_present(self, node):
        """
        Returns True if we have a pad for the node (not neccessarily current)
        """
        pad_path = "pads/{}.pad".format(node)
        date_path = "pads/{}.start-date.txt".format(node)
        if not os.path.exists(pad_path):
            return False
        return True

    def fetch_pad(self, node, ctime, as_sender):
        """
        Returns a 29066-bit cryptographic random one-time-pad (actually 3635-byte, slightly more) for immediate use.
        No pad is available, and None is returned instead if:
        - There is no pad for the given node id (they are a stranger)
        - The pad or state-date file is invalid
        - The state-date is in the future, or the pad has run out of bits.
        - The pad has already been used for transmission.

        If the pad is fetched as a sender (for transmission), the original in the file will be zeroed to prevent re-use.
        """
        if not self.pad_present(node):
            return None
        pad_path = "pads/{}.pad".format(node)
        date_path = "pads/{}.start-date.txt".format(node)
        assert os.path.exists(pad_path)
        try:
            with open(date_path, "r") as f:
                start_date_str = f.read().strip()
            start_date = datetime.datetime.strptime(start_date_str, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
        except IOError:
            logging.error("Pad {node} does not have a valid start date file.")
            return None
        pad_number = math.ceil((ctime - start_date.timestamp()) / self.PERIOD / self.MINIMUM_TIME)
        pad_number = pad_number*2 + (as_sender ^ (self.me < node)) # Every other pad is A -> B vs B -> A
        logging.debug(" Loading pad {}, {}, {}".format(ctime, pad_path, pad_number))
        with open(pad_path, ("r+b" if as_sender else "rb")) as f:
            f.seek(PAD_LENGTH*pad_number, 0)
            pad = f.read(PAD_LENGTH)
            if as_sender:
                f.seek(PAD_LENGTH*pad_number, 0)
                f.write(b'\0'*PAD_LENGTH) # zero bytes which will be used for transmission to avoid re-using them
                pass
        if pad == b'\0'*PAD_LENGTH:
            return None
        if len(pad) == 0:
            logging.warning("Pad expired: {}/{}.".format(pad_number, os.path.getsize(pad_path)/PAD_LENGTH))
            return None
        return pad

    def load_me(self, file="me.txt"):
        if not os.path.exists(file):
            logging.fatal("You need to be assigned a node ID to join the network. Visit https://za3k.com and email me to join.")
            sys.exit(0)
        with open(file) as f:
            me = f.read().strip()
            try:
                self.me = int(me) # Look up by numeric ID
                return
            except ValueError:
                try:
                    self.me = self.ids[me] # Look up by name, undocumented feature
                    return
                except KeyError:
                    logging.fatal("In me.txt, the node must EXACTLY match the id given in nodes.txt")
                    sys.exit(1)
        self.me = me

    def load_nodes(self, file=None):
        if os.path.exists("local-nodes.txt"):
            file = "local-nodes.txt"
        else:
            file = "nodes.txt"
        assert os.path.exists(file)
        nodes = []
        new_names = {}
        with open(file, "r") as f:
            for line in f:
                node, ip, name  = line.split()
                if node == "id":
                    continue
                node = int(node)
                nodes.append(node)
                if node not in self.names:
                    self.ips[node] = ip
                    new_names[node] = name
                    self.names[node] = name
                    self.ids[name] = node
                    self.message_queue[node] = queue.Queue()
        assert set(nodes) == set(range(len(nodes)))

        dirs = ["messages-to-send", "messages-sent", "messages-received"]
        for id_, name in self.names.items():
            if self.pad_present(id_):
                dirs.append("messages-to-send/{name}".format(name=name))
                dirs.append("messages-sent/{name}".format(name=name))
        for d in dirs:
            try:
                os.mkdir(d)
            except FileExistsError:
                pass

    def generate_random(self, num_bytes):
        return os.urandom(num_bytes)
    def generate_message_id(self):
        return self.generate_random(4)

    def pad_parts(self, pad_bytes):
        assert len(pad_bytes) == (1211+1212+1212)
        otp, a_bytes, b_bytes = pad_bytes[:1211], pad_bytes[1211:2423], pad_bytes[2423:]
        assert len(otp) == 1211 and len(a_bytes) == 1212 and len(b_bytes) == 1212
        a = int.from_bytes(a_bytes, byteorder='big', signed=False) >> 7 # discard the last 7 bits of the last byte
        b = int.from_bytes(b_bytes, byteorder='big', signed=False) >> 7 
        return otp, a, b

    def encrypt(self, pad_bytes, unencrypted_bytes, check=True):
        assert len(pad_bytes) == PAD_LENGTH
        assert len(unencrypted_bytes) == MESSAGE_LENGTH
        otp, a, b = self.pad_parts(pad_bytes)

        ciphertext_bytes = xor(unencrypted_bytes, otp)

        ciphertext = int.from_bytes(ciphertext_bytes, byteorder='big', signed=False)
        mac = (ciphertext * a + b) % self.p
        mac_bytes = mac.to_bytes(1212, byteorder='big')

        if check:
            assert self.decrypt(pad_bytes, ciphertext_bytes+mac_bytes, check=False) == unencrypted_bytes
        envelope_bytes = ciphertext_bytes + mac_bytes
        assert len(envelope_bytes) == ENCRYPTED_METHOD_LENGTH
        return envelope_bytes

    def decrypt(self, pad_bytes, encrypted_bytes, check=True):
        """
        Returns either plaintext, or None indiciating the mac failed.
        """
        assert len(pad_bytes) == PAD_LENGTH
        assert len(encrypted_bytes) == ENCRYPTED_METHOD_LENGTH

        otp, a, b = self.pad_parts(pad_bytes)
        ciphertext_bytes, mac_bytes = encrypted_bytes[:1211], encrypted_bytes[1211:]

        plaintext_bytes = xor(ciphertext_bytes, otp)

        ciphertext = int.from_bytes(ciphertext_bytes, byteorder='big', signed=False)
        expected_mac = (ciphertext * a + b) % self.p
        expected_mac_bytes = expected_mac.to_bytes(1212, byteorder='big')

        if mac_bytes != expected_mac_bytes:
            logging.debug("{} {} {}".format(mac_bytes[:10], expected_mac_bytes[:10], plaintext_bytes[:10]))
            raise InvalidMac()
        if check:
            assert self.encrypt(pad_bytes, plaintext_bytes, check=False) == ciphertext_bytes + mac_bytes

        assert len(plaintext_bytes) == MESSAGE_LENGTH
        return plaintext_bytes

    def make_friend_data_envelope(self, ctime, node, pad, message_bytes):
        return struct.pack("!LLL", self.me, node, ctime) + self.encrypt(pad, message_bytes)

    def make_friend_chaff_envelope(self, ctime, node, pad):
        return self.make_friend_data_envelope(ctime, node, pad, b'C' + b"\0"*1210)

    def make_stranger_chaff_envelope(self, ctime, node):
        return struct.pack("!LLL", self.me, node, ctime) + self.generate_random(1211+1212)

    def do_work(self, ctime):
        node = (ctime + self.me) % max(len(self.ids), self.MINIMUM_TIME)
        logging.debug(" Doing work for node {}".format(node))
        if node == self.me:
            logging.debug(" Skipping self")
            return
        if node not in self.names: # actually a list of ids, because it's the keys
            logging.debug(" Skipping blank slot... small N")
            return
        pad = self.fetch_pad(node, ctime, as_sender=True)
        if pad is None:
            logging.debug(" Making chaff for stranger ({})".format(node))
            envelope_bytes = self.make_stranger_chaff_envelope(ctime, node)
        else:
            queue = self.message_queue[node]
            if queue.empty():
                logging.debug(" Making chaff for friend ({})".format(node))
                envelope_bytes = self.make_friend_chaff_envelope(ctime, node, pad)
            else:
                logging.info(" Packing data for friend ({})".format(node))
                message_bytes = queue.get()
                assert isinstance(message_bytes, bytes)
                assert len(message_bytes) == MESSAGE_LENGTH
                envelope_bytes = self.make_friend_data_envelope(ctime, node, pad, message_bytes)
        assert isinstance(envelope_bytes, bytes)
        assert len(envelope_bytes) == ENVELOPE_LENGTH
        self.schedule_send_raw_bytes(node, envelope_bytes, ctime)

    def load_outgoing_messages(self):
        for name in os.listdir("messages-to-send"):
            node = self.ids.get(name)
            if node is None:
                logging.debug("directory found in messages-to-send, expected the dir name to be a node name: {}".format(name))
                continue
            for filename in os.listdir(os.path.join("messages-to-send", name)):
                logging.info("  Found outgoing file {}, goes to node {}...".format(filename, node))
                subpath = os.path.join(name, filename)
                with open("messages-to-send/{}".format(subpath), "rb") as f:
                    os.rename("messages-to-send/{}".format(subpath), "messages-sent/{}".format(subpath))
                    content = f.read()
                logging.debug("  Read file contents...")

                messages = self.make_messages(content)
                for i, message in enumerate(messages):
                    assert len(message)==MESSAGE_LENGTH
                    logging.warning("Added {}/{} to message queue ({}/{}).".format(node, filename, i+1, len(messages)))
                    self.message_queue[node].put(message)

    def make_messages(self, content):
        message_id = self.generate_message_id()
        if len(content) <= 1000:
            return [b'M' + message_id + struct.pack("!H", len(content)) + content + b'\0'*(1204-len(content))]
        else:
            num_parts = math.ceil(len(content)/1000)
            partials = []
            for part_num in range(num_parts):
                part_content = content[1000*part_num:1000*(part_num+1)]
                partial = b'P' + message_id + struct.pack("!HLL", len(part_content), num_parts, part_num) + part_content
                partial += b'\0'*(MESSAGE_LENGTH-len(partial))
                partials.append(partial)
            return partials

    def receive_loop(self):
        logging.debug("Receive loop starting...")
        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversocket.bind(("0.0.0.0", self.PORT))
        serversocket.listen()
        while True:
            logging.debug("Waiting for client connections...")
            (clientsocket, address) = serversocket.accept()
            ct = threading.Thread(target=self.receive_thread, args=(clientsocket,))
            ct.run()
    def receive_thread(self, clientsocket, MSGLEN=ENVELOPE_LENGTH):
        chunks = []
        bytes_recd = 0
        while bytes_recd < MSGLEN:
            chunk = clientsocket.recv(MSGLEN - bytes_recd)
            if chunk == b'':
                raise RuntimeError("recv socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        envelope = b''.join(chunks)
        assert len(envelope) == MSGLEN
        self.received_queue.put((time.time(), envelope))
        logging.debug("Received some raw bytes")
    def process_raw_envelope(self, ctime, envelope_bytes):
        sender, receiver, claimed_time, message_bytes = *struct.unpack("!LLL", envelope_bytes[:12]), envelope_bytes[12:]
        if receiver != self.me:
            logging.error("MALICIOUS: message received with receiver != me. discarding.")
            return
        elif abs(claimed_time - ctime) > self.ALLOWABLE_DRIFT:
            logging.info("message receive which significantly disagrees on the current time (from {}). discarding.".format(sender)) # TODO: raise to 'warning' from friends
            return

        pad = self.fetch_pad(sender, claimed_time, as_sender=False)
        if pad is None:
            logging.debug("discarding stranger chaff (from {})".format(sender))
            return
        try:
            result = self.decrypt(pad, message_bytes)
        except InvalidMac:
            logging.error("MALICIOUS: invalid pad received from a friend (from {}).".format(sender))
            return
        self.process_message_bytes(ctime, result, sender)
    def process_message_bytes(self, ctime, message_bytes, sender):
        logging.debug(" receieved authenticated message (from {})...".format(sender))
        if message_bytes[0:1] == b"C":
            logging.debug(" discarding friend chaff (from {})".format(sender))
        # TODO: check for duplicate message ids and report an error instead of overwriting
        elif message_bytes[0:1] == b"M":
            logging.info(" received message (from {})".format(sender))
            message_id, length = message_bytes[1:5], *struct.unpack("!H", message_bytes[5:7])
            content = message_bytes[7:7+length]
            self.process_message(ctime, message_id, content, sender)
        # TODO: process multi-part messages more properly (ex. out of order)
        elif message_bytes[0:1] == b"P":
            message_id, length, num_parts, part_num = message_bytes[1:5], *struct.unpack("!HLL", message_bytes[5:15])
            logging.info(" received multipart message (from {}, {}/{})".format(sender, part_num, num_parts))
            content = message_bytes[15:15+length]
            self.process_message(ctime, message_id, content, sender, append=True, final=(num_parts==part_num+1)) # Could be multiple messages with same ID
        else:
            logging.warning(" recieved unknown message type {}. discarding. (from {})".format(message_bytes[0:1], sender))
    def process_message(self, ctime, message_id, content, sender, append=False, final=True):
        datestr = datetime.datetime.fromtimestamp(ctime).strftime(self.DATE_FORMAT)
        filename = "messages-received/{}-{}-{}.txt".format(datestr, self.names[sender], message_id.hex())
        if append:
            in_progress_filename = "messages-received/{}-{}.txt.partial".format(self.names[sender], message_id.hex())
            with open(in_progress_filename, "ab") as f:
                f.write(content)
            logging.warning("Partial message from {} saved as {}".format(self.names[sender], in_progress_filename))
            if final:
                os.rename(in_progress_filename, filename)
                logging.warning("Multipart message from {} saved as {}".format(self.names[sender], filename))
        else:
            with open(filename, "wb") as f:
                f.write(content)
            logging.warning("Message from {} saved as {}".format(self.names[sender], filename))

    def send_loop(self):
        while True:
            node, envelope_bytes = self.send_queue.get()
            # Could be done in parallel, not really needed though.
            self.send_raw_bytes(self.ips[node], envelope_bytes)
    def schedule_send_raw_bytes(self, node, raw_bytes, at_time):
        logging.debug(" Scheduling send...")
        self.scheduled_envelopes[at_time].append(
            [node, raw_bytes]
        )
    def send_raw_bytes(self, ip, envelope_bytes):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((ip, self.PORT))
            totalsent = 0
            while totalsent < len(envelope_bytes):
                sent = sock.send(envelope_bytes[totalsent:])
                if sent == 0:
                    raise RuntimeError("send socket connection broken")
                totalsent += sent
        except ConnectionRefusedError:
            logging.info("Connection refused: {}:{}".format(ip, self.PORT))
            return
        finally:
            sock.close()

    def main(self):
        # Start a receive thread
        threading.Thread(target=self.receive_loop, daemon=True).start()
        # Start a send thread. Arguably could be in the main loop.
        threading.Thread(target=self.send_loop, daemon=True).start()
        self.main_loop()

    def main_loop(self):
        last_scheduled_send = int(time.time())
        last_sent = 0
        last_file_check = 0

        while True:
            logging.debug("Work loop...")
            logging.debug("Send queue size: {}".format(self.send_queue.qsize()))
            logging.debug("Received queue size: {}".format(self.received_queue.qsize()))
            logging.debug("Scheduled set size: {}".format(sum(len(a) for a in self.scheduled_envelopes.values())))
            logging.debug("Message queue size: {}".format(sum(a.qsize() for a in self.message_queue.values())))
            now = time.time()

            # Check for scheduled sends
            logging.debug(" Checking for scheduled sends...")
            for ctime in sorted(self.scheduled_envelopes.keys()):
                if ctime <= now:
                    messages = self.scheduled_envelopes.pop(ctime)
                    for m in messages:
                        logging.debug(" Adding to send queue...")
                        self.send_queue.put(m)

            # Process received messages
            logging.debug(" Processing received messages...")
            try:
                while True:
                    received_time, envelope_bytes = self.received_queue.get(block=False)
                    self.process_raw_envelope(received_time, envelope_bytes)
            except queue.Empty:
                pass

            # Do work for upcoming period, plus any delinquent. This is done in advance to avoid timing attacks based on the processing time.
            logging.debug(" Doing work...")
            for ctime in range(last_scheduled_send+1, int(now)+1):
                logging.debug(" Doing work for {}".format(ctime))
                self.do_work(ctime)
                last_scheduled_send = ctime

            # Periodically check for new files to send out also.
            if last_file_check + self.FILE_CHECK_PERIOD <= now:
                logging.info(" Checking for new outgoing files...")
                last_file_check = now
                self.load_nodes() # Reload nodes.txt periodically
                self.load_outgoing_messages()

            # Check back in at the start of next period
            target = math.ceil(now)
            now2 = time.time()
            if now2 >= target:
                logging.warning("Processing taking too long.")
                continue
            logging.debug(" Sleeping...")
            time.sleep(target - now2)

if __name__ == "__main__":
    mix = Mixnet()
    mix.main()
