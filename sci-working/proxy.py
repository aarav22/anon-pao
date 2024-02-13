import socket
import time
# import ssl
import logging
import sys
import select
import subprocess

import constants
import random, string, pickle

import customSHA256
import time

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)-8s - %(message)s', filename='proxy.log')
logger = logging.getLogger(__name__)

class SessionTerminatedException(Exception):pass
class ProtocolViolationException(Exception):pass


class TcpSockBuff(object):
    ''' Wrapped Tcp Socket with access to last sent/received data '''
    def __init__(self, sock, peer=None):
        self.socket = None
        self.socket_ssl = None
        self.recvbuf = ''
        self.sndbuf = ''
        self.peer = peer
        self._init(sock)

    def _init(self, sock):
        self.socket = sock

    def connect(self, target=None):
        target = target or self.peer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.socket.connect(target)

    def accept(self):
        return self.socket.accept()

    def recv(self, buflen=8*1024, *args, **kwargs):
        if self.socket_ssl:
            chunks = []
            chunk = True
            data_pending = buflen
            while chunk and data_pending:
                chunk = self.socket_ssl.read(data_pending)
                chunks.append(chunk)
                data_pending = self.socket_ssl.pending()
            self.recvbuf = ''.join(chunks)
        else:
            self.recvbuf = self.socket.recv(buflen, *args, **kwargs)
        return self.recvbuf


    def sendall(self, data):
        self.socket.sendall(data)
        self.sndbuf = data



class Session(object):
    ''' Proxy session from client <-> proxy <-> server
        @param inbound: inbound socket
        @param outbound: outbound socket
        @param target: target tuple ('ip',port)
        @param buffer_size: socket buff size'''

    def __init__(self, proxy, inbound=None, outbound=None, target=None, buffer_size=4096):
        self.proxy = proxy
        self.bind = proxy.getsockname()
        self.inbound = TcpSockBuff(inbound)
        self.outbound = TcpSockBuff(outbound, peer=target)
        self.buffer_size = buffer_size
        self.datastore = {}
        self.drop_mode = constants.DROP_MODES[2] # none

    def __repr__(self):
        return "<Session %s [client: %s] --> [prxy: %s] --> [target: %s]>"%(hex(id(self)),
                                                                            self.inbound.peer,
                                                                            self.bind,
                                                                            self.outbound.peer)
    def __str__(self):
        return "<Session %s>"%hex(id(self))

    def connect(self, target):
        self.outbound.peer = target
        logger.info("%s connecting to target %s"%(self, repr(target)))
        return self.outbound.connect(target)

    def accept(self):
        sock, addr = self.proxy.accept()
        self.inbound = TcpSockBuff(sock)
        self.inbound.peer = addr
        logger.info("%s client %s has connected"%(self,repr(self.inbound.peer)))
        return sock,addr

    def get_peer_sockets(self):
        return [self.inbound.socket, self.outbound.socket]

    def notify_read(self, sock):

        if sock == self.proxy:
            self.accept()
            self.connect(self.outbound.peer)
        elif sock == self.inbound.socket:
            # new client -> prxy - data
            self.on_recv_peek(self.inbound, self)
            self.on_recv(self.inbound, self.outbound, self, who="client")
        elif sock == self.outbound.socket:
            # new sprxy <- target - data
            self.on_recv(self.outbound, self.inbound, self, who="server")

        return


    def close(self):
        try:
            self.outbound.socket.shutdown(2)
            self.outbound.socket.close()
            self.inbound.socket.shutdown(2)
            self.inbound.socket.close()
        except socket.error as se:
            logger.warning("session.close(): Exception: %s"%repr(se))
        raise SessionTerminatedException()

    def on_recv(self, s_in, s_out, session, who="server"):
        data = s_in.recv(session.buffer_size)
        msg = data

        if who == "client":
            # check START MSG
            if constants.bSTART_MSG in msg:
                s_in.sendall(b'OK')
                print('START OF BLIND CERTIFICATE PROTOCOL')

                # receive the next message from the client
                msg = s_in.recv(session.buffer_size)
                deserialized_c_msg = pickle.loads(msg)
                print('START OF MESSAGE')
                print(f'client says Desrialized Msg is {deserialized_c_msg}')

                m_p2 = deserialized_c_msg['m_p2']
                m_s1 = deserialized_c_msg['m_s1']
                h = deserialized_c_msg['h']

                # 32 bytes string: M_star
                n = 32
                m_star = ''.join(random.choices(string.ascii_letters + string.digits, k=n)).encode('ascii')

                hashObj = customSHA256.Sha256()
                hashObj.h = h
                print(f'len(m_p2 + m_star + m_s1): {len(m_p2 + m_star + m_s1)}')
                hashObj.update(m_p2 + m_star + m_s1)
                h = hashObj.h

                print(f'The hash-s h is {h}')
                # send the m_star:
                print(f'The m_star is {m_star}')

                send_material = {'h': h}
                serialized_send_material = pickle.dumps(send_material)
                s_in.sendall(serialized_send_material)

                # receive the next message from the client

                # this is enc_data (IV (tls one, not AES) + m_p),
                # chaining_block, and key (AES key)
                #  TODO: don't have the key
                c_msg = s_in.recv(session.buffer_size)

                deserialized_c_msg = pickle.loads(c_msg)
                print(f'client says Desrialized Msg is {deserialized_c_msg}')

                IV = deserialized_c_msg['aes_chainaing']
                enc_data = deserialized_c_msg['enc_data']


                # xor the m_star with the chaining block
                xor_bytes = bytes([a ^ b for a, b in zip(IV, m_star)])
                out = subprocess.getoutput("./bin/test_aes 2 12345 "+xor_bytes.hex()+ "00000000000000000000000000000000"+ " 0.0.0.0")

                ct_binary = out.split("\n")[-1] # this is in 0s and 1s
                ct = int(ct_binary, 2).to_bytes(len(ct_binary) // 8, byteorder='big')
                xor_bytes = bytes([a ^ b for a, b in zip(ct, m_star[16:])])

                out_2 = subprocess.getoutput(f"./bin/test_aes 2 12345 "+ xor_bytes.hex() + "00000000000000000000000000000000"+" 0.0.0.0")
                ct_binary_2 = out_2.split("\n")[-1]
                ct_2 = int(ct_binary_2, 2).to_bytes(len(ct_binary_2) // 8, byteorder='big')

                new_enc_data = ct + ct_2
                new_chain_block = ct_2

                print(f'new_enc_data={new_enc_data}')

                # send the new_chain_block
                send_material = {'new_chain_block': new_chain_block}
                serialized_send_material = pickle.dumps(send_material)
                s_in.sendall(serialized_send_material)

                # recv the next message from the client
                c_msg = s_in.recv(session.buffer_size)
                deserialized_c_msg = pickle.loads(c_msg)
                newer_enc_data = deserialized_c_msg['enc_data']
                final_enc_data = enc_data + new_enc_data + newer_enc_data

                print(f'enc_data: {enc_data}')
                print(f'new_enc_data: {new_enc_data}')
                print(f'newer_enc_data: {newer_enc_data}')
                print(f'final_enc_data={final_enc_data}')
                # intercept the mail and send it to the server
                c_msg = s_in.recv(session.buffer_size)
                # data = c_msg

                # copy the first 5 bytes of the mail
                tls_header = c_msg[:5] # this is the tls header
                # adjust the length of the tls header
                len_new_mail = len(final_enc_data)
                tls_header = tls_header[:3] + len_new_mail.to_bytes(2, 'big')

                new_mail = tls_header + final_enc_data
                c_msg = new_mail

                data = c_msg

        if not len(data):
            return session.close()
        if s_in == session.inbound:
            data = self.mangle_client_data(session, data)
        elif s_in == session.outbound:
            data = self.mangle_server_data(session, data)
        if data:
            s_out.sendall(data)
        return data

    def on_recv_peek(self, s_in, session): pass
    def mangle_client_data(self, session, data):
        logger.debug("%s [client] => [server]          %s"%(session,repr(data)))
        return data

    def mangle_server_data(self, session, data):
        logger.debug("%s [client] <= [server]          %s"%(session,repr(data)))
        return data

class ProxyServer(object):
    '''Proxy Class'''

    def __init__(self, listen, target, buffer_size=4096, delay=0.0001):
        self.input_list = set([])
        self.sessions = {}  # sock:Session()
        self.callbacks = {} # name: [f,..]
        #
        self.listen = listen
        self.target = target
        #
        self.buffer_size = buffer_size
        self.delay = delay
        self.bind = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind.bind(listen)
        self.bind.listen(200)

    def __str__(self):
        return "<Proxy %s listen=%s target=%s>"%(hex(id(self)),self.listen, self.target)

    def get_session_by_client_sock(self, sock):
        return self.sessions.get(sock)

    def set_callback(self, name, f):
        self.callbacks[name] = f


    def main_loop(self):
        self.input_list.add(self.bind)
        while True:
            time.sleep(self.delay)
            inputready, _, _ =  select.select(self.input_list, [], [])

            for sock in inputready:
                if not sock in self.input_list:
                    # Check if inputready sock is still in the list of socks to read from
                    # as SessionTerminateException might remove multiple sockets from that list
                    # this might otherwise lead to bad FD access exceptions
                    continue
                session = None
                try:
                    if sock == self.bind:
                        # on_accept
                        session = Session(sock, target=self.target)
                        # for k,v in self.callbacks.items():
                        #     setattr(session, k, v)
                        session.notify_read(sock)
                        for s in session.get_peer_sockets():
                            self.sessions[s]=session
                        self.input_list.update(session.get_peer_sockets())

                    else:
                        # on_recv
                        try:
                            session = self.get_session_by_client_sock(sock)
                            session.notify_read(sock)
                        # except ssl.SSLError as se:
                        #     if se.errno != ssl.SSL_ERROR_WANT_READ:
                        #         raise
                        #     continue
                        except SessionTerminatedException:
                            self.input_list.difference_update(session.get_peer_sockets())
                            logger.warning("%s terminated."%session)

                except Exception as e:
                    logger.error("main: %s"%repr(e))

                    if session:
                        logger.error("main: removing all sockets associated with session that raised exception: %s"%repr(session))
                        try:
                            session.close()
                        except SessionTerminatedException: pass
                        self.input_list.difference_update(session.get_peer_sockets())
                    elif sock and sock!=self.bind:
                        # exception for non-bind socket - probably fine to close and remove it from our list
                        logger.error("main: removing socket that probably raised the exception")
                        sock.close()
                        self.input_list.remove(sock)
                    else:
                        # this is just super-fatal - something happened while processing our bind socket.
                        raise


def main():
    from optparse import OptionParser
    ret = 0
    usage = """usage: %prog [options]

       example: %prog --listen 0.0.0.0:25 --remote mail.server.tld:25
    """
    parser = OptionParser(usage=usage)
    parser.add_option("-q", "--quiet",
                  action="store_false", dest="verbose", default=True,
                  help="be quiet [default: %default]")
    parser.add_option("-l", "--listen", dest="listen", help="listen ip:port [default: 0.0.0.0:<remote_port>]")
    parser.add_option("-r", "--remote", dest="remote", help="remote target ip:port to forward sessions to")
    parser.add_option("-k", "--key", dest="key", default="server.pem", help="SSL Certificate and Private key file to use, PEM format assumed [default: %default]")
    parser.add_option("-s", "--generic-ssl-intercept",
                  action="store_true", dest="generic_tls_intercept", default=False,
                  help="dynamically intercept SSL/TLS")
    parser.add_option("-b", "--bufsiz", dest="buffer_size", type="int", default=4096)

    all_vectors = []

    parser.add_option("-x", "--vectors",
                  default="ALL",
                  help="Comma separated list of vectors. Use 'ALL' (default) to select all vectors, 'NONE' for tcp/ssl proxy mode."
                  " [default: %default]")
    # parse args
    (options, args) = parser.parse_args()
    # normalize args
    if not options.verbose:
        logger.setLevel(logging.INFO)
    if not options.remote:
        parser.error("mandatory option: remote")
    if ":" not in options.remote and ":" in options.listen:
        # no port in remote, but there is one in listen. use this one
        options.remote = (options.remote.strip(), int(options.listen.strip().split(":")[1]))
        logger.warning("no remote port specified - falling back to %s:%d (listen port)"%options.remote)
    elif ":" in options.remote:
        options.remote = options.remote.strip().split(":")
        options.remote = (options.remote[0], int(options.remote[1]))
    else:
        parser.error("neither remote nor listen is in the format <host>:<port>")
    if not options.listen:
        logger.warning("no listen port specified - falling back to 0.0.0.0:%d (remote port)"%options.remote[1])
        options.listen = ("0.0.0.0",options.remote[1])
    elif ":" in options.listen:
        options.listen = options.listen.strip().split(":")
        options.listen = (options.listen[0], int(options.listen[1]))
    else:
        options.listen = (options.listen.strip(), options.remote[1])
        logger.warning("no listen port specified - falling back to %s:%d (remote port)"%options.listen)
    options.vectors = [o.strip() for o in options.vectors.strip().split(",")]
    if 'NONE' in (v.upper() for v in options.vectors):
        options.vectors = []


    # ---- start up engines ----
    prx = ProxyServer(listen=options.listen, target=options.remote,
                      buffer_size=options.buffer_size, delay=0)
    logger.info("%s ready."%prx)
    # rewrite = RewriteDispatcher(generic_tls_intercept=options.generic_tls_intercept)

    # for classname in options.vectors:
    #     try:
    #         proto, vector = classname.split('.',1)
    #         cls_proto = getattr(globals().get("Vectors"),proto)
    #         cls_vector = getattr(cls_proto, vector)
    #         rewrite.add(cls_proto._PROTO_ID, cls_vector)
    #         logger.debug("* added vector (port:%-5s, proto:%8s): %s"%(cls_proto._PROTO_ID, proto, repr(cls_vector)))
    #     except Exception as e:
    #         logger.error("* error - failed to add: %s"%classname)
    #         parser.error("invalid vector: %s"%classname)

    # logging.info(repr(rewrite))
    # prx.set_callback("mangle_server_data", rewrite.mangle_server_data)
    # prx.set_callback("mangle_client_data", rewrite.mangle_client_data)
    # prx.set_callback("on_recv_peek", rewrite.on_recv_peek)
    # import cProfile, pstats, io
    # from pstats import SortKey
    # pr = cProfile.Profile()
    # pr.enable()
    try:
        prx.main_loop()
    except KeyboardInterrupt:
        logger.warning( "Ctrl C - Stopping server")
        ret+=1
    # pr.disable()
    # s = io.StringIO()
    # sortby = SortKey.CUMULATIVE
    # ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    # ps.dump_stats("proxy.txt")
    # print(s.getvalue())

    # logger.info(" -- audit results --")
    # for client,resultlist in rewrite.get_results_by_clients().items():
    #     logger.info("[*] client: %s"%client)
    #     for mangle, result in resultlist:
    #         logger.info("    [%-11s] %s"%("Vulnerable!" if result else " ",repr(mangle)))

    sys.exit(ret)

if __name__ == '__main__':
    main()