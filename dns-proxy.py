#!/usr/bin/env python3

import logging
import select
import socket
import struct
import sys
import time
from argparse import ArgumentParser
from configparser import ConfigParser
from dataclasses import dataclass
from io import BytesIO
from socketserver import ThreadingUDPServer, BaseRequestHandler
from threading import Thread


VERSION = '0.1.2'


@dataclass
class Question:
    qname: bytes
    qtype: int
    qclass: int

    def to_tup(self):
        return (self.qname, self.qtype, self.qclass)


@dataclass
class CacheEntry:
    resp: bytes
    added: int  # timestamp

    def get_resp_questions(self):
        pass

class Cache:
    def __init__(self):
        self._cache = {}

    def get(self, request):
        """
        This will check to see if there's a cached answer to be returned, or
        None.
        """
        question = self._parse_req(request)

        if question.to_tup() not in self.cache:
            # Return quickly if it's not in the cache
            return None

        entry = self.cache[question.to_tup()]
        upd_resp = self._update_response(entry)


    def _parse_req(self, request):
        """
        Parse out the qname, the qtype, and class from the question
        """
        req = BytesIO(request)
        # Skip to the question section
        req.seek(12)

        question = DNSProxyHandler.get_question(req)

        return question

    def _update_response(self, ce: CacheEntry):
        ttl = self._get_ttl(ce.resp)

    def _to_int(self, bytes_):
        return int.from_bytes(bytes_, 'big')


class DNSConfig(ConfigParser):
    _dns_map = None

    def read(self, *args, **kwargs):
        super().read(*args, **kwargs)
        # Cache the dns map
        self.get_dns_map()

    def get_dns_map(self):
        if self._dns_map is not None:
            return self._dns_map

        self._dns_map = {}
        for section in self.sections():
            if section.startswith('dns:'):
                _, domain = section.split(':', maxsplit=1)
                upstreams = self[section]['upstreams'].strip().split()
                self._dns_map[domain] = upstreams

    def get_default_upstreams(self):
        return self.get('main', 'upstream_dns').strip().split()

    def get_upstreams(self, domain):
        """
        Check to see if the domain is in the dns map and return the custom
        upstreams, otherwise return the default upstreams
        """
        # First, check for an empty dns map and just return the
        # defaults
        def_upstreams = self.get_default_upstreams()
        if not self._dns_map:
            return def_upstreams

        res = self.get_custom_sect(domain)
        if res is None:
            # No matches
            return def_upstreams

        section, dom = res

        if (self.getboolean(section, 'fallback') and
            self.getboolean(section, 'fallen_back')
        ):
            # If fallback is on and we've fallen back, return the
            # default upstreams
            return def_upstreams

        return self._dns_map[dom]

    def get_custom_sect(self, domain):
        """
        Get the section matching a given domain
        """
        if isinstance(domain, (bytes, bytearray)):
            domain = domain.decode('utf-8')

        parts = domain.split('.')

        for i in range(len(parts)):
            # Go through the domain, searching from most specific to
            # least specific
            chk = '.'.join(parts[i:])
            if chk in self._dns_map:
                if self.getboolean(f'dns:{chk}', 'exact') and chk != domain:
                    # If this check requires an exact match and it doesn't
                    # match the full domain name, we skip it
                    logging.debug(
                        'Skipping domain check requiring an exact '
                        f'match: {domain} != {chk}'
                    )
                    continue

                # Return a convenience tuple of (<section>, <domain>)
                return (f'dns:{chk}', chk)

        return None


class RetryThread(Thread):
    # This is the base of a check for response
    _sample_query = (
        b'>\x0b\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x06google\x03com\x00'
        b'\x00\x01\x00\x01\x00\x00)\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\n'
        b'\x00\x08r\x88\x96\x84\xea\xb8\x0f5'
    )

    def __init__(self, *args, **kwargs):
        self.conf = kwargs['conf']
        del kwargs['conf']
        super().__init__(*args, **kwargs)

        self._retry_int = self.conf.getint('main', 'fallback_retry')
        self.daemon = True

    def run(self):
        while True:
            for sect in self.conf.sections():
                if (sect.startswith('dns:') and
                    self.conf.getboolean(sect, 'fallen_back')
                ):
                    try:
                        self._check_upstreams(sect)
                    except Exception as e:
                        logging.warning(
                            'An error occurred in the retry thread '
                            'rechecking upstreams: {e}'
                        )

            time.sleep(self._retry_int)

    def _check_upstreams(self, section):
        """
        We basically just re-use a method in the DNSProxyHandler here
        """
        timeout = self.conf.getint('main', 'upstream_timeout')
        upstreams = self.conf[section]['upstreams'].strip().split()
        # TODO: randomize the id in the sample query
        socks, ep = DNSProxyHandler.send_and_get_epoll(
            self._sample_query,
            upstreams,
            timeout,
        )

        ready = ep.poll(timeout)
        if not ready:
            # Still dead
            logging.warning(
                f'Upstreams ({", ".join(upstreams)}) for '
                f'{section.split(":")[1]} are down'
            )
        else:
            # We have a response from one or more upstreams
            self.conf[section]['fallen_back'] = 'false'

        DNSProxyHandler.close_all(socks.values())

        ep.close()


class DNSProxyHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        logging.debug(f'got data: {data}')

        qname = self._get_qname(data)
        upstreams = self.server.conf.get_upstreams(qname)

        resp = self._proxy_to_upstreams(data, upstreams, qname)

        sock.sendto(resp, self.client_address)

    def _proxy_to_upstreams(self, data, upstreams, qname):
        """
        Here, we will send to all upstreams and take the first answer
        we get, which will be quite fast
        """
        socks, ep = self.send_and_get_epoll(
            data,
            upstreams,
            self.server.conf.getint('main', 'upstream_timeout'),
        )

        # Poll until timeout or a response from an upstream
        ready = ep.poll(self.server.conf.getint('main', 'upstream_timeout'))
        if not ready:
            logging.debug('Failed to get response from any server')
            logging.warning(f'Upstreams, {", ".join(upstreams)}, are down')
            # We check for a custom setup for this and fall back to
            # defaults if necessary
            res = self.server.conf.get_custom_sect(qname)
            if (res is not None and
                self.server.conf.getboolean(res[0], 'fallback')
            ):
                logging.warning(f'Falling back to defaults for {res[1]}')
                self.server.conf[res[0]]['fallen_back'] = 'true'
                # Fallback to the default upstreams
                return self._proxy_to_upstreams(
                    data,
                    self.server.conf.get_default_upstreams(),
                    qname,
                )

            # TODO: return a real timeout response
            return b''

        for fd, _ in ready:
            resp = socks[fd].recv(65535)
            remote = socks[fd].getpeername()
            logging.debug(f'Received response for {qname} from {remote}')

            # As soon as we get a response from a server, just close
            # all the sockets and break out of the loop
            self.close_all(socks.values())
            break

        # Finally, close the epoll object
        ep.close()

        return resp

    @staticmethod
    def send_and_get_epoll(data, upstreams, timeout):
        """
        This will send the data specified to all upstreams and return
        a tuple of a dict mapping socket fd -> socket and the epoll object
        """
        socks = {}
        ep = select.epoll(len(upstreams))
        for upstream in upstreams:
            fam = socket.AF_INET6 if ':' in upstream else socket.AF_INET
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((upstream, 53))

            logging.debug(f'Sending request to {upstream}')
            # Set the timeout on the socket
            sock.settimeout(timeout)
            # Set this to a non-blocking operation on send
            sock.sendall(data, socket.MSG_DONTWAIT)
            # Update the mapping of fd -> sock object
            socks[sock.fileno()] = sock

            ep.register(sock.fileno(), select.EPOLLIN)

        return (socks, ep)

    @staticmethod
    def close_all(items):
        """
        Iterate through the list of items and call close on them
        """
        for item in items:
            try:
                item.close()
            except Exception as e:
                logging.warning(f'Error closing socket: {e}')


    def _get_qname(self, req_data):
        """
        Take the incoming request data and pase the qname from it to
        determine if we forward to a different upstream instead of
        the defaults
        """
        # The BytesIO just makes moving the pointer much easier
        data = BytesIO(req_data)
        # Skip to the question
        data.seek(12)

        q = self.get_question(data)

        return q.qname

    @classmethod
    def get_question(cls, data):
        labels = []

        llen = self._to_int(data.read(1))  # 1st label len
        while llen > 0:
            if llen < 64:
                # Standard question
                cur_qname += b'.' + data.read(llen)
                llen = self._to_int(data.read(1))
            else:
                # domain name compression
                llen = llen & 0x3f
                offset = (llen << 8) + self._to_int(data.read(1))

                # Create a copy of the entire message to recurse
                msg_copy = BytesIO(data.get_value())
                msg_copy.seek(offset)

                labels.extend(self._parse_labels(msg_copy))
                return labels

        ret = Question(
            qname=b'.'.join(labels),
            qtype=self.to_int(data.read(2)),
            qclass=self.to_int(data.read(2)),
        )

        return ret

    @staticmethod
    def to_int(bytes_):
        return int.from_bytes(bytes_, 'big')


class DNSProxyServer(ThreadingUDPServer):
    def __init__(self, *args, **kwargs):
        # Grab and store the configuration arg
        self.conf = kwargs['conf']
        del kwargs['conf']
        # And finally, call the upstream method
        super().__init__(*args, **kwargs)


def get_args():
    desc = (
        'A simple DNS proxy with support for custom servers on a per '
        'domain basis'
    )
    p = ArgumentParser(description=desc)
    p.add_argument('-c', '--config', default='dns.ini',
        help='The path to the config file: [default: %(default)s]')
    p.add_argument('-V', '--version', action='store_true', default=False,
        help='Print the version and exit [default: %(default)s]')
    p.add_argument('-D', '--debug', action='store_true', default=False,
        help='Add debug output [default: %(default)s]')

    args = p.parse_args()

    if args.version:
        import os.path
        print(f'{os.path.basename(sys.argv[0])}: {VERSION}')
        sys.exit(0)

    return args


def setup_logging(args):
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        format=(
            '%(asctime)s - %(levelname)s - '
            '%(filename)s:%(lineno)d %(funcName)s - %(message)s'
        ),
        level=level,
    )

def get_conf(args):
    config = DNSConfig()
    config.read(args.config)

    return config


def main():
    args = get_args()
    setup_logging(args)
    conf = get_conf(args)

    retry_thread = RetryThread(conf=conf)
    retry_thread.start()

    with DNSProxyServer(
        (conf['main']['bind_addr'], conf.getint('main', 'bind_port')),
        DNSProxyHandler,
        conf=conf
    ) as server:
        server.serve_forever()

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
