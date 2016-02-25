# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2015, IBM
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations

import argparse
import atexit
import logging
import os
import Queue
import re
import signal
import SocketServer
import sqlite3
import stat
import struct
import subprocess
import sys
import threading

from sshagentmux.base_agent_request import BaseAgentRequestHandler
from sshagentmux.upstream_socket_thread import UpstreamSocketThread
from sshagentmux.util import daemonize, setup_logging

LOG = logging.getLogger(__name__)


class AgentProxyRequestHandler(BaseAgentRequestHandler):
    """
    Handle a single SSH agent session
    """

    SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1
    SSH_AGENT_FAILURE = bytearray(struct.pack('> I B', 1, 5))

    def setup(self):
        self.fetch_peer_info()
        self.authorized_identities = \
            self.server.authorizer.authorized_identities(self.username)

    def handle(self):
        """
        Handle a single SSH agent session
        """
        for request in self._each_msg():
            r_len, r_type = struct.unpack_from('> I B', request)

            response = self.SSH_AGENT_FAILURE

            if os.getuid() == self.peer_uid:
                # Forward all requests for the local user
                response = self.server.agent.forward_request(request)
            elif r_type == self.SSH_AGENTC_REQUEST_RSA_IDENTITIES:
                # Deny enumerating SSHv1 RSA identities
                response = self.SSH_AGENT_FAILURE
            elif r_type == self.SSH2_AGENTC_REQUEST_IDENTITIES:
                # Filter identities
                response = self._filter_identities(request)
            elif r_type == self.SSH2_AGENTC_SIGN_REQUEST:
                # Restrict Identities to authorized identitites
                key_blob_len = struct.unpack_from('> I', request, 5)[0]
                key_blob = request[9:9 + key_blob_len]
                key_digest = self._key_digest(key_blob)

                if self.server.authorizer.is_authorized(self.username,
                                                        key_digest):
                    LOG.info("identity %s used by %s: %s", key_digest,
                             self.username, self.process_info)
                    response = self.server.agent.forward_request(request)
                else:
                    LOG.warning("declined identity %s use by %s: %s",
                                key_digest, self.username, self.process_info)
                    response = self.SSH_AGENT_FAILURE

            self.request.sendall(response)

    def _filter_identities(self, request):
        """
        Filter identities from upstream agent to only ones this user is
        authorized to use
        """
        identities = []

        response = self.server.agent.forward_request(request)

        for key_blob, key_comment in self._parse_identities(response):
            if self._key_digest(key_blob) in self.authorized_identities:
                identity = (key_blob, key_comment)
                identities.append(identity)

        return self._build_identities_answer(identities)


class AuthorizationProxy(SocketServer.ThreadingUnixStreamServer):
    def __init__(self, listening_sock, db_path, upstream_sock):
        # XXX BaseServer is an old style class, so we need to explicitly call
        # our parents initializer
        SocketServer.ThreadingUnixStreamServer. \
            __init__(self, listening_sock, AgentProxyRequestHandler)

        self.authorizer = Authorizer(db_path)

        # Shared request queue
        request_queue = Queue.Queue(100)
        # Start first consumer thread
        self.agent = UpstreamSocketThread(upstream_sock, queue=request_queue)
        self.agent.start()
        # Start two additional consumer threads
        for i in range(2):
            UpstreamSocketThread(upstream_sock, queue=request_queue).start()


def authorization_proxy(options):
    auth_sock = start_agent()

    # Remove auth sock if is a socket
    try:
        stat_info = os.stat(options.socket)
        if stat.S_ISSOCK(stat_info.st_mode):
            os.remove(options.socket)
        else:
            LOG.error("auth socket %s exist", options.socket)
    except OSError:
        pass

    # Open socket with permissive permissions, socket permission enforcement
    # isn't consistant across operating systems, so administrator should
    # enforce permissions on enclosing directory
    saved_umask = os.umask(0)
    server = AuthorizationProxy(options.socket, options.database, auth_sock)
    os.umask(saved_umask)

    # Remove listening socket at exit
    atexit.register(lambda: os.remove(options.socket))

    def sighup_handler(signo, frame):
        server.authorizer.reload()

    signal.signal(signal.SIGHUP, sighup_handler)

    server.serve_forever()


def start_agent():
    """
    Start ssh-agent and return auth socket path
    """
    agent_output = subprocess.check_output('/usr/bin/ssh-agent')

    match = re.search(r'SSH_AUTH_SOCK=([^;]+);.*SSH_AGENT_PID=(\d+);',
                      agent_output, re.MULTILINE | re.DOTALL)
    if not match:
        LOG.error("ssh-agent return unexpected output: %s", agent_output)
        return None

    auth_sock, pid = match.groups()
    pid = int(pid)

    atexit.register(lambda: os.kill(pid, signal.SIGTERM))

    return auth_sock


class Authorizer(object):
    def __init__(self, db_path):
        self._database_file = db_path
        self._reload_pending = True
        self._lock = threading.Lock()
        self._authorizations = {}
        self._reload_authorizations()

    def reload(self):
        # Invoked from signal handler, do not preform actual reload here
        LOG.info("queued reload")
        self._reload_pending = True

    def authorized_identities(self, username):
        """
        Returns frozenset of identities this user is authorized to use

        """
        if self._reload_pending:
            self._reload_authorizations()

        with self._lock:
            if username in self._authorizations:
                return self._authorizations[username]
            else:
                return frozenset()

    def is_authorized(self, username, key_digest):
        if self._reload_pending:
            self._reload_authorizations()

        with self._lock:
            return (username in self._authorizations and
                    key_digest in self._authorizations[username])

    def _load_authorization_db(self):
        new_authorizations = {}

        try:
            with sqlite3.connect(self._database_file) as db:
                db.executescript("""CREATE TABLE IF NOT EXISTS identities (
                                        key_digest TEXT UNIQUE NOT NULL,
                                        name TEXT NOT NULL
                                   );

                                   CREATE UNIQUE INDEX IF NOT EXISTS
                                        idx_identities_key_digest ON
                                        identities (key_digest);

                                   CREATE TABLE IF NOT EXISTS authorizations (
                                        username TEXT NOT NULL,
                                        identity_id INTEGER
                                   );

                                   CREATE UNIQUE INDEX IF NOT EXISTS
                                        idx_authorizations_username_identity
                                        ON authorizations (username,
                                        identity_id);
                                """)

                cur = db.cursor()
                cur.execute("""SELECT
                                    username, key_digest
                               FROM authorizations JOIN identities ON
                                    authorizations.identity_id==identities.rowid;
                            """)

                # Ensure we can load the entire database before replacing
                # our authorizations
                for username, key_digest in cur.fetchall():
                    if username not in new_authorizations:
                        new_authorizations[username] = set()

                    new_authorizations[username].add(key_digest)
        except Exception as msg:
            LOG.error("load from %s failed: %s", self._database_file, msg)

        return new_authorizations

    def _reload_authorizations(self):
        new_authorizations = self._load_authorization_db()

        with self._lock:
            # Replace authorizations
            self._authorizations.clear()
            for u in new_authorizations.keys():
                self._authorizations[u] = frozenset(new_authorizations[u])

            self._reload_pending = False
            authorization_count = sum(len(self._authorizations[username])
                                      for username in self._authorizations)
            LOG.info("loaded %s authorizations for %s users from %s",
                     authorization_count, len(self._authorizations),
                     self._database_file)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', '-d', action='store_true',
                        help="Enable debug logging")
    parser.add_argument('--database', help='Authorization database',
                        default=os.path.expanduser('~/authorization_proxy.db'))
    parser.add_argument('--pidfile', help='PID file',
                        default=os.path.expanduser(
                            '~/authorization_proxy.pid'))
    parser.add_argument('--socket', help='SSH Authentication Socket path',
                        default=os.path.expanduser(
                            '~/authorization_proxy.sock'))
    parser.add_argument('--logfile', help='Log file', default='/dev/null')
    parser.add_argument('action')

    args = parser.parse_args()

    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    setup_logging("authorization_proxy", level)

    if args.action == 'start':
        daemonize(target=authorization_proxy, pidfile=args.pidfile,
                  stderr=args.logfile, stdout=args.logfile,
                  args=(args,))
    elif args.action == 'stop':
        if os.path.exists(args.pidfile):
            with open(args.pidfile) as f:
                os.kill(int(f.read()), signal.SIGTERM)
        else:
            print >>sys.stderr, 'Not running'
            raise SystemExit(1)
    elif args.action == 'debug':
        authorization_proxy(args)
    else:
        print >>sys.stderr, 'Unknown command {!r}'.format(sys.argv[1])
        raise SystemExit(1)


if __name__ == '__main__':
    main()
