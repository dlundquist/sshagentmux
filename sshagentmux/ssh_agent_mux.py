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
import logging
import multiprocessing
import os
import SocketServer
import struct
import sys
import tempfile

from sshagentmux.base_agent_request import BaseAgentRequestHandler
from sshagentmux.upstream_socket_thread import UpstreamSocketThread
from sshagentmux.util import daemonize, setup_logging

LOG = logging.getLogger(__name__)


class AgentMultiplexerRequestHandler(BaseAgentRequestHandler):
    """
    Handle a single SSH agent session
    """

    def setup(self):
        self._identity_map = {}
        self.fetch_peer_info()
        # Deny connections from other users
        if self.peer_uid != os.getuid():
            raise RuntimeError("Connection from uid {} denied.".format(
                               self.peer_uid))

    def handle(self):
        """
        Handle a single SSH agent session
        """
        for request in self._each_msg():
            r_len, r_type = struct.unpack_from('> I B', request)

            if r_type == self.SSH2_AGENTC_REQUEST_IDENTITIES:
                response = self._merge_identities(request)
            elif r_type == self.SSH2_AGENTC_SIGN_REQUEST:
                # Extract key blob from request
                key_blob_len = struct.unpack_from('> I', request, 5)[0]
                key_blob = request[9:9 + key_blob_len]
                hex_blob = ''.join('{:02x}'.format(b) for b in key_blob)

                agent = self._identity_map[hex_blob]

                if agent:
                    if agent == self.server.alternate_agent:
                        key_digest = self._key_digest(key_blob)
                        LOG.info("identity %s used by %s: %s", key_digest,
                                 self.username, self.process_info)

                    response = agent.forward_request(request)
                else:
                    response = \
                        self.server.default_agent.forward_request(request)
            else:
                response = self.server.default_agent.forward_request(request)

            self.request.sendall(response)

    def _merge_identities(self, request):
        """
        Gather identities from all upstream agents and merge into a single
        response, keep track of where we found each identity
        """
        identities = []
        for agent in self.server.agents():
            response = agent.forward_request(request)

            for key_blob, key_comment in self._parse_identities(response):
                # Record where each identity came from
                hex_blob = ''.join('{:02x}'.format(b) for b in key_blob)
                if hex_blob in self._identity_map and \
                        self._identity_map[hex_blob] != agent:
                    LOG.error("identity %s duplicated in %s and %s by %s",
                              hex_blob, agent, self._identity_map[hex_blob],
                              self.username)

                self._identity_map[hex_blob] = agent

                identity = (key_blob, key_comment)
                identities.append(identity)

        return self._build_identities_answer(identities)


class AgentMultiplexer(SocketServer.ThreadingUnixStreamServer):
    timeout = 3

    def __init__(self, listening_sock, default_agent_sock,
                 alternate_agent_sock):
        # XXX BaseServer is an old style class, so we need to explicitly call
        # our parents initializer
        SocketServer.ThreadingUnixStreamServer.__init__(
            self, listening_sock, AgentMultiplexerRequestHandler)

        self.default_agent = UpstreamSocketThread(default_agent_sock)
        self.default_agent.start()
        self.alternate_agent = UpstreamSocketThread(alternate_agent_sock)
        self.alternate_agent.start()

    def agents(self):
        yield self.default_agent
        yield self.alternate_agent


def start_agent_mux(ready_pipeout, parent_pid, upstream_socket,
                    alternative_socket):
    # generate unique socket path
    sock_dir = tempfile.mkdtemp()
    sock_path = sock_dir + '/ssh_auth.sock'

    # pass all sockets to AgentMultiplexer
    server = AgentMultiplexer(sock_path, upstream_socket, alternative_socket)

    # Let parent know the socket is ready
    ready_pipeout.send(sock_path)
    ready_pipeout.close()

    while check_pid(parent_pid):
        server.handle_request()

    os.unlink(sock_path)
    os.rmdir(sock_dir)


def check_pid(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def same_socket(sock1, sock2):
    return os.path.realpath(sock1) == os.path.realpath(sock2)


def main():
    # fetch alternate socket path from command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', '-d', action='store_true',
                        help="Enable debug logging")
    parser.add_argument('--socket', required=True,
                        help='alternative SSH agent socket')

    args, extra_args = parser.parse_known_args()

    if extra_args and extra_args[0] == '--':
        extra_args = extra_args[1:]

    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    setup_logging("sshagentmux", level)

    LOG.info("Starting sshagentmux")

    # use specified socket if SSH_AUTH_SOCK is not present in environment
    sock_path = args.socket

    if 'SSH_AUTH_SOCK' in os.environ and not same_socket(
            os.environ['SSH_AUTH_SOCK'], args.socket):
        upstream_socket = os.environ['SSH_AUTH_SOCK']

        # Save original parent pid so we can detect when it exits
        parent_pid = os.getppid()
        if extra_args:
            parent_pid = os.getpid()

        # Start proxy process and wait for it to creating auth socket
        # Using a pipe for compatibility with OpenBSD
        ready_pipein, ready_pipeout = multiprocessing.Pipe()
        daemonize(target=start_agent_mux,
                  stderr=os.path.expanduser('~/.sshagentmux.log'),
                  args=(ready_pipeout, parent_pid, upstream_socket,
                        args.socket))

        # Wait for server to setup listening socket
        sock_path = ready_pipein.recv()
        ready_pipein.close()
        ready_pipeout.close()

        if not os.path.exists(sock_path):
            print >>sys.stderr, 'Agent Multiplexer failed to ' \
                'create auth socket'
            sys.exit(1)

    # Behave like ssh-agent(1)
    if extra_args:
        # start command if specified in extra_args
        os.environ['SSH_AUTH_SOCK'] = sock_path
        os.execvp(extra_args[0], extra_args)
    else:
        # print how to setup environment (same behavior as ssh-agent)
        print 'SSH_AUTH_SOCK={:s}; export SSH_AUTH_SOCK;'.format(sock_path)


if __name__ == '__main__':
    main()
