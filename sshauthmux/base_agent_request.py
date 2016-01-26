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

import hashlib
import pwd
import re
import socket
import SocketServer
import struct
import subprocess
import sys


class BaseAgentRequestHandler(SocketServer.BaseRequestHandler):
    SSH2_AGENTC_REQUEST_IDENTITIES = 11
    SSH2_AGENT_IDENTITIES_ANSWER = 12
    SSH2_AGENTC_SIGN_REQUEST = 13
    PEERCRED_STRUCT = struct.Struct('= I I I')

    def fetch_peer_info(self):
        """
        Collect user and process info of peer
        """
        if sys.platform == 'linux2':
            SO_PEERCRED = 17

            peercred = self.request.getsockopt(socket.SOL_SOCKET, SO_PEERCRED,
                                               self.PEERCRED_STRUCT.size)

            self.peer_pid, self.peer_uid, _ = \
                self.PEERCRED_STRUCT.unpack(peercred)
        elif sys.platform == 'openbsd5':
            SO_PEERCRED = 4130

            peercred = self.request.getsockopt(socket.SOL_SOCKET, SO_PEERCRED,
                                               self.PEERCRED_STRUCT.size)

            self.peer_uid, _, self.peer_pid = \
                self.PEERCRED_STRUCT.unpack(peercred)
        else:
            raise RuntimeError("Unsupported platform {}.".format(
                               sys.platform))

        self._fetch_process_info()
        self.username = pwd.getpwuid(self.peer_uid)[0]

    def handle(self):
        """
        Handle a single SSH agent session
        """
        raise Exception('Unimplemented')

    def _key_digest(self, key_blob):
        m = hashlib.md5()
        m.update(key_blob)

        return ':'.join(re.findall(r'.{1,2}', m.hexdigest(), re.DOTALL))

    def _parse_identities(self, response):
        """
        Parse a SSH2_AGENT_IDENTITIES_ANSWER yielding each identity as a key,
        comment tuple
        """
        r_len, r_type = struct.unpack_from('> I B', response)
        offset = struct.calcsize('> I B')
        if r_type != self.SSH2_AGENT_IDENTITIES_ANSWER:
            return

        id_count = struct.unpack_from('> I', response, offset)[0]
        offset += struct.calcsize('> I')

        for i in range(id_count):
            key_blob_len = struct.unpack_from('> I', response, offset)[0]
            offset += struct.calcsize('> I')
            key_blob = response[offset:offset + key_blob_len]
            offset += key_blob_len

            key_comment_len = struct.unpack_from('> I', response,
                                                 offset)[0]
            offset += struct.calcsize('> I')
            key_comment = response[offset:offset + key_comment_len]
            offset += key_comment_len

            yield (key_blob, key_comment)

    def _build_identities_answer(self, identities):
        """
        Build a SSH2_AGENT_IDENTITIES_ANSWER out of a list of key, comment
        tuples
        """
        answer = bytearray(9)
        # Leave length and identity count zero for now
        struct.pack_into('> I B I', answer, 0, 0,
                         self.SSH2_AGENT_IDENTITIES_ANSWER, 0)

        identity_count = 0
        for key_blob, key_comment in identities:
            blob_length = bytearray(4)
            struct.pack_into('> I', blob_length, 0, len(key_blob))

            answer.extend(blob_length)
            answer.extend(key_blob)

            comment_length = bytearray(4)
            struct.pack_into('> I', comment_length, 0, len(key_comment))

            answer.extend(comment_length)
            answer.extend(key_comment)

            identity_count += 1

        answer_length = len(answer) - 4

        # Now we can fill in the response length and identity count
        struct.pack_into('> I', answer, 0, answer_length)
        struct.pack_into('> I', answer, 5, identity_count)

        return answer

    def _each_msg(self):
        """
        Iterate over agent protocol messages
        """
        while True:
            msg_length = 4
            msg_buffer = bytearray()

            while len(msg_buffer) < msg_length:
                recv_len = msg_length - len(msg_buffer)
                chunk = self.request.recv(recv_len)
                if not chunk:
                    return

                msg_buffer.extend(chunk)
                if msg_length == 4 and len(msg_buffer) == 4:
                    msg_length = 4 + struct.unpack('> I', msg_buffer)[0]

            yield msg_buffer

    def _fetch_process_info(self):
        """
        Retrieve the command line of the process
        """
        self.process_info = 'pid={}'.format(self.peer_pid)
        ps_cmd = ['ps', '-o', 'args', '-ww', '-p', '{}'.format(self.peer_pid)]
        ps_output = subprocess.check_output(ps_cmd)
        self.process_info = ps_output.split('\n')[1]
