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

import logging
import Queue
import socket
import struct
import threading

LOG = logging.getLogger(__name__)


class UpstreamSocketThread(threading.Thread):
    SSH_AGENT_FAILURE = bytearray(struct.pack('> I B', 1, 5))
    timeout = 30

    def __init__(self, socket_path, queue=None):
        super(UpstreamSocketThread, self).__init__()
        self._socket_path = socket_path
        if queue is None:
            queue = Queue.Queue()
        self._queue = queue
        self.daemon = True
        self._sock = None
        self._retries = 5
        self._reconnect()

    def __str__(self):
        return self._socket_path

    def forward_request(self, msg):
        """
        Called my other thread submitting a request
        """
        response_queue = Queue.Queue(1)
        request = (msg, response_queue)
        self._queue.put(request)

        response = response_queue.get(True, self.timeout)

        return response

    def run(self):
        # Reuse connection
        while True:
            request_msg, response_queue = self._queue.get()
            for attempt in range(self._retries):
                try:
                    self._sock.sendall(request_msg)
                    response_msg = self._recv_msg()
                except socket.error, msg:
                    LOG.error("upstream agent error: %s", msg)
                    for chunk in self._hex_dump_chunks(request_msg):
                        LOG.warning("upstream agent request: %s" % chunk)
                    self._reconnect()
                else:
                    response_queue.put(response_msg)
                    break
            else:
                response_queue.put(self.SSH_AGENT_FAILURE)

    def _hex_dump_chunks(self, msg):
        for i in range(0, len(msg), 16):
            yield " ".join("{:02x}".format(c) for c in msg[i:i + 16])

    def _reconnect(self):
        if self._sock is not None:
            self._sock.close()

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(self._socket_path)

    def _recv_msg(self):
        msg_length = 4
        msg_buffer = bytearray()

        while len(msg_buffer) < msg_length:
            chunk = self._sock.recv(msg_length - len(msg_buffer))
            if not chunk:
                return
            msg_buffer.extend(chunk)

            if msg_length == 4 and len(msg_buffer) == 4:
                msg_length = 4 + struct.unpack('> I', msg_buffer)[0]

        return msg_buffer
