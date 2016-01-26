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

import atexit
import os
import logging
import logging.handlers
import signal
import sys

LOG = logging.getLogger(__name__)


def setup_logging(name, level=logging.DEBUG):

    log = logging.getLogger()
    log.setLevel(level)
    handler = logging.handlers.SysLogHandler(address='/dev/log')

    FORMAT = name + "[%(process)d]:%(module)s %(levelname)s %(message)s"
    DATE_FORMAT = '%b %d %H:%M:%S'
    formatter = logging.Formatter(fmt=FORMAT, datefmt=DATE_FORMAT)
    handler.setFormatter(formatter)
    log.addHandler(handler)


def daemonize(target=None, pidfile=None, stdin='/dev/null', stdout='/dev/null',
              stderr='/dev/null', args=(), kwargs={}):

    if pidfile and os.path.exists(pidfile):
        raise RuntimeError('Already running')

    # First fork (detaches from parent)
    try:
        if os.fork() > 0:
            # Parent returns
            return
    except OSError as e:
        raise RuntimeError('fork #1 failed.')

    os.chdir('/')
    os.umask(077)
    os.setsid()

    # Second fork (relinquish session leadership)
    try:
        if os.fork() > 0:
            raise SystemExit(0)
    except OSError as e:
        raise RuntimeError('fork #2 failed with error %s' % e)

    # Flush I/O buffers
    sys.stdout.flush()
    sys.stderr.flush()

    # Replace file descriptors for stdin, stdout, and stderr
    with open(stdin, 'rb', 0) as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open(stdout, 'ab', 0) as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
    with open(stderr, 'ab', 0) as f:
        os.dup2(f.fileno(), sys.stderr.fileno())

    if pidfile:
        # Write the PID file
        with open(pidfile, 'w') as f:
            print >>f, os.getpid()

        # Arrange to have the PID file removed on exit/signal
        atexit.register(lambda: os.remove(pidfile))

    # Signal handler for termination (required)
    def sigterm_handler(signo, frame):
        LOG.error("SIGTERM received, exiting")
        sys.exit(1)

    signal.signal(signal.SIGTERM, sigterm_handler)

    target(*args, **kwargs)
