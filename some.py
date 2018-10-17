#!/usr/bin/env python

import logging
import shlex
import six
import subprocess

logger = logging.getLogger('')


class Struct(object):
    """
    Allows you to access dictionary elements by point.
    """
    __slots__ = ('__dict__')
    tab_size = 2

    def __init__(self, E=None, *args, **kwargs):
        self.__dict__ = {}
        for k, v in six.iteritems(E or {}):
            if isinstance(v, dict):
                self.__dict__[k] = self.__class__(v)
            else:
                self.__dict__[k] = v
        for k, v in six.iteritems(kwargs):
            if isinstance(v, dict):
                self.__dict__[k] = self.__class__(v)
            else:
                self.__dict__[k] = v

    def as_dict(self):
        return {k: v.as_dict() if isinstance(v, Struct) else str(v) for k, v in six.iteritems(self.__dict__)}

    def __str__(self, i=0):
        def generate():
            for k in sorted(self.__dict__):
                v = self.__dict__[k]
                if isinstance(v, Struct):
                    yield "{}{}:\n{}".format(" " * i, k, v.__str__(i + self.tab_size))
                else:
                    yield "{}{} = {}".format(" " * i, k, v)
        return '\n'.join(generate())

    def __repr__(self):
        return str(self)


def exec_popen(command, shell=False, log=True, log_limit=200):
    """
        Exec command with subprocess.popen and return stdout, stderr, returncode.
    :param command:
    :param bool shell: use shell in subprocess for execute command
    :param log: enable stdout, stderr logging
    :param log_limit: length of debug log string in chars for stdout
    :return:
    """
    logger.debug('Execute cmd: "{}"'.format(command))
    try:
        p = subprocess.Popen(
            command if shell else shlex.split(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell
        )
    except Exception as e:
        stdout, stderr = '', 'Command: "{cmd}" raise error: "{err}"'.format(cmd=command, err=e)
        returncode = None
        logger.warning('Command: "{cmd}" raise error: "{err}"'.format(cmd=command, err=e))
    else:
        stdout, stderr = p.communicate()
        returncode = p.returncode
        if log:
            if returncode != 0 or stderr:
                logger.warning('Command: "{cmd}" exit with code "{code}" return stderr: "{err}"'.format(
                    cmd=command, code=returncode, err=stderr))
            if returncode == 0 or stdout:
                logger.debug('Command: "{cmd}" exit with code "{code}" return stdout: "{err}"'.format(
                    cmd=command, code=returncode, err=stdout[:log_limit]))
    return stdout, stderr, returncode


