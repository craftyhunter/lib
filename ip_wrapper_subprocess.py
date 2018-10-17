#!/usr/bin/env python

import logging
import re
import shlex
import subprocess
from collections import namedtuple
from ipaddress import ip_interface

__author__ = 'craftyhunter'

__version__ = '0.2.5'
VERSION = tuple(map(int, __version__.split('.')))

__all__ = ['Ip', 'IpAddress', 'IpRoute', 'IpLink', 'IpTunnel', 'IpRule', 'Address', 'Rule', 'Route', 'Link', 'Tunnel']

logger = logging.getLogger('')

Address = namedtuple(
    'Address', ['local', 'dev', 'family', 'scope', 'dynamic', 'address_wo_prefix', 'prefix'])
Rule = namedtuple(
    'Rule', ['priority', 'type_', 'from_', 'to', 'iif', 'oif', 'table'])
Link = namedtuple(
    'Link', ['dev', 'alias', 'state', 'mtu', 'mode', 'qdisc', 'group', 'qlen', 'flags'])
Route = namedtuple(
    'Route', ['to', 'from_', 'via', 'dev', 'proto', 'scope', 'src', 'metric', 'mtu', 'advmss', 'is_local', 'table'])
Tunnel = namedtuple(
    'Tunnel', ['name', 'mode', 'local', 'remote', 'dev', 'encaplimit', 'hoplimit', 'tclass', 'flowlabel'])


class Ip(object):
    __slots__ = ('last_command', '_executor')
    CMD_IP = '/sbin/ip'
    CMD = ''

    def __init__(self, executor=None):
        self._executor = executor or self._exec_popen

    def _action(self, action, family=None, kv_opts=None, opts=None):
        kv_opts = kv_opts or ()
        opts = opts or ()
        family_str = '-{}'.format(family) if family else ''
        params = [self.CMD_IP, family_str, self.CMD, action]
        params.extend(['{} {}'.format(param, value) for param, value in kv_opts if value])
        params.extend([param for param, value in opts if value])
        self.last_command = ' '.join([_x for _x in params if _x])
        return self._executor(self.last_command)

    @staticmethod
    def _exec_popen(command):
        logger.debug(command)
        try:
            p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            raise OSError('Command: "{cmd}" raise error: "{err}"'.format(cmd=command, err=e))
        else:
            stdout, stderr = p.communicate()
            returncode = p.returncode
        return stdout.decode('utf-8'), stderr.decode('utf-8'), returncode


class IpAddress(Ip):
    __slots__ = ()
    CMD = 'address'
    PATTERN_ADDR = '(?P<family>inet[6]?)[ \t]*(?P<address>[0-9a-f:./]+)[ \t]*' \
                   '(scope (?P<scope>[a-z]+))?(?P<other>.*)'
    PATTERN_DEVICE = '[0-9]+[:][ \t]*(?P<dev>[A-Za-z0-9_:.-]+)(@[A-Za-z0-9_.:-]+)?[:].*'

    def add(self, dev=None, local=None, address=None, peer=None, broadcast=None, label=None, scope=None, family=None):
        kv_list = ('local', 'dev', 'scope', 'peer', 'broadcast', 'label')
        k_list = ()
        if address and isinstance(address, Address):
            dev = address.dev
            local = address.local
            scope = address.scope
        if not dev or not local:
            raise Exception('Must be specified required parameters: "{}".'.format(['dev', 'local']))
        try:
            local_ip = ip_interface(local.decode())
        except AttributeError:
            local_ip = ip_interface(local)
        local = str(local_ip)
        family = family or local_ip.version
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='add', family=family, kv_opts=kv_opts, opts=opts)

    def delete(
            self, dev=None, local=None, address=None, peer=None, broadcast=None, label=None, scope=None, family=None):
        kv_list = ('local', 'dev', 'scope', 'peer', 'broadcast', 'label')
        k_list = ()
        if address and isinstance(address, Address):
            dev = address.dev
            local = address.local
            scope = address.scope
        if not dev:
            raise Exception('Must be specified required parameters: "dev".')
        try:
            local_ip = ip_interface(local.decode())
        except AttributeError:
            local_ip = ip_interface(local)
        local = str(local_ip)
        family = family or local_ip.version
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='delete', family=family, kv_opts=kv_opts, opts=opts)

    def show(self, dev=None, scope=None, to=None, label=None, up=False, dynamic=False,
             permanent=False, tentative=False, deprecated=False, dadfailed=False,
             temporary=False, primary=False, secondary=False, family=None):
        """
        Show ip addresses.
        :param dev: NAME
                name of device
        :param scope: SCOPE_VAL
                only list addresses with this scope
        :param to: PREFIX
                only list addresses matching this prefix
        :param label: PATTERN
                only list addresses with labels matching the PATTERN.  PATTERN is a usual shell style pattern
        :param up:
                only list running interfaces
        :param dynamic:
                (IPv6 only) only list addresses installed due to stateless address configuration
        :param permanent:
                (IPv6 only) only list permanent (not dynamic) addresses
        :param tentative:
                (IPv6 only) only list addresses which have not yet passed duplicate address detection
        :param deprecated:
                (IPv6 only) only list deprecated addresses
        :param dadfailed:
                (IPv6 only) only list addresses which have failed duplicate address detection
        :param temporary:
                (IPv6 only) only list temporary addresses
        :param primary:
                only list primary addresses
        :param secondary:
                only list secondary addresses
        :param family: 4 or 6
        :return list: list with rules
        """
        kv_list = ('dev', 'scope', 'to', 'label')
        k_list = ('up', 'dynamic', 'permanent', 'tentative', 'deprecated', 'dadfailed', 'temporary',
                  'primary', 'secondary')
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        stdout, stderr, returncode = self._action(action='show', family=family, kv_opts=kv_opts, opts=opts)
        if returncode != 0:
            return [], stderr, returncode
        addresses = []
        lines = (x.strip() for x in stdout.strip().split('\n'))
        if dev:
            try:
                next(lines)
            except StopIteration:
                pass
        pattern = re.compile(self.PATTERN_ADDR)
        pattern_dev = re.compile(self.PATTERN_DEVICE)
        for line in lines:
            if not line:
                continue
            if line.strip().startswith('valid_lft'):
                continue
            if line.strip().startswith('inet'):
                addr_match = pattern.match(line)
                if addr_match:
                    addresses.append(Address(
                        local=addr_match.group('address'),
                        dev=dev,
                        family=4 if addr_match.group('family') == 'inet' else 6,
                        scope=addr_match.group('scope'),
                        address_wo_prefix=addr_match.group('address').split('/')[0],
                        prefix=addr_match.group('address').split('/')[1],
                        dynamic=True if addr_match.group('other').find('dynamic') >= 0 else False,
                    ))
                else:
                    logger.error('ip address. Line with address "{}" no matched. Need fix pattern.'.format(line))
                continue
            if line.strip().startswith('link'):
                # additional link info
                continue
            dev_match = pattern_dev.match(line)
            if dev_match:
                dev = dev_match.group('dev')
            else:
                logger.error('ip address. Can not parse dev from line"{}".'.format(line))
        return addresses, stderr, returncode

    def flush(self, dev=None, scope=None, to=None, label=None, up=False, dynamic=False,
              permanent=False, tentative=False, deprecated=False, dadfailed=False,
              temporary=False, primary=False, secondary=False, family=None):
        kv_list = ('dev', 'scope', 'to', 'label')
        k_list = ('up', 'dynamic', 'permanent', 'tentative', 'deprecated', 'dadfailed', 'temporary',
                  'primary', 'secondary')
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        if not [x for x, y in ((k, env.get(k, None)) for k in kv_list) if y]:
            raise Exception('flush method must have specified at least one parameter.')
        return self._action(action='flush', family=family, kv_opts=kv_opts, opts=opts)


class IpRoute(Ip):
    __slots__ = ()
    CMD = 'route'
    PATTERN_SHOW = '(?P<dest>[a-z0-9/:.]+)[ \t]*(via (?P<via>[a-f0-9:.]+))?[ \t]*' \
                   '(dev[ \t]*(?P<dev>[a-zA-Z0-9_-]+))?[ \t]*(proto (?P<proto>[a-z0-9]+))?[ \t]*' \
                   '(scope (?P<scope>[a-z0-9]+))?[ \t]*(src (?P<src>[a-f0-9:.]+))?[ \t]*' \
                   '(metric (?P<metric>[0-9]+))?[ \t]*(expires (?P<expires>[0-9]+)sec)?[ \t]*' \
                   '(mtu (?P<mtu>[0-9]+))?[ \t]*(advmss (?P<advmss>[0-9]+))?.*'
    PATTERN_GET = '(?P<local>local)?[ \t]*(?P<dest>[a-f0-9:.]+)?[ \t]*(from (?P<from>[0-9a-f:.]+))?[ \t]*' \
                  '(via (?P<via>[a-f0-9:.]+))?[ \t]*dev (?P<dev>[a-zA-Z0-9_-]+)[ \t]*src (?P<src>[a-f0-9:.]+)[ \t]*' \
                  '(metric (?P<metric>[0-9]+))?.*'

    def add(self, to=None, tos=None, dsfield=None, metric=None, preference=None, table=None,
            dev=None, via=None, src=None, realm=None, mtu=None, mtu_lock=None, window=None,
            rtt=None, rttvar=None, rto_min=None, ssthresh=None, cwnd=None, initcwnd=None,
            initrwnd=None, quickack=None, advmss=None, reordering=None, nexthop=None, scope=None,
            protocol=None, onlink=False, family=None, route=None):
        kv_list = (
            'to',  'dev', 'via', 'src', 'table', 'tos', 'dsfield', 'metric', 'preference', 'realm', 'scope',
            'mtu', 'mtu lock', 'advmss', 'window', 'rtt', 'rttvar', 'rto_min', 'ssthresh', 'cwnd', 'initcwnd',
            'initrwnd', 'quickack', 'reordering', 'nexthop', 'protocol')
        k_list = ('onlink', )
        if route and isinstance(route, Route):
            dev = route.dev
            to = route.to
            from_ = route.from_
            via = route.via
            src = route.src
            metric = route.metric
            mtu = route.mtu
            advmss = route.advmss
            table = route.table
        for option in ('to', 'src', 'via'):
            if family:
                continue
            try:
                try:
                    option_ = ip_interface(locals().get(option).decode())
                except AttributeError:
                    option_ = ip_interface(locals().get(option))
                family = family or option_.version
                locals()[option] = str(option_)
            except ValueError:
                pass
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='add', family=family, kv_opts=kv_opts, opts=opts)

    def change(self, to=None, tos=None, dsfield=None, metric=None, preference=None, table=None,
               dev=None, via=None, src=None, realm=None, mtu=None, mtu_lock=None, window=None,
               rtt=None, rttvar=None, rto_min=None, ssthresh=None, cwnd=None, initcwnd=None,
               initrwnd=None, quickack=None, advmss=None, reordering=None, nexthop=None, scope=None,
               protocol=None, onlink=False, family=None, route=None):
        kv_list = (
            'to',  'dev', 'via', 'src', 'table', 'tos', 'dsfield', 'metric', 'preference', 'realm', 'scope',
            'mtu', 'mtu lock', 'advmss', 'window', 'rtt', 'rttvar', 'rto_min', 'ssthresh', 'cwnd', 'initcwnd',
            'initrwnd', 'quickack', 'reordering', 'nexthop', 'protocol')
        k_list = ('onlink', )
        if route and isinstance(route, Route):
            dev = route.dev
            to = route.to
            from_ = route.from_
            via = route.via
            src = route.src
            metric = route.metric
            mtu = route.mtu
            advmss = route.advmss
            table = route.table
        for option in ('to', 'src', 'via'):
            if family:
                continue
            try:
                try:
                    option_ = ip_interface(locals().get(option).decode())
                except AttributeError:
                    option_ = ip_interface(locals().get(option))
                family = family or option_.version
                locals()[option] = str(option_)
            except ValueError:
                pass
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='change', family=family, kv_opts=kv_opts, opts=opts)

    def replace(self, to=None, tos=None, dsfield=None, metric=None, preference=None, table=None,
                dev=None, via=None, src=None, realm=None, mtu=None, mtu_lock=None, window=None,
                rtt=None, rttvar=None, rto_min=None, ssthresh=None, cwnd=None, initcwnd=None,
                initrwnd=None, quickack=None, advmss=None, reordering=None, nexthop=None, scope=None,
                protocol=None, onlink=False, family=None, route=None):
        kv_list = (
            'to',  'dev', 'via', 'src', 'table', 'tos', 'dsfield', 'metric', 'preference', 'realm', 'scope',
            'mtu', 'mtu lock', 'advmss', 'window', 'rtt', 'rttvar', 'rto_min', 'ssthresh', 'cwnd', 'initcwnd',
            'initrwnd', 'quickack', 'reordering', 'nexthop', 'protocol')
        k_list = ('onlink', )
        if route and isinstance(route, Route):
            dev = route.dev
            to = route.to
            from_ = route.from_
            via = route.via
            src = route.src
            metric = route.metric
            mtu = route.mtu
            advmss = route.advmss
            table = route.table
        for option in ('to', 'src', 'via'):
            if family:
                continue
            try:
                try:
                    option_ = ip_interface(locals().get(option).decode())
                except AttributeError:
                    option_ = ip_interface(locals().get(option))
                family = family or option_.version
                locals()[option] = str(option_)
            except ValueError:
                pass
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='replace', family=family, kv_opts=kv_opts, opts=opts)

    def delete(self, to=None, tos=None, dsfield=None, metric=None, preference=None, table=None,
               dev=None, via=None, src=None, realm=None, mtu=None, mtu_lock=None, window=None,
               rtt=None, rttvar=None, rto_min=None, ssthresh=None, cwnd=None, initcwnd=None,
               initrwnd=None, quickack=None, advmss=None, reordering=None, nexthop=None, scope=None,
               protocol=None, onlink=False, family=None, route=None):
        kv_list = (
            'to',  'dev', 'via', 'src', 'table', 'tos', 'dsfield', 'metric', 'preference', 'realm', 'scope',
            'mtu', 'mtu lock', 'advmss', 'window', 'rtt', 'rttvar', 'rto_min', 'ssthresh', 'cwnd', 'initcwnd',
            'initrwnd', 'quickack', 'reordering', 'nexthop', 'protocol')
        k_list = ('onlink', )
        if route and isinstance(route, Route):
            dev = route.dev
            to = route.to
            from_ = route.from_
            via = route.via
            src = route.src
            metric = route.metric
            mtu = route.mtu
            advmss = route.advmss
            table = route.table
        for option in ('to', 'src', 'via'):
            if family:
                continue
            try:
                try:
                    option_ = ip_interface(locals().get(option).decode())
                except AttributeError:
                    option_ = ip_interface(locals().get(option))
                family = family or option_.version
                locals()[option] = str(option_)
            except ValueError:
                pass
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='delete', family=family, kv_opts=kv_opts, opts=opts)

    def show(self, to=None, tos=None, dsfield=None, table=None, from_=None, protocol=None, scope=None,
             type_=None, dev=None, via=None, src=None, realm=None, realms=None, cloned=False, cached=False,
             family=None):
        kv_list = ('to', 'tos', 'dsfield', 'table', 'protocol', 'scope', 'dev', 'via', 'src', 'realm', 'realms')
        kv_list_wrong_names = ('from', 'type')
        k_list = ('cloned', 'cached')
        for option in ('to', 'src', 'via'):
            if family:
                continue
            try:
                try:
                    option_ = ip_interface(locals().get(option).decode())
                except AttributeError:
                    option_ = ip_interface(locals().get(option))
                family = family or option_.version
                locals()[option] = str(option_)
            except ValueError:
                pass
        if not family:
            try:
                try:
                    option_ = ip_interface(locals().get('from_').decode())
                except AttributeError:
                    option_ = ip_interface(locals().get('from_'))
                family = family or option_.version
                locals()['from_'] = str(option_)
            except ValueError:
                pass
        env = locals()
        kv_opts = tuple([(k, env.get(k, None)) for k in kv_list] +
                        [(k, env.get('{}_'.format(k), None)) for k in kv_list_wrong_names])
        opts = ((k, env.get(k, False)) for k in k_list)
        if not family:
            stdout4, stderr6, returncode4 = self._action(action='show', family=4, kv_opts=kv_opts, opts=opts)
            stdout6, stderr6, returncode6 = self._action(action='show', family=6, kv_opts=kv_opts, opts=opts)
            lines = (x.strip() for x in stdout4.strip().split('\n') + stdout6.strip().split('\n'))
            stderr = stdout4 + stderr6
            returncode = returncode4 if returncode4 != 0 else returncode6 if returncode6 != 0 else 0
        else:
            stdout, stderr, returncode = self._action(action='show', family=family, kv_opts=kv_opts, opts=opts)
            lines = (x.strip() for x in stdout.strip().split('\n'))
        res = []
        if returncode != 0:
            return res, stderr, returncode
        pattern = re.compile(self.PATTERN_SHOW)
        for line in lines:
            if not line:
                continue
            row_match = pattern.match(line)
            if row_match:
                try:
                    route = Route(
                        to=row_match.group('dest'),
                        via=via if via else row_match.group('via'),
                        dev=dev if dev else row_match.group('dev'),
                        proto=row_match.group('proto'),
                        scope=scope if scope else row_match.group('scope'),
                        src=src if src else row_match.group('src'),
                        metric=int(row_match.group('metric')) if row_match.group('metric') else None,
                        mtu=int(row_match.group('mtu')) if row_match.group('mtu') else None,
                        advmss=int(row_match.group('advmss')) if row_match.group('advmss') else None,
                        is_local=False,
                        from_=None,
                        table=table if table else None,)
                except Exception as ex:
                    logger.error('ip route. Line with route "{}" matched. Raise: {}.'.format(line, ex))
                else:
                    res.append(route)
            else:
                logger.error('ip route. Line with route "{}" no matched. Need fix pattern.'.format(line))
        return res, stderr, returncode

    def flush(self, to=None, tos=None, dsfield=None, table=None, from_=None, protocol=None, scope=None,
              type_=None, dev=None, via=None, src=None, realm=None, realms=None, cloned=False, cached=False,
              family=None):
        kv_list = ('to', 'tos', 'dsfield', 'table', 'protocol', 'scope', 'dev', 'via', 'src', 'realm', 'realms')
        kv_list_wrong_names = ('from', 'type')
        k_list = ('cloned', 'cached')
        for option in ('to', 'src', 'via'):
            if family:
                continue
            try:
                try:
                    option_ = ip_interface(locals().get(option).decode())
                except AttributeError:
                    option_ = ip_interface(locals().get(option))
                family = family or option_.version
                locals()[option] = str(option_)
            except ValueError:
                pass
        if not family:
            try:
                try:
                    option_ = ip_interface(locals().get('from_').decode())
                except AttributeError:
                    option_ = ip_interface(locals().get('from_'))
                family = family or option_.version
                locals()['from_'] = str(option_)
            except ValueError:
                pass
        env = locals()
        kv_opts = tuple([(k, env.get(k, None)) for k in kv_list] +
                        [(k, env.get('{}_'.format(k), None)) for k in kv_list_wrong_names])
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='flush', family=family, kv_opts=kv_opts, opts=opts)

    def get(self, to, tos=None, from_=None, dsfield=None, iif=None, oif=None, connected=False, family=None):
        kv_list = ('to', 'tos', 'dsfield', 'iif', 'oif')
        kv_list_wrong_names = ('from', )
        k_list = ('connected', )
        for option in ('to', ):
            if family:
                continue
            try:
                try:
                    option_ = ip_interface(locals().get(option).decode())
                except AttributeError:
                    option_ = ip_interface(locals().get(option))
                family = family or option_.version
                locals()[option] = str(option_)
            except ValueError:
                pass
        if not family:
            try:
                try:
                    option_ = ip_interface(locals().get('from_').decode())
                except AttributeError:
                    option_ = ip_interface(locals().get('from_'))
                family = family or option_.version
                locals()['from_'] = str(option_)
            except ValueError:
                pass
        env = locals()
        kv_opts = tuple([(k, env.get(k, None)) for k in kv_list] +
                        [(k, env.get('{}_'.format(k), None)) for k in kv_list_wrong_names])
        opts = ((k, env.get(k, False)) for k in k_list)
        stdout, stderr, returncode = self._action(action='show', family=family, kv_opts=kv_opts, opts=opts)
        if returncode != 0:
            return None, stderr, returncode
        lines = stdout.strip().split('\n')
        pattern = re.compile(self.PATTERN_GET)
        if lines:
            line = lines.pop(0)
            row_match = pattern.match(line)
            try:
                return Route(
                    to=row_match.group('dest'),
                    via=row_match.group('via'),
                    dev=row_match.group('dev'),
                    proto=None,
                    scope=None,
                    src=row_match.group('src'),
                    metric=row_match.group('metric'),
                    mtu=None,
                    advmss=None,
                    is_local=True if row_match.group('local') else False,
                    from_=row_match.group('from'),
                    table=None,
                ), stderr, returncode
            except AttributeError:
                logger.error('ip route get. Line with route "{}" no matched. Need fix pattern.'.format(line))


class IpLink(Ip):
    __slots__ = ()
    CMD = 'link'
    PATTERN_SHOW = '[0-9]+[:][ \t]*(?P<dev>[a-zA-Z0-9.]+)(?P<alias>@[A-Za-z0-9]+)?[:][ \t]*' \
                   '<(?P<flags>[A-Z_,-]+)?>( mtu (?P<mtu>[0-9]+))?( qdisc (?P<qdisc>[a-z0-9]+))?' \
                   '( state (?P<state>[a-zA-Z]+))?( mode (?P<mode>[a-zA-Z]+))?( group (?P<group>[a-zA-Z]+))?' \
                   '( qlen (?P<qlen>[0-9]+))?.*'

    def add(self, name, type_, link=None, txqueuelen=None, address=None, broadcast=None,
            mtu=None, numtxqueues=None, numrxqueues=None, id_=None, dev=None, group=None,
            remote=None, local=None, ttl=None, tos=None, port=None, hoplimit=None,
            encaplimit=None, ikey=None, okey=None, tclass=None, flowlabel=None, dscp=None,
            learning=False, nolearning=False, proxy=False, noproxy=False, rsc=False, norsc=False,
            l2miss=False, nol2miss=False, l3miss=False, nol3miss=False, iseq=False, oseq=False,
            ocsum=False, icsum=False):
        kv_list = (
            'link', 'name', 'txqueuelen', 'address', 'broadcast', 'mtu', 'numtxqueues', 'numrxqueues',
            'group', 'remote', 'local', 'ttl', 'tos', 'port', 'hoplimit', 'encaplimit', 'ikey', 'okey',
            'tclass', 'flowlabel', 'dscp', 'dev')
        kv_list_wrong_names = ('type', 'id')
        k_list = (
            'learning', 'nolearning', 'proxy', 'noproxy', 'rsc', 'norsc', 'l2miss', 'nol2miss',
            'l3miss', 'nol3miss', 'iseq', 'oseq', 'ocsum', 'icsum')
        env = locals()
        kv_opts = tuple([(k, env.get(k, None)) for k in kv_list] +
                        [(k, env.get('{}_'.format(k), None)) for k in kv_list_wrong_names])
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='add', kv_opts=kv_opts, opts=opts)

    def set(self, dev=None, group=None, name=None, txqueuelen=None, txqlen=None, mtu=None,
            address=None, broadcast=None, brd=None, peer=None, netns=None, alias=None,
            vf=None, vlan=None, qos=None, rate=None, spoofchk=None, master=None, arp=None,
            multicast=None, dynamic=None, nomaster=False, up=False, down=False):
        kv_list = (
            'dev', 'name', 'txqueuelen', 'txqlen', 'address', 'broadcast', 'mtu', 'brd', 'group',
            'peer', 'netns', 'alias', 'vf', 'vlan', 'qos', 'rate', 'spoofchk', 'master', 'arp',
            'multicast', 'dynamic')
        k_list = ('nomaster', 'up', 'down')
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='set', kv_opts=kv_opts, opts=opts)

    def delete(self, dev):
        kv_list = ('dev', )
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ()
        return self._action(action='delete', kv_opts=kv_opts, opts=opts)

    def show(self, dev=None, group=None, up=False):
        kv_list = ('dev', 'group')
        k_list = ('up', )
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        stdout, stderr, returncode = self._action(action='show', kv_opts=kv_opts, opts=opts)
        res = []
        if returncode != 0:
            return res, stderr, returncode
        lines = (x.strip() for x in stdout.strip().split('\n')[::2])
        pattern = re.compile(self.PATTERN_SHOW)
        for line in lines:
            if not line:
                continue
            row_match = pattern.match(line)
            if row_match:
                link = Link(
                    dev=row_match.group('dev'),
                    alias=row_match.group('dev') + row_match.group('alias') if row_match.group('alias') else None,
                    state=row_match.group('state'),
                    mtu=row_match.group('mtu'),
                    qdisc=row_match.group('qdisc'),
                    mode=row_match.group('mode'),
                    group=row_match.group('group'),
                    qlen=row_match.group('qlen'),
                    flags=row_match.group('flags').split(',') if row_match.group('flags') else []
                )
                res.append(link)
            else:
                logger.error('ip link. Line with link "{}" no matched. Need fix pattern.'.format(line))
        return res, stderr, returncode


class IpTunnel(Ip):
    __slots__ = ()
    CMD = 'tunnel'
    TUN_MODES_V4 = ('ipip', 'sit', 'isatap', 'gre')
    TUN_MODES_V6 = ('ip6ip6', 'ipip6', 'ip6gre', 'any')
    PATTERN_SHOW = '(?P<NAME>[a-zA-Z0-9-_]+)[:][\t ]?(?P<MODE>[a-z0-9/]+)( remote (?P<REMOTE>[0-9a-f:]+))?' \
                   '( local (?P<LOCAL>[0-9a-f:]+))?( dev (?P<DEV>[0-9a-zA-Z:.]+))?' \
                   '( encaplimit (?P<ENCAPLIMIT>[0-9]+))?( hoplimit (?P<HOPLIMIT>[0-9]+))?' \
                   '( tclass (?P<TCLASS>[0-9a-z]+))?( flowlabel (?P<FLOWLABEL>[0-9a-z]+))?.*'

    def add(self, name=None, mode=None, family=None, local=None, remote=None, dev=None,
            ttl=None, tos=None, dsfield=None, tclass=None, key=None, ikey=None, okey=None,
            encaplim=None, flowlabel=None, nopmtudisc=False, csum=False, icsum=False, ocsum=False,
            seq=False, iseq=False, oseq=False, tunnel=None):
        kv_list = (
            'name', 'mode', 'local', 'remote', 'dev', 'ttl', 'tos', 'dsfield', 'tclass', 'key',
            'ikey', 'okey', 'encaplim', 'flowlabel')
        k_list = ('nopmtudisc', 'csum', 'icsum', 'ocsum', 'seq', 'iseq', 'oseq')
        if tunnel and isinstance(tunnel, Tunnel):
            name = tunnel.name
            mode = tunnel.mode
            local = tunnel.local
            remote = tunnel.remote
            dev = tunnel.dev
            encaplim = tunnel.encaplimit
            tclass = tunnel.tclass
            flowlabel = tunnel.flowlabel
        if not name or not mode:
            raise Exception('Must be specified required parameters: "{}".'.format(['name', 'mode']))
        if mode in self.TUN_MODES_V4:
            family = family or 4
        elif mode in self.TUN_MODES_V6:
            family = family or 6
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='add', family=family, kv_opts=kv_opts, opts=opts)

    def change(self, name=None, mode=None, family=None, local=None, remote=None, dev=None,
               ttl=None, tos=None, dsfield=None, tclass=None, key=None, ikey=None, okey=None,
               encaplim=None, flowlabel=None, nopmtudisc=False, csum=False, icsum=False, ocsum=False,
               seq=False, iseq=False, oseq=False, tunnel=None):
        kv_list = (
            'name', 'mode', 'local', 'remote', 'dev', 'ttl', 'tos', 'dsfield', 'tclass', 'key',
            'ikey', 'okey', 'encaplim', 'flowlabel')
        k_list = ('nopmtudisc', 'csum', 'icsum', 'ocsum', 'seq', 'iseq', 'oseq')
        if tunnel and isinstance(tunnel, Tunnel):
            name = tunnel.name
            mode = tunnel.mode
            local = tunnel.local
            remote = tunnel.remote
            dev = tunnel.dev
            encaplim = tunnel.encaplimit
            tclass = tunnel.tclass
            flowlabel = tunnel.flowlabel
        if not name:
            raise Exception('Must be specified required parameters: "name".')
        if mode in self.TUN_MODES_V4:
            family = family or 4
        elif mode in self.TUN_MODES_V6:
            family = family or 6
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        return self._action(action='change', family=family, kv_opts=kv_opts, opts=opts)

    def delete(self, name, family=None, tunnel=None):
        kv_list = ('name', )
        if tunnel and isinstance(tunnel, Tunnel):
            name = tunnel.name
        if not name:
            raise Exception('Must be specified required parameters: "name".')
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ()
        return self._action(action='delete', family=family, kv_opts=kv_opts, opts=opts)

    def show(self, name=None, mode=None, family=None, local=None, remote=None, dev=None,
             ttl=None, tos=None, dsfield=None, tclass=None, key=None, ikey=None, okey=None,
             encaplim=None, flowlabel=None, nopmtudisc=False, csum=False, icsum=False, ocsum=False,
             seq=False, iseq=False, oseq=False):
        kv_list = (
            'name', 'mode', 'local', 'remote', 'dev', 'ttl', 'tos', 'dsfield', 'tclass', 'key',
            'ikey', 'okey', 'encaplim', 'flowlabel')
        k_list = ('nopmtudisc', 'csum', 'icsum', 'ocsum', 'seq', 'iseq', 'oseq')
        if mode in self.TUN_MODES_V4:
            family = family or 4
        elif mode in self.TUN_MODES_V6:
            family = family or 6
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ((k, env.get(k, False)) for k in k_list)
        if not family:
            stdout4, stderr4, returncode4 = self._action(action='show', family=4, kv_opts=kv_opts, opts=opts)
            stdout6, stderr6, returncode6 = self._action(action='show', family=6, kv_opts=kv_opts, opts=opts)
            lines = (x.strip() for x in stdout4.strip().split('\n') + stdout6.strip().split('\n'))
            stderr = stdout4 + stderr6
            returncode = returncode4 if returncode4 != 0 else returncode6 if returncode6 != 0 else 0
        else:
            stdout, stderr, returncode = self._action(action='show', family=family, kv_opts=kv_opts, opts=opts)
            lines = (x.strip() for x in stdout.strip().split('\n'))
        res = []
        if returncode != 0:
            return res, stderr, returncode
        pattern = re.compile(self.PATTERN_SHOW)
        for line in lines:
            if not line:
                continue
            row_match = pattern.match(line)
            if row_match:
                mode = row_match.group('MODE')
                if mode == 'ip/ipv6':
                    mode = 'ipip6'
                tunnel = Tunnel(
                    name=row_match.group('NAME'),
                    mode=mode,
                    local=row_match.group('LOCAL'),
                    remote=row_match.group('REMOTE'),
                    dev=row_match.group('DEV'),
                    encaplimit=row_match.group('ENCAPLIMIT'),
                    hoplimit=row_match.group('HOPLIMIT'),
                    tclass=row_match.group('TCLASS'),
                    flowlabel=row_match.group('FLOWLABEL'),)
                res.append(tunnel)
            else:
                logger.error('ip tunnel. Line with tunnel "{}" no matched. Need fix pattern.'.format(line))
        return res, stderr, returncode


class IpRule(Ip):
    __slots__ = ()
    CMD = 'rule'
    PATTERN_SHOW = '(?P<priority>[0-9]+)[:][ \t]*(from (?P<from_>[a-zA-Z0-9:.]+))?[ \t]*' \
                   '(to (?P<to>[a-zA-Z0-9:.]+))?[ \t]*(iif (?P<iif>[a-zA-Z0-9:.]+))?[ \t]*' \
                   '(oif (?P<oif>[a-zA-Z0-9:.]+))?[ \t]*(lookup (?P<lookup>[0-9a-zA-Z]+))?'

    def add(self, type_=None, from_=None, to=None, iif=None, oif=None, tos=None, dsfield=None, fwmark=None,
            priority=None, table=None, suppress_prefixlength=None, suppress_ifgroup=None, realms=None,
            nat=None, family=None, rule=None):
        kv_list = (
            'to', 'iif', 'oif', 'tos', 'dsfield', 'fwmark', 'priority', 'table', 'suppress_prefixlength',
            'suppress_ifgroup', 'realms', 'nat')
        kv_list_wrong_names = ('type', 'from')
        if rule and isinstance(rule, Rule):
            type_ = rule.type_
            from_ = rule.from_
            to = rule.to
            iif = rule.iif
            oif = rule.oif
            table = rule.table
            priority = rule.priority
        if not family:
            try:
                try:
                    option_ = ip_interface(locals().get('to').decode())
                except AttributeError:
                    option_ = ip_interface(locals().get('to'))
                family = family or option_.version
                locals()['to'] = str(option_)
            except ValueError:
                pass
        if not family:
            try:
                try:
                    option_ = ip_interface(locals().get('from_').decode())
                except AttributeError:
                    option_ = ip_interface(locals().get('from_'))
                family = family or option_.version
                locals()['from_'] = str(option_)
            except ValueError:
                pass
        env = locals()
        kv_opts = tuple([(k, env.get(k, None)) for k in kv_list] +
                        [(k, env.get('{}_'.format(k), None)) for k in kv_list_wrong_names])
        opts = ()
        return self._action(action='add', family=family, kv_opts=kv_opts, opts=opts)

    def delete(self, type_=None, from_=None, to=None, iif=None, oif=None, tos=None, dsfield=None, fwmark=None,
               priority=None, table=None, suppress_prefixlength=None, suppress_ifgroup=None, realms=None,
               nat=None, family=None, rule=None):
        kv_list = (
            'to', 'iif', 'oif', 'tos', 'dsfield', 'fwmark', 'priority', 'table', 'suppress_prefixlength',
            'suppress_ifgroup', 'realms', 'nat')
        kv_list_wrong_names = ('type', 'from')
        if rule and isinstance(rule, Rule):
            type_ = rule.type_
            from_ = rule.from_
            to = rule.to
            iif = rule.iif
            oif = rule.oif
            table = rule.table
            priority = rule.priority
        if not family:
            try:
                try:
                    option_ = ip_interface(locals().get('to').decode())
                except AttributeError:
                    option_ = ip_interface(locals().get('to'))
                family = family or option_.version
                locals()['to'] = str(option_)
            except ValueError:
                pass
        if not family:
            try:
                try:
                    option_ = ip_interface(locals().get('from_').decode())
                except AttributeError:
                    option_ = ip_interface(locals().get('from_'))
                family = family or option_.version
                locals()['from_'] = str(option_)
            except ValueError:
                pass
        env = locals()
        kv_opts = ((k, env.get(k, None)) for k in kv_list)
        opts = ()
        kv_opts = tuple([(k, env.get(k, None)) for k in kv_list] +
                        [(k, env.get('{}_'.format(k), None)) for k in kv_list_wrong_names])
        return self._action(action='delete', family=family, kv_opts=kv_opts, opts=opts)

    def flush(self, family=None):
        return self._action(action='flush', family=family, kv_opts=(), opts=())

    def show(self, family=None):
        stdout, stderr, returncode = self._action(action='show', family=family, kv_opts=(), opts=())
        res = []
        if returncode != 0:
            return res, stderr, returncode
        lines = (x.strip() for x in stdout.strip().split('\n'))
        pattern = re.compile(self.PATTERN_SHOW)
        for line in lines:
            if not line:
                continue
            row_match = pattern.match(line)
            if row_match:
                rule = Rule(
                    priority=row_match.group('priority'),
                    type_=None,
                    from_=row_match.group('from_'),
                    to=row_match.group('to'),
                    iif=row_match.group('iif'),
                    oif=row_match.group('oif'),
                    table=row_match.group('lookup'),
                )
                res.append(rule)
            else:
                logger.error('ip rule. Line with rule "{}" no matched. Need fix pattern.'.format(line))
        return res, stderr, returncode
