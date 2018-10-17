#!/usr/bin/env python

import logging
import re
import shlex
import subprocess
from collections import MutableMapping, Iterable

__author__ = 'craftyhunter'
__version__ = '0.3.5'
VERSION = tuple(map(int, __version__.split('.')))
__all__ = [
    'Iptables', 'IptablesPolicy', 'IptablesRule', 'IptablesTable', 'IptablesFragment',
    'IptablesMatch', 'IptablesInInterface', 'IptablesOutInterface', 'IptablesProtocol',
    'IptablesDestination', 'IptablesTarget', 'IptablesSource', 'IptablesChain', 'VERSION',
]

logger = logging.getLogger('')


class Iptables(object):
    __slots__ = ('__executor', '__table', '__chain', 'last_command')
    CMD_v4 = '/sbin/iptables'
    CMD_v6 = '/sbin/ip6tables'
    OPTS = (('wait', None), ('numeric', None), ('exact', None), ('line_numbers', None), ('verbose', None))
    TABLES = ('filter', 'nat', 'mangle', 'raw', 'security')
    DEF_CHAINS = ('PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING')

    def __init__(self, table=None, chain=None, executor=None):
        self.__executor = executor or self.__exec_popen
        self.__table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        self.__chain = chain

    def _action(self, action, additional, table, family=None):
        cmd = self.CMD_v6 if family == 6 else self.CMD_v4
        self.last_command = ' '.join([cmd, table, action, additional])
        return self.__executor(command=self.last_command)

    @staticmethod
    def __exec_popen(command):
        try:
            p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception as e:
            logger.warning('Error raised when iptables command was executed. Cmd: "{}". Raise: "{}"'.format(command, e))
            raise OSError('Command: "{cmd}" raise error: "{err}"'.format(cmd=command, err=e))
        else:
            stdout, stderr = p.communicate()
            returncode = p.returncode
        return stdout.decode('utf-8'), stderr.decode('utf-8'), returncode

    def _generate_opts_str(self, **kwargs):
        for key, default_value in self.OPTS:
            value = kwargs.get(key, default_value)
            if value is None or value is False:
                continue
            elif value is True:
                yield '--{}'.format(key)
            else:
                yield '--{} {}'.format(key, value)

    def append(self, table=None, chain=None, rule=None, target=None, source=None, not_source=None, destination=None,
               not_destination=None, protocol=None, not_protocol=None, in_interface=None, not_in_interface=None,
               goto=None, out_interface=None, not_out_interface=None, match=None, modprobe=None,
               fragment=False, not_fragment=False, wait=None, verbose=False, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        chain = chain or self.__chain
        if not table or not chain:
            raise ValueError(
                'append method call without required argument: "{}".'.format(
                    [x for x, y in (('table', table), ('chain', chain)) if not y]))
        elif rule:
            if not isinstance(rule, IptablesRule):
                raise ValueError('Argument "rule" must be IptablesRule class.')
        elif not target:
            raise ValueError('Append method call without required arguments: "target".')
        else:
            rule = IptablesRule(match=match, target=target, fragment=fragment)
            rule.source.append(source)
            rule.source.append(not_source)
            rule.destination.append(destination)
            rule.destination.append(not_destination)
            rule.protocol.append(protocol)
            rule.protocol.append(not_protocol)
            rule.in_interface.append(in_interface)
            rule.in_interface.append(not_in_interface)
            rule.out_interface.append(out_interface)
            rule.out_interface.append(not_out_interface)
        opts_str = ' '.join(self._generate_opts_str(kwargs=locals()))
        additional = ' '.join([str(chain), str(rule), opts_str])
        return self._action(table=str(table), action='-A', additional=additional, family=family)

    def check(self, table=None, chain=None, rule=None, target=None, source=None, not_source=None, destination=None,
              not_destination=None, protocol=None, not_protocol=None, in_interface=None, not_in_interface=None,
              goto=None, out_interface=None, not_out_interface=None, match=None, modprobe=None,
              fragment=False, not_fragment=False, wait=None, verbose=False, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        chain = chain or self.__chain
        if not table or not chain:
            raise ValueError(
                'check method call without required argument: "{}".'.format(
                    [x for x, y in (('table', table), ('chain', chain)) if not y]))
        elif rule:
            if not isinstance(rule, IptablesRule):
                raise ValueError('Argument "rule" must be IptablesRule class.')
        elif not target:
            raise ValueError('Append method call without required arguments: "target".')
        else:
            rule = IptablesRule(match=match, target=target, fragment=fragment)
            rule.source.append(source)
            rule.source.append(not_source)
            rule.destination.append(destination)
            rule.destination.append(not_destination)
            rule.protocol.append(protocol)
            rule.protocol.append(not_protocol)
            rule.in_interface.append(in_interface)
            rule.in_interface.append(not_in_interface)
            rule.out_interface.append(out_interface)
            rule.out_interface.append(not_out_interface)
        opts_str = ' '.join(self._generate_opts_str(kwargs=locals()))
        additional = ' '.join([str(chain), str(rule), opts_str])
        return self._action(table=str(table), action='-C', additional=additional, family=family)

    def delete(self, table=None, chain=None, rule=None, rulenum=None, target=None, source=None, destination=None,
               protocol=None, match=None, goto=None, in_interface=None, out_interface=None, modprobe=None,
               verbose=False, fragment=False, not_fragment=False, wait=None, numeric=False, exact=False,
               line_numbers=False, not_source=None, not_destination=None, not_protocol=None, not_in_interface=None,
               not_out_interface=None, extensions=None, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        chain = chain or self.__chain
        if not table or not chain:
            raise ValueError(
                'delete method call without required argument: "{}".'.format(
                    [x for x, y in (('table', table), ('chain', chain)) if not y]))
        elif rule:
            if not isinstance(rule, IptablesRule):
                raise ValueError('Argument "rule" must be IptablesRule class.')
        else:
            rule = IptablesRule(match=match, target=target, fragment=fragment)
            rule.source.append(source)
            rule.source.append(not_source)
            rule.destination.append(destination)
            rule.destination.append(not_destination)
            rule.protocol.append(protocol)
            rule.protocol.append(not_protocol)
            rule.in_interface.append(in_interface)
            rule.in_interface.append(not_in_interface)
            rule.out_interface.append(out_interface)
            rule.out_interface.append(not_out_interface)
        opts_str = ' '.join(self._generate_opts_str(kwargs=locals()))
        opts = [str(chain)]
        if rulenum:
            opts.extend([str(rulenum), opts_str])
        else:
            opts.extend([str(rule), opts_str])
        additional = ' '.join(opts)
        return self._action(table=str(table), action='-D', additional=additional, family=family)

    def insert(self, table=None, chain=None, rule=None, target=None, source=None, not_source=None, destination=None,
               not_destination=None, protocol=None, not_protocol=None, in_interface=None, not_in_interface=None,
               goto=None, out_interface=None, not_out_interface=None, match=None, modprobe=None,
               fragment=False, not_fragment=False, wait=None, verbose=False, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        chain = chain or self.__chain
        if not table or not chain:
            raise ValueError(
                'Append method call without required argument: "{}".'.format(
                    [x for x, y in (('table', table), ('chain', chain)) if not y]))
        elif rule:
            if not isinstance(rule, IptablesRule):
                raise ValueError('Argument "rule" must be IptablesRule class.')
        elif not target:
            raise ValueError('insert method call without required arguments: "target".')
        else:
            rule = IptablesRule(match=match, target=target, fragment=fragment)
            rule.source.append(source)
            rule.source.append(not_source)
            rule.destination.append(destination)
            rule.destination.append(not_destination)
            rule.protocol.append(protocol)
            rule.protocol.append(not_protocol)
            rule.in_interface.append(in_interface)
            rule.in_interface.append(not_in_interface)
            rule.out_interface.append(out_interface)
            rule.out_interface.append(not_out_interface)
        opts_str = ' '.join(self._generate_opts_str(kwargs=locals()))
        additional = ' '.join([str(chain), str(rule), opts_str])
        return self._action(table=str(table), action='-I', additional=additional, family=family)

    def replace(self, rulenum, table=None, chain=None, rule=None, target=None, source=None, not_source=None,
                destination=None, not_destination=None, protocol=None, not_protocol=None, in_interface=None,
                not_in_interface=None, goto=None, out_interface=None, not_out_interface=None, match=None,
                modprobe=None, fragment=False, not_fragment=False, wait=None, verbose=False, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        chain = chain or self.__chain
        if not table or not chain or not rulenum:
            raise ValueError(
                'replace method call without required argument: "{}".'.format(
                    [x for x, y in (('table', table), ('chain', chain), ('rulenum', rulenum)) if not y]))
        elif rule:
            if not isinstance(rule, IptablesRule):
                raise ValueError('Argument "rule" must be IptablesRule class.')
        else:
            rule = IptablesRule(match=match, target=target, fragment=fragment)
            rule.source.append(source)
            rule.source.append(not_source)
            rule.destination.append(destination)
            rule.destination.append(not_destination)
            rule.protocol.append(protocol)
            rule.protocol.append(not_protocol)
            rule.in_interface.append(in_interface)
            rule.in_interface.append(not_in_interface)
            rule.out_interface.append(out_interface)
            rule.out_interface.append(not_out_interface)
        opts_str = ' '.join(self._generate_opts_str(kwargs=locals()))
        opts = [str(chain)]
        if rulenum:
            opts.extend([str(rulenum), opts_str])
        else:
            opts.extend([str(rule), opts_str])
        additional = ' '.join(opts)
        return self._action(table=str(table), action='-R', additional=additional, family=family)

    def show(self, table=None, chain=None, verbose=False, wait=None, family=None, raw=False, record_type='all'):
        supported_types = ('rule', 'policy', 'chain')
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        if not table:
            raise ValueError('show method call without required argument: "table".')
        chain = chain or self.__chain
        opts_str = ' '.join(self._generate_opts_str(kwargs=locals()))
        opts = [opts_str]
        if chain:
            opts = [str(chain), opts_str]
        additional = ' '.join([str(_x) for _x in opts if _x])
        if isinstance(record_type, str) and record_type != 'all':
            record_type = (record_type, )
        elif record_type == 'all':
            record_type = supported_types
        stdout, stderr, returncode = self._action(table=str(table), action='-S', additional=additional, family=family)
        rules = []
        lines = (x.strip() for x in stdout.strip().split('\n') if x)
        for line in lines:
            if line.startswith('-A'):
                if 'rule' in record_type:
                    rules.append(IptablesRule(raw_line=line))
            elif line.startswith('-P'):
                if 'policy' in record_type:
                    rules.append(IptablesPolicy(raw_line=line))
            elif line.startswith('-N'):
                if 'chain' in record_type:
                    rules.append(IptablesChain(raw_line=line))
            else:
                logger.warning('Iptables show cannot parse row "{}".'.format(line))
                continue
        if raw:
            return [
                '{} {} {}'.format(x.PREFIX, x.chain, x) if isinstance(x, IptablesRule) else '{} {}'.format(x.PREFIX, x)
                for x in rules]
        return rules, stderr, returncode

    def list(self, table=None, chain=None, verbose=False, wait=None, numeric=False, line_numbers=False, exact=False,
             family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        chain = chain or self.__chain
        if not table:
            raise ValueError('list method call without required argument: "table".')
        opts_str = ' '.join(self._generate_opts_str(kwargs=locals()))
        opts = [str(table)]
        if chain:
            opts.append(str(chain))
        opts.append(opts_str)
        additional = ' '.join([str(_x) for _x in opts if _x])
        return self._action(table=str(table), action='-L', additional=additional, family=family)

    def zero(self, table=None, chain=None, rulenum=None, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        if not table:
            raise ValueError('zero method call without required argument: "table".')
        chain = chain or self.__chain
        opts = []
        if chain:
            opts.append(str(chain))
            if rulenum:
                opts.append(str(rulenum))
        additional = ' '.join([_x for _x in opts])
        return self._action(table=str(table), action='-Z', additional=additional, family=family)

    def new_chain(self, chain, table=None, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        if not table:
            raise ValueError('new_chain method call without required argument: "table".')
        return self._action(table=str(table), action='-N', additional=str(chain), family=family)

    def delete_chain(self, chain, table=None, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        if not table:
            raise ValueError('delete_chain method call without required argument: "table".')
        return self._action(table=str(table), action='-X', additional=str(chain), family=family)

    def rename_chain(self, old_chain, new_chain, table=None, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        if not table:
            raise ValueError('rename_chain method call without required argument: "table".')
        return self._action(
            table=str(table), action='-E', additional='{} {}'.format(str(old_chain), str(new_chain)), family=family)

    def flush(self, table=None, chain=None, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        if not table:
            raise ValueError('flush method call without required argument: "table".')
        opts = []
        if chain:
            opts.append(str(chain))
        additional = ' '.join([_x for _x in opts])
        return self._action(table=str(table), action='-F', additional=additional, family=family)

    def policy(self, table=None, policy=None, chain=None, target=None, family=None):
        table = table or self.__table
        table = table if isinstance(table, IptablesTable) else IptablesTable(table)
        chain = chain or self.__chain
        if not table:
            raise ValueError('policy method call without required argument: "table".')
        elif policy:
            if not isinstance(policy, IptablesPolicy):
                raise ValueError('Argument "rule" must be IptablesPolicy class.')
        elif [x for x in (chain, target) if not x]:
            raise ValueError(
                'Append method call without required arguments: {}.'.format([x for x in (chain, target) if not x]))
        else:
            policy = IptablesPolicy(chain=chain, target=target)
        return self._action(table=str(table), action='-P', additional=str(policy), family=family)


class MultiValue(object):
    """
    MultiValue(cls, arg1)
    MultiValue(cls, arg1, arg2)
    MultiValue(cls, arg1, key1: value1, key2: value2)
    MultiValue(cls, arg1, {key1: value1, key2: value2})
    MultiValue(cls, (arg1, arg2))
    MultiValue(cls, key1=value1, key2=value2)
    MultiValue(cls, {key1: value1, key2: value2})

    """
    __slots__ = ('__values', '_cls')
    PREFIX = ''

    def __init__(self, cls, *args, **kwargs):
        self.__values = list()
        self._cls = cls
        self.append(*args, **kwargs)

    def __contains__(self, value):
        objs = self.__prepare(value)
        if len(objs) > 0:
            obj = objs[0]
        else:
            return False
        if isinstance(obj, self._cls):
            return obj in self.__values
        else:
            return set(self.__values).issuperset(set(obj))

    def __iter__(self):
        for value in self.__values:
            yield value

    def __getitem__(self, item):
        return self.__values[item]

    def __repr__(self):
        return '{}({}, *{})'.format(
            self.__class__.__name__,
            getattr(self._cls, 'class_name', self._cls),
            self.__values)

    def __str__(self):
        return ' '.join([str(_x) for _x in self.__values])

    def __prepare(self, *args, **kwargs):
        res = list()
        for arg in args:
            if arg is None:
                continue
            elif isinstance(arg, self._cls):
                res.append(arg)
            elif not getattr(arg, 'pop', None) and not isinstance(arg, tuple):
                res.append(self._cls(arg))
            elif isinstance(arg, MutableMapping):
                res.append(self._cls(**arg))
            elif isinstance(arg, Iterable):
                res.extend(self.__prepare(*arg))
            else:
                raise Exception('Got wrong type "{}" of "{}"'.format(type(arg).__name__, arg))
        if kwargs:
            res.append(self._cls(**kwargs))
        return res

    def append(self, *args, **kwargs):
        self.__values.extend(self.__prepare(*args, **kwargs))

    def remove(self, *args, **kwargs):
        for obj in self.__prepare(*args, **kwargs):
            try:
                self.__values.remove(obj)
            except ValueError:
                pass

    @property
    def values(self):
        return self.__values

    @values.setter
    def values(self, value):
        if not value:
            self.__values = list()
            return
        self.append(value)


class IptablesRule(object):
    __slots__ = ('__source', '__destination', '__protocol', '__in_interface', '__out_interface', '__match',
                 '__target', '__fragment', 'chain')
    PREFIX = '-A'
    PATTERN_CHAIN = '-[AIR] (?P<chain>[a-zA-Z0-9_-]+)[ ]*(?P<other>.*)'
    PATTERN_SOURCE = '(?P<no>[!])?[ ]*-s (?P<src>[0-9a-f:/.]+)[ ]*(?P<other>.*)'
    PATTERN_DEST = '(?P<no>[!])?[ ]*-d (?P<dest>[0-9a-f:/.]+)[ ]*(?P<other>.*)'
    PATTERN_PROTOCOL = '(?P<no>[!])?[ ]*-p (?P<protocol>[0-9a-zA-Z_-]+)[ ]*(?P<other>.*)'
    PATTERN_FRAGMENT = '(?P<no>[!])?[ ]*--fragment[ \t]*(?P<other>.*)'
    PATTERN_OPTION = '(?P<no>[!])?[ ]*--[a-zA-Z0-9_]+[ ]?[a-zA-Z0-9_-]+[ \t]*(?P<other>.*)'
    PATTERN_TARGET_NAME = '-j (?P<jump>[a-zA-Z0-9_-]+)[ ]*(?P<other>.*)'
    PATTERN_MATCH_NAME = '(?P<with_prefix>-m (?P<match>[a-zA-Z0-9_-]+)[ ]*(?P<other>.*))'

    def __init__(
            self, target=None, source=None, destination=None, in_interface=None, chain=None,
            out_interface=None, protocol=None, match=None, fragment=None, raw_line=None):
        self.__source = source if isinstance(source, MultiValue) else MultiValue(IptablesSource, source)
        if isinstance(destination, MultiValue):
            self.__destination = destination
        else:
            self.__destination = MultiValue(IptablesDestination, destination)
        self.__protocol = protocol if isinstance(protocol, MultiValue) else MultiValue(IptablesProtocol, protocol)
        self.__match = match if isinstance(match, MultiValue) else MultiValue(IptablesMatch, match)
        if isinstance(in_interface, MultiValue):
            self.__in_interface = in_interface
        else:
            self.__in_interface = MultiValue(IptablesInInterface, in_interface)
        if isinstance(out_interface, MultiValue):
            self.__out_interface = out_interface
        else:
            self.__out_interface = MultiValue(IptablesOutInterface, out_interface)
        self.__target = target if isinstance(target, IptablesTarget) else IptablesTarget(
            target=target) if target else ''
        if isinstance(fragment, IptablesFragment):
            self.__fragment = fragment
        else:
            self.__fragment = IptablesFragment(fragment) if fragment else ''
        self.chain = chain
        if raw_line:
            self._string_to_rule(raw_line)

    def __hash__(self):
        return hash((str(self),))

    def __eq__(self, other):
        return hash(self) == hash(other)

    @property
    def source(self):
        return self.__source

    @source.setter
    def source(self, value):
        self.__source = MultiValue(IptablesSource, value)

    @property
    def destination(self):
        return self.__destination

    @destination.setter
    def destination(self, value):
        self.__destination = MultiValue(IptablesDestination, value)

    @property
    def in_interface(self):
        return self.__in_interface

    @in_interface.setter
    def in_interface(self, value):
        self.__in_interface = MultiValue(IptablesInInterface, value)

    @property
    def out_interface(self):
        return self.__out_interface

    @out_interface.setter
    def out_interface(self, value):
        self.__out_interface = MultiValue(IptablesOutInterface, value)

    @property
    def protocol(self):
        return self.__protocol

    @protocol.setter
    def protocol(self, value):
        self.__protocol = MultiValue(IptablesProtocol, value)

    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        self.__target = value if isinstance(value, IptablesTarget) else IptablesTarget(value) if value else ''

    @property
    def fragment(self):
        return self.__fragment

    @fragment.setter
    def fragment(self, value):
        if isinstance(value, IptablesFragment):
            self.__fragment = value
        else:
            self.__fragment = IptablesFragment(value) if value else ''

    @property
    def match(self):
        return self.__match

    @match.setter
    def match(self, value):
        self.__match = MultiValue(IptablesMatch, value)

    def _string_to_rule(self, rule_str):
        max_iteration = 100
        i = 0
        while rule_str:
            i += 1
            if i > max_iteration:
                break
            rule_str = rule_str.strip()
            if rule_str.startswith('-s ') or rule_str.startswith('! -s '):
                match = re.match(self.PATTERN_SOURCE, rule_str)
                if match:
                    self.source.append(
                        address=match.group('src'),
                        negative=True if match.group('no') else False)
                    rule_str = match.group('other')
                else:
                    logger.error('source pattern with string: "{}".'.format(rule_str))
            elif rule_str.startswith('-d ') or rule_str.startswith('! -d '):
                match = re.match(self.PATTERN_DEST, rule_str)
                if match:
                    self.destination.append(
                        address=match.group('dest'),
                        negative=True if match.group('no') else False)
                    rule_str = match.group('other')
                else:
                    logger.error('dest pattern with string: "{}"'.format(rule_str))
            elif rule_str.startswith('-p ') or rule_str.startswith('! -p '):
                match = re.match(self.PATTERN_PROTOCOL, rule_str)
                if match:
                    self.protocol.append(
                        protocol=match.group('protocol'),
                        negative=True if match.group('no') else False)
                    rule_str = match.group('other')
                else:
                    logger.error('protocol pattern with string: "{}"'.format(rule_str))
            elif rule_str.startswith('-m '):
                match = re.match(self.PATTERN_MATCH_NAME, rule_str)
                if match:
                    m = IptablesMatch(match.group('match'), raw_line=match.group('with_prefix'))
                    self.match.append(m)
                    rule_str = rule_str.replace(str(m), '', 1).strip()
                else:
                    logger.error('match pattern with string: "{}"'.format(rule_str))
            elif rule_str.startswith('-j '):
                match = re.match(self.PATTERN_TARGET_NAME, rule_str)
                if match:
                    self.target = IptablesTarget(match.group('jump'), raw_line=match.group('other'))
                    rule_str = rule_str.replace(str(self.target), '', 1).strip()
                else:
                    logger.error('target pattern with string: "{}"'.format(rule_str))
            elif rule_str.startswith('-A '):
                match = re.match(self.PATTERN_CHAIN, rule_str)
                if match:
                    self.chain = match.group('chain')
                    rule_str = match.group('other')
                else:
                    logger.error('chain pattern with string: "{}"'.format(rule_str))
            elif rule_str.startswith('--fragment') or rule_str.startswith('! --fragment'):
                match = re.match(self.PATTERN_FRAGMENT, rule_str)
                if match:
                    self.fragment = False if match.group('no') else True
                    rule_str = match.group('other')
                else:
                    logger.error('fragment pattern with string: "{}"'.format(rule_str))
            elif rule_str.startswith('--'):
                match = re.match(self.PATTERN_OPTION, rule_str)
                if match:
                    rule_str = match.group('other')
                else:
                    logger.error('option pattern with string: "{}"'.format(rule_str))
            else:
                logger.critical('Can not parse string: "{}"'.format(rule_str))
                rule_str = None
                # raise Exception('Can not parse string: "{}"'.format(rule_str))
                # goto = var_goto, modprobe = var_modprobe

    def __str__(self):
        opts = ('source', 'destination', 'in_interface',
                'out_interface', 'protocol', 'match', 'fragment', 'target')
        opts = (getattr(self, x, '') for x in opts)
        opts = (str(x) for x in opts if x)
        return ' '.join((x for x in opts if x))

    def __repr__(self):
        opts = ('source', 'destination', 'in_interface',
                'out_interface', 'protocol', 'match', 'fragment', 'target')
        vals = {x: repr(getattr(self, x, None)) for x in opts if str(getattr(self, x, ''))}
        opts = ('{}={}'.format(x, vals.get(x, None)) for x in opts)
        return '{}({})'.format(self.__class__.__name__, ', '.join(opts))


class IptablesPolicy(object):
    __slots__ = ('chain', 'target')
    PREFIX = '-P'
    PATTERN_POLICY = '-P[ ]*(?P<chain>[a-zA-Z0-9_-]+)[ ]*(?P<target>[a-zA-Z0-9_]+).*'

    def __init__(self, chain=None, target=None, raw_line=None):
        env = locals()
        if raw_line:
            self.__parse(raw_line)
        elif chain and target:
            self.chain = chain
            self.target = target if isinstance(target, IptablesTarget) else IptablesTarget(target)
        else:
            raise ValueError(
                'Cannot create IptablesPolicy without required args: {}.'.format(
                    [x for x in self.__slots__ if not env.get(x)]))

    def __parse(self, rule_str):
        match = re.match(self.PATTERN_POLICY, rule_str)
        if match:
            self.chain = match.group('chain')
            self.target = IptablesTarget(match.group('target'))
        else:
            raise Exception('Can not match POLICY with pattern "{}" from string: "{}"'.format(
                self.PATTERN_POLICY, rule_str))

    def __str__(self):
        opts = [self.chain, self.target.name]
        return ' '.join([_x for _x in opts if _x])

    def __repr__(self):
        opts = ((x, getattr(self, x, None)) for x in self.__slots__)

        return '{}({})'.format(
            self.__class__.__name__,
            ', '.join(('{}="{}"'.format(x, y) if isinstance(y, str) else '{}={}'.format(x, repr(y)) for x, y in
                       opts)))


class IptablesChain(object):
    __slots__ = ('chain', )
    PREFIX = '-N'
    PATTERN_CHAIN = '-N[ ]*(?P<chain>[a-zA-Z0-9_-]+).*'

    def __init__(self, chain=None, raw_line=None):
        if raw_line:
            self.__parse(raw_line)
        elif chain:
            self.chain = chain
        else:
            raise ValueError('Cannot create IptablesPolicy without required args: {}.'.format(['chain']))

    def __parse(self, rule_str):
        match = re.match(self.PATTERN_CHAIN, rule_str)
        if match:
            self.chain = match.group('chain')
        else:
            raise Exception('Can not match POLICY with pattern "{}" from string: "{}"'.format(
                self.PATTERN_CHAIN, rule_str))

    def __str__(self):
        return str(self.chain)

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, 'chain="{}"'.format(self.chain))


class IptablesTarget(object):
    __slots__ = ('__name', '__cnf', '__v')
    PREFIX = '-j'
    PATTERN_NAME = '-j[ ]*(?P<target>[0-9a-zA-Z:./]+).*'
    IPTABLES_TARGETS = {
        'ACCEPT': {},
        'DROP': {},
        'REJECT': {},
        'RETURN': {},
        'MASQUERADE': {},
        'SNAT': {
            'kv_opts': {'to_source': {'name': 'to-source', 'required': True}},
            'opts': {'random': {}, 'persistent': {}},
            'pattern': '(-j SNAT)?[ ]*--to-source[ ]*(?P<to_source>[0-9a-f:./]+)[ ]*'
                       '([-]*(?P<random>random))?[ ]*'
                       '([-]*(?P<persistent>persistent))?.*'},
        'DNAT': {
            'kv_opts': {'to_destination': {'name': 'to-destination', 'required': True}},
            'opts': {'random': {}, 'persistent': {}},
            'pattern': '(-j DNAT)?[ ]*--to-destination[ ]*(?P<to_destination>[0-9a-f:./]+)[ ]*'
                       '([-]*(?P<random>random))?[ ]*'
                       '([-]*(?P<persistent>persistent))?.*'},

    }

    def __init__(self, target=None, raw_line=None, **kwargs):
        self.__name = ''
        self.__cnf = {}
        self.__v = {}
        opts = {}
        if isinstance(target, MutableMapping):
            self.__name, opts = target.popitem()
            if not isinstance(opts, MutableMapping):
                raise ValueError('Options of target in IptablesTarget must be dict. Opts: {}'.format(opts))
        elif target is not None:
            self.__name = target
            # raise ValueError('Cannot create IptablesTarget from type {}'.format(type(target)))
        elif not raw_line:
            raise ValueError('For create IptablesTarget must be specified or target or raw_line')
        if raw_line and not opts:
            if not self.__name:
                match = re.match(self.PATTERN_NAME, raw_line)
                if match:
                    self.__name = match.group('target')
            pattern = self.IPTABLES_TARGETS.get(self.name, {}).get('pattern')
            if pattern:
                match = re.match(pattern, raw_line)
                if match:
                    opts = match.groupdict()
                else:
                    opts = {}
        self.__cnf = self.IPTABLES_TARGETS.get(self.__name, {})
        for opt, opt_parameters in self.__cnf.get('kv_opts', {}).items():
            if opt in opts:
                self.__v[opt] = opts[opt]
            elif opt in kwargs:
                self.__v[opt] = kwargs[opt]
            elif opt_parameters.get('required', False):
                raise ValueError('Can not get required parameter "{}".'.format(opt))
            else:
                self.__v[opt] = False
        for opt, opt_parameters in self.__cnf.get('opts', {}).items():
            if opt in opts:
                self.__v[opt] = True if opts[opt] else False
            elif opt in kwargs:
                self.__v[opt] = True if kwargs[opt] else False
            elif opt_parameters.get('required', False):
                raise ValueError('Can not get required parameter "{}".'.format(opt))
            else:
                self.__v[opt] = None

    def __getattr__(self, item):
        cls = self.__class__
        if item not in self.__v:
            raise AttributeError('{.__name__!r} object has no attribute {!r}'.format(cls, item))
        return self.__v[item]

    def __str__(self):
        opts = [self.PREFIX, self.name]
        opts_ = ((v.get('name', k), self.__v.get(k)) for k, v in self.__cnf.get('kv_opts', {}).items())
        opts.extend(['--{} {}'.format(k, v) for k, v in opts_ if v])
        opts_ = ((v.get('name', k), self.__v.get(k)) for k, v in self.__cnf.get('opts', {}).items())
        opts.extend(['--{}'.format(k) for k, v in opts_ if v])
        return ' '.join(opts)

    def __repr__(self):
        opts = ['target="{}"'.format(self.name)]
        opts.extend('{}={}'.format(x, y) if x in self.__cnf.get('opts', {}) else '{}="{}"'.format(x, y) for x, y in
                    self.__v.items())
        return '{}({})'.format(self.__class__.__name__, ', '.join(opts))

    @property
    def name(self):
        return self.__name


class IptablesMatch(object):
    """
    IptablesMatch(match='multiport', dports=80)
    IptablesMatch(match={'multiport': {'dports': 80, 'sports': 80}})
    IptablesMatch(match='multiport', **{'dports': 80, 'sports': 80})
    IptablesMatch(raw_line='-m comment --comment animalsv2')
    """
    class_name = 'IptablesMatch'
    __slots__ = ('__name', '__cnf', '__v')
    PREFIX = '-m'
    PATTERN_NAME = '-m[ ]*(?P<match>[0-9a-zA-Z:./]+).*'
    IPTABLES_MATCHES = {
        'comment': {
            'kv_opts': {'comment': {'required': True}},
            'opts': {},
            'pattern': '(-m comment )?--comment (?P<comment>[0-9a-z_:./]+).*'
        },
        'multiport': {
            'kv_opts': {'ports': {}, 'dports': {}, 'sports': {}},
            'opts': {},
            'pattern': '-m multiport '
                       '(--dports (?P<dports>[0-9a-z_:.,/]+))?'
                       '(--sports (?P<sports>[0-9a-z_:.,/]+))?'
                       '(--ports (?P<ports>[0-9a-z_:.,/]+))?.*'
        }
    }

    def __init__(self, match=None, raw_line=None, **kwargs):
        self.__name = ''
        self.__cnf = {}
        self.__v = {}
        opts = {}
        if isinstance(match, MutableMapping):
            self.__name, opts = match.popitem()
            if not isinstance(opts, MutableMapping):
                raise ValueError('Options of target in IptablesMatch must be dict. Opts: {}'.format(opts))
        elif match is not None:
            self.__name = match
            # raise ValueError('Cannot create IptablesMatch from type {}'.format(type(match)))
        elif not raw_line:
            raise ValueError('For create IptablesMatch must be specified or match or raw_line')
        if raw_line and not opts:
            if not self.__name:
                match = re.match(self.PATTERN_NAME, raw_line)
                if match:
                    self.__name = match.group('match')
            pattern = self.IPTABLES_MATCHES.get(self.name, {}).get('pattern')
            if pattern:
                match = re.match(pattern, raw_line)
                if match:
                    opts = match.groupdict()
                else:
                    opts = {}
        self.__cnf = self.IPTABLES_MATCHES.get(self.__name, {})
        for opt, opt_parameters in self.__cnf.get('kv_opts', {}).items():
            if opt in opts:
                self.__v[opt] = opts[opt]
            elif opt in kwargs:
                self.__v[opt] = kwargs[opt]
            elif opt_parameters.get('required', False):
                raise ValueError('Can not get required parameter "{}".'.format(opt))
            else:
                self.__v[opt] = None
            if not any((self.__v[opt] is None, isinstance(self.__v[opt], bool))):
                self.__v[opt] = str(self.__v[opt])
        for opt, opt_parameters in self.__cnf.get('opts', {}).items():
            if opt in opts:
                self.__v[opt] = True if opts[opt] else False
            elif opt in kwargs:
                self.__v[opt] = True if kwargs[opt] else False
            elif opt_parameters.get('required', False):
                raise ValueError('Can not get required parameter "{}".'.format(opt))
            else:
                self.__v[opt] = None
            if not any((self.__v[opt] is None, isinstance(self.__v[opt], bool))):
                self.__v[opt] = str(self.__v[opt])

    def __getattr__(self, item):
        cls = self.__class__
        if item not in self.__v:
            raise AttributeError('{.__name__!r} object has no attribute {!r}'.format(cls, item))
        return self.__v[item]

    def __gt__(self, other):
        return str(self) > str(other)

    def __str__(self):
        opts = [self.PREFIX, self.name]
        opts_ = ((v.get('name', k), self.__v.get(k)) for k, v in self.__cnf.get('kv_opts', {}).items())
        opts.extend(['--{} {}'.format(k, v) for k, v in opts_ if v])
        opts_ = ((v.get('name', k), self.__v.get(k)) for k, v in self.__cnf.get('opts', {}).items())
        opts.extend(['--{}'.format(k) for k, v in opts_ if v])
        return ' '.join(opts)

    def __repr__(self):
        opts = ['match="{}"'.format(self.name)]
        for k, v in self.__v.items():
            if k in self.__cnf.get('opts', {}):
                opts.append('{}'.format(k))
            elif v is None or isinstance(v, bool):
                opts.append('{}={}'.format(k, None))
            else:
                opts.append('{}="{}"'.format(k, v))
        return '{}({})'.format(self.__class__.__name__, ', '.join(opts))

    def __hash__(self):
        return hash((self.__name, tuple((x for x in sorted((x for x in self.__v.values() if x))))))

    def __eq__(self, other):
        return hash(self) == hash(other)

    @property
    def name(self):
        return self.__name


class IptablesFragment(object):
    class_name = 'IptablesFragment'
    __slots__ = ('fragment', 'negative')
    PREFIX = '--'

    def __init__(self, fragment=False, negative=False):
        for arg in self.__slots__:
            value = locals().get(arg, False)
            setattr(self, arg, value)

    def __str__(self):
        return '{}{}{}'.format(
            '! ' if getattr(self, 'negative', None) else '',
            '{}'.format(self.PREFIX),
            '{}'.format(self.__slots__[0] if self.__slots__ else ''))

    def __repr__(self):
        return '{}({})'.format(
            self.__class__.__name__,
            ', '.join(('{}={}'.format(x, getattr(self, x, False)) for x in self.__slots__)))


class IptablesParameter(object):
    __slots__ = ()
    PREFIX = ''

    def __init__(self, **kwargs):
        for arg in self.__slots__:
            value = kwargs.get(arg, None)
            setattr(self, arg, value)

    def __str__(self):
        opts = [
            '!' if getattr(self, 'negative', None) else '',
            '{p}'.format(p=self.PREFIX) if self.PREFIX else '']
        for opt in self.__slots__:
            if opt == 'negative':
                continue
            value = getattr(self, opt, None)
            if not value:
                continue
            opts.append(value)
        return ' '.join([str(_x) for _x in opts if _x])

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        return hash(tuple((getattr(self, x) for x in self.__slots__)))

    def __repr__(self):
        opts = ((x, getattr(self, x, None)) for x in self.__slots__)
        return '{}({})'.format(
            self.__class__.__name__,
            ', '.join(('{}="{}"'.format(x, y) if isinstance(y, str) else '{}={}'.format(x, repr(y)) for x, y in
                       opts)))


class IptablesTable(IptablesParameter):
    __slots__ = ('table', )
    PREFIX = '-t'

    def __init__(self, table):
        super(IptablesTable, self).__init__(table=table)


class IptablesSource(IptablesParameter):
    class_name = 'IptablesSource'
    __slots__ = ('address', 'negative')
    PREFIX = '-s'

    def __init__(self, address, negative=False):
        super(IptablesSource, self).__init__(address=address, negative=negative)


class IptablesDestination(IptablesParameter):
    class_name = 'IptablesDestination'
    __slots__ = ('address', 'negative')
    PREFIX = '-d'

    def __init__(self, address, negative=False):
        super(IptablesDestination, self).__init__(address=address, negative=negative)


class IptablesProtocol(IptablesParameter):
    class_name = 'IptablesProtocol'
    __slots__ = ('protocol', 'negative')
    PREFIX = '-p'

    def __init__(self, protocol, negative=False):
        super(IptablesProtocol, self).__init__(protocol=protocol, negative=negative)


class IptablesInInterface(IptablesParameter):
    class_name = 'IptablesInInterface'
    __slots__ = ('interface', 'negative')
    PREFIX = '-i'

    def __init__(self, interface, negative=False):
        super(IptablesInInterface, self).__init__(interface=interface, negative=negative)


class IptablesOutInterface(IptablesParameter):
    class_name = 'IptablesOutInterface'
    __slots__ = ('interface', 'negative')
    PREFIX = '-o'

    def __init__(self, interface, negative=False):
        super(IptablesOutInterface, self).__init__(interface=interface, negative=negative)
