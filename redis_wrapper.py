#!/usr/bin/env python

import copy
import ipaddress
import logging
import pickle
import six
import time

from collections import defaultdict
from itertools import chain
from redis.lock import Lock, LockError


__author__ = 'craftyhunter'
__version__ = '0.1.0'
VERSION = tuple(map(int, __version__.split('.')))
__all__ = [
    'RedisLock', 'RedisHashTable', 'VERSION',
]

logger = logging.getLogger('')


class RedisLock(Lock):
    """
    Simple Redis LuaLock with metrics lock using.
    Metrics:
        'acquired': 0,              # count success acquire locks
        'acquired_fail': 0,         # count fail attempts to acquire lock
        'released': 0,              # count release locks
        'released_by_timeout': 0,   # count attempts to release already released lock
        'wait_{}': 0.0,             # count locks in range from time_histogram_intervals_list
        'lock_{}': 0.0,             # count waits in range from time_histogram_intervals_list

    """
    __slots__ = ('__metrics', '__lock_acquired_time')
    baskets_with_time_intervals = (
        1, 5, 10, 20, 50, 100, 200, 300, 400, 500, 600, 700, 800, 900,
        1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000, 10000,
    )

    def __init__(self, **kwargs):
        super(RedisLock, self).__init__(**kwargs)
        self.__lock_acquired_time = None
        self.__metrics = defaultdict(int)

    def __enter__(self):
        if not self.acquire():
            raise LockError('Can\'t acquire lock {}'.format(self.name))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

    def get_interval_for_time(self, t):
        for t1 in self.baskets_with_time_intervals:
            if t <= t1:
                return t1
        else:
            return 'slow'

    def acquire(self, **kwargs):
        if not self.__lock_acquired_time:
            self.__lock_acquired_time = time.time()
            acquired = self.acquire(**kwargs)
            wait_time = (time.time() - self.__lock_acquired_time) * 1000
            if not acquired:
                self.__metrics['acquired_fail'] += 1
                self.__metrics['wait_{}'.format(self.get_interval_for_time(wait_time))] += 1
                raise LockError('Can\'t acquire lock {}'.format(self.name))
            self.__metrics['acquired'] += 1
            self.__metrics['wait_{}'.format(self.get_interval_for_time(wait_time))] += 1
        return True

    def release(self):
        if self.__lock_acquired_time is not None:
            try:
                self.release()
            except LockError:
                locked_time = time.time() - self.__lock_acquired_time
                if locked_time > self.timeout:
                    self.__metrics['released_by_timeout'] += 1
                metric_name = 'lock_{}'.format(self.get_interval_for_time(self.timeout * 1000))
                self.__metrics[metric_name] += 1
                raise
            else:
                metric_name = 'lock_{}'.format(
                    self.get_interval_for_time((time.time() - self.__lock_acquired_time) * 1000)
                )
                self.__metrics[metric_name] += 1
                self.__metrics['released'] += 1
            finally:
                self.__lock_acquired_time = None
        return True

    @property
    def metrics(self):
        return copy.deepcopy(self.__metrics)


# TODO: add hscan
class RedisHashTable(dict):
    """
    Provide simple access to Redis hashes as python dict.
    You can set functions to pack and unpack key or value data.
    Example: you wants store in redis json or pickled data.
    """
    __slots__ = ('_redis_conn', 'name', '__kpf', '__kuf', '__vpf', '__vuf')

    def __init__(
            self, redis_conn, table,
            key_pack_func=None, key_unpack_func=None, value_pack_func=None, value_unpack_func=None):
        super(RedisHashTable, self).__init__()
        self.__kpf = key_pack_func or str
        self.__kuf = key_unpack_func or str
        self.__vpf = value_pack_func or str
        self.__vuf = value_unpack_func or str
        self._redis_conn = redis_conn
        self.name = table

    def __contains__(self, item):
        return self._redis_conn.hexists(name=self.name, key=self.__kpf(item))

    def __delete__(self, instance):
        return bool(self._redis_conn.hdel(self.name, self.__kpf(instance)))

    def __getitem__(self, y):
        v = self._redis_conn.hget(name=self.name, key=self.__kpf(y))
        if v is None:
            raise KeyError(y)
        return None if v == 'None' else self.__vuf(v)

    def __iter__(self):
        return self.keys()

    def __len__(self):
        return self._redis_conn.hlen(name=self.name)

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, self.name)

    def __setitem__(self, i, y):
        return self._redis_conn.hset(self.name, self.__kpf(i), self.__vpf(y))

    def __str__(self):
        return '{}({})'.format(self.__class__.__name__, self.name)

    def clear(self):
        return bool(self._redis_conn.delete(self.name))

    def get(self, k, d=None):
        v = self._redis_conn.hget(name=self.name, key=self.__kpf(k))
        if v is None:
            return d
        return None if v == 'None' else self.__vuf(v)

    def has_key(self, k):
        return self.__contains__(k)

    def items(self):
        return ((self.__kuf(field), None if value == 'None' else self.__vuf(value)) for field, value in six.iteritems(
            self._redis_conn.hgetall(name=self.name)))

    def keys(self):
        return (self.__kuf(field) for field in self._redis_conn.hkeys(name=self.name))

    def values(self):
        return (None if value == 'None' else self.__vuf(value) for value in self._redis_conn.hvals(name=self.name))

    def update(self, E=None, **kwargs):
        self._redis_conn.hmset(
            self.name,
            {self.__kpf(k): self.__vpf(v) for k, v in chain(six.iteritems(E), six.iteritems(kwargs))}
        )

    def as_dict(self):
        return dict(self.items())


class RedisHashTableWithTime(RedisHashTable):
    """
    Adds to RedisHashTable key modified time.
    """
    __slots__ = ('_table_name_modify_time', )

    def __init__(self, table_name_modify_time, **kwargs):
        super(RedisHashTableWithTime, self).__init__(**kwargs)
        self._table_name_modify_time = table_name_modify_time

    def __delete__(self, instance):
        self.__touch_mtime(instance)
        return super(RedisHashTableWithTime, self).__delete__(instance)

    def __setitem__(self, i, y):
        self.__touch_mtime(i)
        return super(RedisHashTableWithTime, self).__setitem__(i, y)

    def update(self, E=None, **kwargs):
        for k in chain(E.keys(), kwargs.keys()):
            self.__touch_mtime(k)
        return super(RedisHashTableWithTime, self).update(E=E, **kwargs)

    def __touch_mtime(self, key):
        return self._redis_conn.hset(self._table_name_modify_time, self.__kpf(key), time.time())

    def mtime(self, key):
        try:
            return float(self._redis_conn.hget(self._table_name_modify_time, self.__kpf(key)))
        except (ValueError, TypeError):
            return 0.0


class RedisPickledDataExample(RedisHashTableWithTime):
    """
        {
            "ip_address": {
                "var1": "val1",
                "var2": "val2",
                "var3": "var3",
            }
        }
    """
    __slots__ = ()
    table_name_data = 'prefix_table.table_name'
    value_keys = ('var1', 'var2', 'var3')
    table_name_modify_time = 'prefix_table.table_name_last_active'

    def __init__(self, redis_conn):
        super(RedisPickledDataExample, self).__init__(
            redis_conn=redis_conn,
            table=self.table_name_data,
            table_name_modify_time=self.table_name_modify_time,
            key_pack_func=str,
            key_unpack_func=self.to_ip_address,
            value_pack_func=pickle.dumps,
            value_unpack_func=pickle.loads,
        )

    @staticmethod
    def to_ip_address(address):
        """
        Convert str, int representation of ip address to ipaddress object
        :param address:
        :return ipaddress._BaseAddress:
        """
        if not isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            try:
                address = int(address)
            except ValueError:
                try:
                    address = six.u(address)
                except TypeError:
                    pass
            finally:
                return ipaddress.ip_address(address)
        return address

    def filtered(self, **kwargs):
        conditions = {k: v for k, v in kwargs.items() if k in self.value_keys}
        for client_ip, client_data in self.items():
            if conditions == {k: v for k, v in client_data.items() if k in conditions}:
                yield client_ip, client_data


