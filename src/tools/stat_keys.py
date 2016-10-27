#!/usr/bin/env python

import collections
import sys

import rdbtools


class StatsReporter(object):
    def __init__(self):
        self._byte_stats = collections.defaultdict(int)
        self._count_stats = collections.defaultdict(int)
        self._counter = 0

    def next_record(self, record):
        if record.key is None:
            return  # some records are not keys (e.g. dict)
        if record.database != 0:
            raise Exception("Unknown DB record")
        key_type = record.key[:record.key.index(':')]
        self._count_stats[key_type] += 1
        self._byte_stats[key_type] += record.bytes
        self._counter += 1
        if self._counter % 1000 == 0:
            self.print_summary()

    def print_summary(self):
        print('-' * 50)
        total_bytes = sum(self._byte_stats.itervalues())
        total_entries = sum(self._count_stats.itervalues())
        print('Total {} entries and {} bytes'.format(
            total_entries, total_bytes))
        for key in self._count_stats.iterkeys():
            print("{} - {}({} %) entries; {} ({}%) bytes; Avg size {} ".format(
                key,
                self._count_stats[key],
                (self._count_stats[key] * 100.) / total_entries,
                self._byte_stats[key],
                (self._byte_stats[key] * 100.) / total_bytes,
                float(self._byte_stats[key]) / self._count_stats[key]))


def main():
    if len(sys.argv) != 2:
        print 'Usage: stat_keys.py <rdb_file_path>'
        return
    dump_file = sys.argv[1]
    reporter = StatsReporter()
    callback = rdbtools.MemoryCallback(reporter, 64)
    parser = rdbtools.RdbParser(callback)
    parser.parse(dump_file)
    print '=============FINISHED!==============='
    reporter.print_summary()

if __name__ == '__main__':
    main()
