from pathlib import Path
import dpkt
from socket import inet_ntoa
from os import fsync

# global list of file handles for all the channels
_fileHandles = list()
__logFilesDir__ = Path().joinpath("logs")
__statFilesDir__ = Path().joinpath("stats")
__threshold__ = 200
__accessCounter__ = {}


class streamHandler(object):
    def __init__(self, channel_name):
        self.name = channel_name
        self._fh = Path().joinpath(self.name).open('wb')
        self.total = 0

    def add(self, ts, pkt):
        self.total += 1
        self._fh.write(pkt)

    def stats(self):
        return {'total': self.total}


class pCapHandling:
    def __init__(self, pcap_files):
        self._eth = None
        self.pcapFiles = pcap_files
        self._channels = {}

    def _flushData(self, fileHandle):
        fileHandle.flush()
        fsync(fileHandle.fileno())


    def _getLogFilepath(self, __fileName__):
        return Path().joinpath("logs").joinpath(__fileName__)


    def __writeData__(self, _channel, payLoad):
        _channel = self._getLogFilepath(_channel + ".log")
        if __accessCounter__.get(_channel, -123456789) == -123456789:
            __accessCounter__.update({_channel: 1})
            _channel = open(_channel, 'a')
            _channel.write(payLoad)
            _channel.close()
        elif __accessCounter__.get(_channel, -123456789) < __threshold__:
            __accessCounter__.update({_channel: __threshold__ + 1})
            _channel = open(_channel, 'a')
            _channel.write(payLoad)
            _channel.close()
        elif __accessCounter__.get(_channel, -123456789) > __threshold__:
            _channel.write(payLoad)
            self._flushData(_channel)
            __accessCounter__.update({_channel: __threshold__ + 1})
            if _channel not in _fileHandles:
                _fileHandles.append(_channel)
        """
        _channel = self.__getLogFilepath__(__fileHandle__ + ".log")
        __fileHandle__ = open(_channel, 'a')
        __fileHandle__.write(payLoad)
        # _fileHandles.append(__fileHandle__)
        # self.__flushData__(__fileHandle__)
        __fileHandle__.close()
        """

    def stats(self):
        stats = {}
        totals = {'total': 0}
        for cname, channel in self._channels.items():
            stats[cname] = channel.stats()
            totals['total'] += stats[cname]['total']
        stats['all'] = totals
        return stats

    def pCapProcessing(self):
        for pcap_file in self.pcapFiles:
            self.processPcap(pcap_file)
        return self.stats()

    def processPcap(self, pcap_file):
        for ts, buf in dpkt.pcap.Reader(pcap_file):
            _eth = dpkt.ethernet.Ethernet(buf)
            channel_name = 'other'
            if isinstance(_eth.data, dpkt.udp.UDP) or isinstance(_eth.data, dpkt.tcp.TCP):
                connectionType = "UDP"
                __sourceAddr__ = inet_ntoa(_eth.data.data.src)
                __destinationAddr__ = inet_ntoa(_eth.data.data.dst)
                channel_name = connectionType + '-' +__sourceAddr__ + '-' + __destinationAddr__

            if channel_name not in self._channels:
                self._channels[channel_name] = streamHandler(channel_name)

            self._channels[channel_name].add(ts, buf)


if __name__ == "__main__":
    pcaps = []
    for file in Path().joinpath('pcaps').iterdir():
        pcaps.append(file)
    phndler = pCapHandling(pcaps)
    stats = phndler.pCapProcessing()
