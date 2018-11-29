from pathlib import Path
import dpkt
from socket import inet_ntoa


class streamHandler(object):
    def __init__(self, channel_name):
        self.name = channel_name
        self._fh = Path().joinpath("logs").joinpath(self.name).open('wb')
        self.total = 0

    def add(self, ts, pkt):
        self._fh.write(pkt)
        
        self.total += 1

    def stats(self):
        return {'total': self.total}


class pCapHandling:
    def __init__(self, pcap_files):
        self._eth = None
        self.pcapFiles = pcap_files
        self._channels = {}


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
        for ts, buf in dpkt.pcap.Reader(open(pcap_file, 'rb')):
            _eth = dpkt.ethernet.Ethernet(buf)
            channelName = 'Other'
            if isinstance(_eth.data.data, dpkt.udp.UDP):
                connectionType = "UDP"
                _sourceAddr = inet_ntoa(_eth.data.src)
                _destinationAddr = inet_ntoa(_eth.data.dst)
                _sourcePort = _eth.data.data.sport
                _destinationPort = _eth.data.data.dport
            elif isinstance(_eth.data.data, dpkt.tcp.TCP):
                connectionType = "TCP"
            channelName = connectionType + '-' + _sourceAddr + '-' + \
                          _destinationAddr + '-' + str(_sourcePort) + '-' + \
                          str(_destinationPort)

            if channelName not in self._channels:
                self._channels[channelName] = streamHandler(channelName)

            self._channels[channelName].add(ts, buf)


if __name__ == "__main__":
    pcaps = []
    for file in Path().joinpath('pcaps').iterdir():
        pcaps.append(file)
    phndler = pCapHandling(pcaps)
    stats = phndler.pCapProcessing()
    for channel, count in stats.items():
        print("{} : {}".format(channel, count['total']))
