from pathlib import Path
import dpkt
from socket import inet_ntoa
import threading

channelTraffic = dict()
globalStats = dict()
threads = list()

class streamHandler:
    def __init__(self, channel_name):
        self.name = channel_name
        self._fh = open(Path().joinpath("logs").joinpath(self.name), 'wb')

    def add(self, ts, pkt):
        if self.name not in channelTraffic.keys():
            channelTraffic[self.name] = [(ts, pkt)]
            globalStats[self.name] = [1, len(pkt)]
        else:
            channelTraffic[self.name].append((ts, pkt))
            currentStat = globalStats[self.name]
            globalStats.update({self.name: [currentStat[0] + 1, currentStat[1] + len(pkt)]})
        while len(channelTraffic[self.name]):
            channelTraffic[self.name] = sorted(channelTraffic[self.name], key=lambda x: x[0])
            self._fh.write(channelTraffic[self.name][0][1])
            channelTraffic[self.name].pop(0)


class pCapHandling:
    def __init__(self, pcap_files):
        self._eth = None
        self.pcapFiles = pcap_files
        self._channels = {}

    def pCapProcessing(self):
        # threads = ["t#" + str(i) for i in range(0, len(self.pcapFiles))]
        for index, pcap_file in enumerate(self.pcapFiles):
            thread = threading.Thread(target=self.processPcap, args=(pcap_file,))
            thread.start()
            threads.append(thread)
        for _ in threads:
            _.join()
        return self

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
    phndler.pCapProcessing()
    for channel, stat in globalStats.items():
        # stat[0] = counter | stat[1] = bytes
        print("{} -- Count: {} | Bytes: {}".format(channel, stat[0], stat[1]))
