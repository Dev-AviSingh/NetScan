import socket
from platform import system
from threading import Thread
import time
import subprocess
from uuid import getnode

class Scanner:
    def __init__(self, timeout = 7):
        self.__doc__ = """The module scans the local network with the help of a basic TCP handshake, it tries to check the domain name of the device. The mac address of the hosts available is checked with the help of the ARP table in the system's cache."""
        self.activeIps = []
        self.activeDevices = []
        self.activeMacs = []
        self.threads = []
        self.timeout = timeout
        
        ipcheck = socket.socket()
        ipcheck.connect(('www.google.com', 443))
        
        self.deviceIp = ipcheck.getsockname()[0]
        self.deviceMac = ':'.join(("%012X" % getnode())[i:i+2] for i in range(0, 12, 2))
        
        self.ip = "192.168.0.1"

        self.splitip = self.ip.split(".")
        self.timetaken = 0
        del ipcheck

    def checkActivity(self, ip, port):
        __doc__ = "The function is a worker for the threads created in the startScan function."
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#Creates a socket only for the ip address provided to it
        try:
            s.connect((ip, port))# Tries to connect to the host to be tested
            self.activeIps.append(ip)# If successful it means that the host is present and is thus added to the activeIps list
            s.close()
        except ConnectionRefusedError:
            self.activeIps.append(ip)# If the host refuses it means that someone was there to refuse it thus it means that the host is present
        except socket.error as e:pass
        s.close()

    def startScan(self, port = 5050):
        __doc__ = "The hosts are scanned by creating a seperate thread for all the individual 255 hosts."
        socket.setdefaulttimeout(self.timeout)
        start = time.time()
        for x in range(1, 256):
            ip = self.splitip[0] + "." + self.splitip[1] + "." + self.splitip[2] + "." + str(x)    
            t = Thread(target = self.checkActivity, args = (ip, port + x))
            t.start()
            self.threads.append(t)

        for x in self.threads:
            x.join()
        end = time.time()

        self.activeIps = sorted(self.activeIps)# Is the first data to be found and all the other details are found as per the IPS thus it is sorted so that every other list is sorted

        self.timetaken = end - start
        

    def scanNames(self):
        __doc__ = "The function tries to check the domain name of the remote host."
        for x in self.activeIps:
            self.activeDevices.append(socket.getfqdn(x))
        

    def scanMac(self):
        __doc__ = "The function checks the mac address of the remote host by checking in the ARP cache of the system."
        for ip in self.activeIps:
            if ip == self.deviceIp:
                self.activeMacs.append(self.deviceMac)
                continue
            
            check = subprocess.check_output("arp -a", shell = True).decode("utf-8")
            #--------------- A simple code to search for the mac address--------
            pos = check.find(ip)
            macpos = (15 - len(ip)) + 7 + pos + len(ip)
            mac = check[macpos:macpos + 17]
            #--------------- A simple code to search for the mac address--------
            self.activeMacs.append(mac)
            

    def getNames(self):
        __doc__ = "Makes sure the data is collected before returning it."
        self.startScan()
        self.scanNames()
        self.scanMac()
        return self.activeIps, self.activeDevices, self.activeMacs



a = Scanner()
ip, name, mac = a.getNames()

print(ip)
print(name)
print(mac)

