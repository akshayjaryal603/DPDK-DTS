import os
import re
import time
import settings
from config import PortConf
from settings import NICS, LOG_NAME_SEP
from ssh_connection import SSHConnection
from crb import Crb
from net_device import GetNicObj
from virt_resource import VirtResource
from utils import RED, remove_old_rsa_key
from uuid import uuid4
#from project_dpdk import DPDKdut

class MyDut(Crb):

    """
    A connection to the CRB under test.
    This class sends commands to the CRB and validates the responses. It is
    implemented using either ssh for linuxapp or the terminal server for
    baremetal.
    All operations are in fact delegated to an instance of either CRBLinuxApp
    or CRBBareMetal.
    """

    PORT_MAP_CACHE_KEY = 'dut_port_map'
    PORT_INFO_CACHE_KEY = 'dut_port_info'
    NUMBER_CORES_CACHE_KEY = 'dut_number_cores'
    CORE_LIST_CACHE_KEY = 'dut_core_list'
    PCI_DEV_CACHE_KEY = 'dut_pci_dev_info'

    def __init__(self, crb, serializer, dut_id):
	print("******************** MyDut class file call here")
        self.NAME = 'dut' + LOG_NAME_SEP + '%s' % crb['My IP']
        super(MyDut, self).__init__(crb, serializer, self.NAME, alt_session=True, dut_id=dut_id)

        self.host_init_flag = False
        self.number_of_cores = 0
        self.tester = None
        self.cores = []
        self.architecture = None
        self.ports_info = []
        self.conf = PortConf()
        self.ports_map = []
        self.virt_pool = None
        # hypervisor pid list, used for cleanup
        self.virt_pids = []

    def init_host_session(self, vm_name):
        """
        Create session for each VM, session will be handled by VM instance
        """
        pass

    def new_session(self, suite=""):
        """
        Create new session for dut instance. Session name will be unique.
        """
        pass

    def close_session(self, session):
        """
        close new session in dut instance
        """
        pass

    def change_config_option(self, target, parameter, value):
        """
        This function change option in the config file
        """
        pass

    def set_nic_type(self, nic_type):
        """
        Set CRB NICS ready to validated.
        """
        self.nic_type = nic_type
        if 'cfg' in nic_type:
            self.conf.load_ports_config(self.get_ip_address())

    def set_toolchain(self, target):
        """
        This looks at the current target and instantiates an attribute to
        be either a CRBLinuxApp or CRBBareMetal object. These latter two
        classes are private and should not be used directly by client code.
        """
        pass

    def mount_procfs(self):
        """
        Mount proc file system.
        """
        mount_procfs = getattr(self, 'mount_procfs_%s' % self.get_os_type())
        mount_procfs()

    def mount_procfs_linux(self):
        pass

    def mount_procfs_freebsd(self):
        pass

    def get_ip_address(self):
        """
        Get DUT's ip address.
        """
        return self.crb['IP']

    def get_password(self):
        """
        Get DUT's login password.
        """
        return self.crb['pass']

    def get_username(self):
        """
        Get DUT's login username.
        """
        return self.crb['user']

    def dut_prerequisites(self):

	print("******************** MyDut class file prerequisites call here")

        """
        Prerequest function should be called before execute any test case.
        Will call function to scan all lcore's information which on DUT.
        Then call pci scan function to collect nic device information.
        At last setup DUT' environment for validation.
        """
        self.send_expect("cd %s" % self.base_dir, "# ")
        self.send_expect("alias ls='ls --color=none'", "#")

        if self.get_os_type() == 'freebsd':
            self.send_expect('alias make=gmake', '# ')

        self.init_core_list()
        self.pci_devices_information()
        # scan ports before restore interface
        self.scan_ports()
        # restore dut ports to kernel
        self.restore_interfaces()
        # rescan ports after interface up
        #self.rescan_ports()
        # load port infor from config file
        self.load_portconf()
        self.mount_procfs()
        # auto detect network topology
        self.map_available_ports()
        # print latest ports_info
        for port_info in self.ports_info:
            self.logger.info(port_info)
	#self.ports_map = [0,1]   		#changes made here
        if self.ports_map is None or len(self.ports_map) == 0:
            self.logger.warning("ports_map should not be empty, please check all links")

        # initialize virtualization resource pool
        self.virt_pool = VirtResource(self)

    def restore_interfaces(self):
        """
        Restore all ports's interfaces.
        """
        # no need to restore for all info has been recorded
        pass

    def stop_ports(self):
        """
        After all execution done, some special nic like fm10k should be stop
        """
        pass

    def restore_interfaces_linux(self):
        """
        Restore Linux interfaces.
        """
        pass

    def setup_memory(self, hugepages=-1):
        """
        Setup hugepage on DUT.
        """
        pass

    def setup_memory_linux(self, hugepages=-1):
        """
        Setup Linux hugepages.
        """
        pass

    def taskset(self, core):
        if self.get_os_type() != 'linux':
            return ''

        return 'taskset %s ' % core

    def is_ssh_session_port(self, pci_bus):
        """
        Check if the pci device is the dut SSH session port.
        """
        return

    def get_dpdk_bind_script(self):
        op = self.send_expect("ls", "#")
        if "usertools" in op:
            res = 'usertools/dpdk-devbind.py'
        else:
            op = self.send_expect("ls tools", "#")
            if "dpdk_nic_bind.py" in op:
                res = 'tools/dpdk_nic_bind.py'
            else:
                res = 'tools/dpdk-devbind.py'
        return res

    def bind_interfaces_linux(self, driver='igb_uio', nics_to_bind=None):
        """
        Bind the interfaces to the selected driver. nics_to_bind can be None
        to bind all interfaces or an array with the port indexes
        """

        binding_list = '--bind=%s ' % driver

        current_nic = 0
        for (pci_bus, pci_id) in self.pci_devices_info:
            if settings.accepted_nic(pci_id):
                if self.is_ssh_session_port(pci_bus):
                    continue

                if nics_to_bind is None or current_nic in nics_to_bind:
                    binding_list += '%s ' % (pci_bus)

                current_nic += 1
        if current_nic == 0:
            self.logger.info("Not nic need bind driver: %s" % driver)
            return
        bind_script_path = self.get_dpdk_bind_script()
        self.send_expect('%s --force %s' % (bind_script_path, binding_list), '# ')

    def unbind_interfaces_linux(self, nics_to_bind=None):
        """
        Unbind the interfaces.
        """

        binding_list = '-u '

        current_nic = 0
        for (pci_bus, pci_id) in self.pci_devices_info:
            if settings.accepted_nic(pci_id):
                if self.is_ssh_session_port(pci_bus):
                    continue

                if nics_to_bind is None or current_nic in nics_to_bind:
                    binding_list += '%s ' % (pci_bus)

                current_nic += 1

        if current_nic == 0:
            self.logger.info("Not nic need unbind driver")
            return

        bind_script_path = self.get_dpdk_bind_script()
        self.send_expect('%s --force %s' % (bind_script_path, binding_list), '# ')

    def get_ports(self, nic_type='any', perf=None, socket=None):
        """
        Return DUT port list with the filter of NIC type, whether run IXIA
        performance test, whether request specified socket.
        """
        ports = []
        candidates = []

        nictypes = []
        if nic_type == 'any':
            for portid in range(len(self.ports_info)):
                ports.append(portid)
            return ports
        elif nic_type == 'cfg':
            for portid in range(len(self.ports_info)):
                if self.ports_info[portid]['source'] == 'cfg':
                    if (socket is None or
                        self.ports_info[portid]['numa'] == -1 or
                            socket == self.ports_info[portid]['numa']):
                        ports.append(portid)
            return ports
        else:
            for portid in range(len(self.ports_info)):
                port_info = self.ports_info[portid]
                # match nic type
                if port_info['type'] == NICS[nic_type]:
                    # match numa or none numa awareness
                    if (socket is None or
                        port_info['numa'] == -1 or
                            socket == port_info['numa']):
                        # port has link,
                        if self.tester.get_local_port(portid) != -1:
                            ports.append(portid)
            return ports

    def get_ports_performance(self, nic_type='any', perf=None, socket=None,
                              force_same_socket=True,
                              force_different_nic=True):
        """
            Return the maximum available number of ports meeting the parameters.
            Focuses on getting ports with same/different NUMA node and/or
            same/different NIC.
        """

        available_ports = self.get_ports(nic_type, perf, socket)
        accepted_sets = []

        while len(available_ports) > 0:
            accepted_ports = []
            # first available port is the reference port
            accepted_ports.append(available_ports[0])

            # check from second port according to parameter
            for port in available_ports[1:]:

                if force_same_socket and socket is None:
                    if self.ports_info[port]['numa'] != self.ports_info[accepted_ports[0]]['numa']:
                        continue
                if force_different_nic:
                    if self.ports_info[port]['pci'][:-1] == self.ports_info[accepted_ports[0]]['pci'][:-1]:
                        continue

                accepted_ports.append(port)

            for port in accepted_ports:
                available_ports.remove(port)

            accepted_sets.append(accepted_ports)

        biggest_set = max(accepted_sets, key=lambda s: len(s))

        return biggest_set

    def get_peer_pci(self, port_num):
        """
        return the peer pci address of dut port
        """
        if 'peer' not in self.ports_info[port_num]:
            return None
        else:
            return self.ports_info[port_num]['peer']

    def get_mac_address(self, port_num):
        """
        return the port mac on dut
        """
        return self.ports_info[port_num]['mac']

    def get_ipv6_address(self, port_num):
        """
        return the IPv6 address on dut
        """
        return

    def get_numa_id(self, port_num):
        """
        return the Numa Id of port
        """
        if self.ports_info[port_num]['numa'] == -1:
            self.logger.warning('NUMA not supported')

        return self.ports_info[port_num]['numa']

    def lcore_table_print(self, horizontal=False):
        if not horizontal:
            result_table = ResultTable(['Socket', 'Core', 'Thread'])

            for lcore in self.cores:
                result_table.add_row([lcore['socket'], lcore['core'], lcore['thread']])
            result_table.table_print()
        else:
            result_table = ResultTable(['X'] + [''] * len(self.cores))
            result_table.add_row(['Thread'] + [n['thread'] for n in self.cores])
            result_table.add_row(['Core'] + [n['core'] for n in self.cores])
            result_table.add_row(['Socket'] + [n['socket'] for n in self.cores])
            result_table.table_print()

    def get_memory_channels(self):
        n = self.crb['memory channels']
        if n is not None and n > 0:
            return n
        else:
            return 1

    def check_ports_available(self, pci_bus, pci_id):
        """
        Check that whether auto scanned ports ready to use
        """
        pci_addr = "%s:%s" % (pci_bus, pci_id)
        if self.nic_type == 'any':
            return True
        elif self.nic_type == 'cfg':
            if self.conf.check_port_available(pci_bus) is True:
                return True
        elif self.nic_type not in NICS.keys():
            self.logger.warning("NOT SUPPORTED NIC TYPE: %s" % self.nic_type)
        else:
            codename = NICS[self.nic_type]
            if pci_id == codename:
                return True

        return False

    def load_serializer_ports(self):
        cached_ports_info = self.serializer.load(self.PORT_INFO_CACHE_KEY)
        if cached_ports_info is None:
            return None

        self.ports_info = cached_ports_info

    def save_serializer_ports(self):
        cached_ports_info = []
        for port in self.ports_info:
            port_info = {}
            for key in port.keys():
                if type(port[key]) is str:
                    port_info[key] = port[key]
            cached_ports_info.append(port_info)
        self.serializer.save(self.PORT_INFO_CACHE_KEY, cached_ports_info)

    def scan_ports(self):
        """
        Scan ports information or just read it from cache file.
        """
        if self.read_cache:
            self.load_serializer_ports()
            self.scan_ports_cached()

        if not self.read_cache or self.ports_info is None:
            self.scan_ports_uncached()

    def scan_ports_cached(self):
        """
        Scan cached ports, instantiate tester port
        """
        scan_ports_cached = getattr(self, 'scan_ports_cached_%s' % self.get_os_type())
        return scan_ports_cached()

    def scan_ports_cached_linux(self):
        """
        Scan Linux ports and instantiate tester port
        """
        if self.ports_info is None:
            return

        for port_info in self.ports_info:
            addr_array = port_info['pci'].split(':')
            domain_id = addr_array[0]
            bus_id = addr_array[1]
            devfun_id = addr_array[2]

            port = GetNicObj(self, domain_id, bus_id, devfun_id)
            port_info['port'] = port

            self.logger.info("DUT cached: [%s %s] %s" % (port_info['pci'],
                                port_info['type'], port_info['intf']))

    def scan_ports_uncached(self):
        """
        Scan ports and collect port's pci id, mac address, ipv6 address.
        """
        scan_ports_uncached = getattr(self, 'scan_ports_uncached_%s' % self.get_os_type())
        return scan_ports_uncached()

    def scan_ports_uncached_linux(self):
        """
        Scan Linux ports and collect port's pci id, mac address, ipv6 address.
        """
        self.ports_info = []

        skipped = RED('Skipped: Unknown/not selected')
        unknow_interface = RED('Skipped: unknow_interface')

        for (pci_bus, pci_id) in self.pci_devices_info:
            if self.check_ports_available(pci_bus, pci_id) is False:
                self.logger.info("DUT: [%s %s] %s" % (pci_bus, pci_id,
                                                      skipped))
                continue

            addr_array = pci_bus.split(':')
            domain_id = addr_array[0]
            bus_id = addr_array[1]
            devfun_id = addr_array[2]

            port = GetNicObj(self, domain_id, bus_id, devfun_id)
            intf = port.get_interface_name()
            if "No such file" in intf:
                self.logger.info("DUT: [%s] %s" % (pci_bus, unknow_interface))
                continue

            macaddr = port.get_mac_addr()
            if "No such file" in intf:
                self.logger.info("DUT: [%s] %s" % (pci_bus, unknow_interface))
                continue

            numa = port.socket
            # store the port info to port mapping
            self.ports_info.append(
                {'port': port, 'pci': pci_bus, 'type': pci_id, 'numa': numa,
                 'intf': intf, 'mac': macaddr})

            if not port.get_interface2_name():
                continue

            intf = port.get_interface2_name()
            macaddr = port.get_intf2_mac_addr()
            numa = port.socket
            # store the port info to port mapping
            self.ports_info.append(
                {'port': port, 'pci': pci_bus, 'type': pci_id, 'numa': numa,
                 'intf': intf, 'mac': macaddr})


    def scan_ports_uncached_freebsd(self):
        """
        Scan Freebsd ports and collect port's pci id, mac address, ipv6 address.
        """
        pass

    def setup_virtenv(self, virttype):
        """
        Setup current virtualization hypervisor type and remove elder VM ssh keys
        """
        pass

    def generate_sriov_vfs_by_port(self, port_id, vf_num, driver='default'):
        """
        Generate SRIOV VFs with default driver it is bound now or specified driver.
        """
        pass

    def destroy_sriov_vfs_by_port(self, port_id):
        pass

    def destroy_all_sriov_vfs(self):

        pass

    def get_vm_core_list(self):

        return 

    def load_portconf(self):
        """
        Load port configurations for ports_info. If manually configured infor
        not same as auto scanned, still use infor in configuration file.
        """
        for port in self.ports_info:
            pci_bus = port['pci']
            ports_cfg = self.conf.get_ports_config()
            if pci_bus in ports_cfg:
                port_cfg = ports_cfg[pci_bus]
                port_cfg['source'] = 'cfg'
            else:
                port_cfg = {}

            for key in ['intf', 'mac', 'peer', 'source']:
                if key in port_cfg:
                    if key in port and port_cfg[key].lower() != port[key].lower():
                        self.logger.warning("CONFIGURED %s NOT SAME AS SCANNED!!!" % (key.upper()))
                    port[key] = port_cfg[key].lower()
            if 'numa' in port_cfg:
                if port_cfg['numa'] != port['numa']:
                    self.logger.warning("CONFIGURED NUMA NOT SAME AS SCANNED!!!")
                port['numa'] = port_cfg['numa']

    def map_available_ports(self):
        """
        Load or generate network connection mapping list.
        """
        if self.read_cache:
            self.ports_map = self.serializer.load(self.PORT_MAP_CACHE_KEY)

        if not self.read_cache or self.ports_map is None:
            self.map_available_ports_uncached()
            self.serializer.save(self.PORT_MAP_CACHE_KEY, self.ports_map)

        self.logger.warning("DUT PORT MAP: " + str(self.ports_map))

    def map_available_ports_uncached(self):
        """
        Generate network connection mapping list.
        """
        nrPorts = len(self.ports_info)
        if nrPorts == 0:
            return

        remove = []
        self.ports_map = [-1] * nrPorts

        hits = [False] * len(self.tester.ports_info)

        for dutPort in range(nrPorts):
            peer = self.get_peer_pci(dutPort)
            dutpci = self.ports_info[dutPort]['pci']
            if peer is not None:
                for remotePort in range(len(self.tester.ports_info)):
                    if self.tester.ports_info[remotePort]['pci'].lower() == peer.lower():
                        hits[remotePort] = True
                        self.ports_map[dutPort] = remotePort
                        break
                if self.ports_map[dutPort] == -1:
                    self.logger.error("CONFIGURED TESTER PORT CANNOT BE FOUND!!!")
                else:
                    continue  # skip ping6 map

            for remotePort in range(len(self.tester.ports_info)):
                if hits[remotePort]:
                    continue

                # skip ping self port
                remotepci = self.tester.ports_info[remotePort]['pci']
                if (self.crb['IP'] == self.crb['tester IP']) and (dutpci == remotepci):
                    continue

                # skip ping those not connected port
                ipv6 = self.get_ipv6_address(dutPort)
                if ipv6 == "Not connected":
                    if self.tester.ports_info[remotePort].has_key('ipv4'):
			out = self.tester.send_ping(
				dutPort, self.tester.ports_info[remotePort]['ipv4'],
				self.get_mac_address(dutPort))
		    else:
                    	continue
		else:
                    if getattr(self, 'send_ping6', None):
                    	out = self.send_ping6(
                        	dutPort, self.tester.ports_info[remotePort]['ipv6'],
                        	self.get_mac_address(dutPort))
                    else:
                    	out = self.tester.send_ping6(
				remotePort, ipv6, self.get_mac_address(dutPort))

                if ('64 bytes from' in out):
                    self.logger.info("PORT MAP: [dut %d: tester %d]" % (dutPort, remotePort))
                    self.ports_map[dutPort] = remotePort
                    hits[remotePort] = True
                    if self.crb['IP'] == self.crb['tester IP']:
                        # remove dut port act as tester port
                        remove_port = self.get_port_info(remotepci)
                        if remove_port is not None:
                            remove.append(remove_port)
                        # skip ping from those port already act as dut port
                        testerPort = self.tester.get_local_index(dutpci)
                        if testerPort != -1:
                            hits[testerPort] = True
                    break

        for port in remove:
            self.ports_info.remove(port)

    def check_port_occupied(self, port):
        out = self.alt_session.send_expect('lsof -i:%d' % port, '# ')
        if out == '':
            return False
        else:
            return True

    def get_maximal_vnc_num(self):
        
	return

    def close(self):
        """
        Close ssh session of DUT.
        """
        pass

    def virt_exit(self):
        """
        Stop all unstopped hypervisors process
        """
        # try to kill all hypervisor process
        pass

    def crb_exit(self):
        """
        Recover all resource before crb exit
        """
        self.logger.logger_exit()
        #self.enable_tester_ipv6()
        self.close()

