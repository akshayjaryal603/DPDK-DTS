
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


class Dut(Crb):

    """
    A connection to the CRB under test.
    This class sends commands to the CRB and validates the responses. It is
    implemented using either ssh for linuxapp or the terminal server for
    baremetal.
    All operations are in fact delegated to an instance of either CRBLinuxApp
    or CRBBareMetal.
    """
    print("*************************Inside Dut class****************************")
    PORT_MAP_CACHE_KEY = 'dut_port_map'
    PORT_INFO_CACHE_KEY = 'dut_port_info'
    NUMBER_CORES_CACHE_KEY = 'dut_number_cores'
    CORE_LIST_CACHE_KEY = 'dut_core_list'
    PCI_DEV_CACHE_KEY = 'dut_pci_dev_info'

    def __init__(self, crb, serializer, dut_id):
        self.NAME = 'dut' + LOG_NAME_SEP + '%s' % crb['My IP']
        super(Dut, self).__init__(crb, serializer, self.NAME, alt_session=True, dut_id=dut_id)

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
        self.host_session = SSHConnection(
            self.get_ip_address(),
            vm_name + '_host',
            self.get_username(),
            self.get_password())
        self.host_session.init_log(self.logger)
        self.logger.info("[%s] create new session for VM" % (threading.current_thread().name))

    def new_session(self, suite=""):
        """
        Create new session for dut instance. Session name will be unique.
        """
        if len(suite):
            session_name = self.NAME + '_' + suite
        else:
            session_name = self.NAME + '_' + str(uuid4())
        session = self.create_session(name=session_name)
        if suite != "":
            session.logger.config_suite(suite, self.NAME)
        else:
            session.logger.config_execution(self.NAME)

        if getattr(self, "base_dir", None):
            session.send_expect("cd %s" % self.base_dir, "# ")

        return session

    def close_session(self, session):
        """
        close new session in dut instance
        """
        self.destroy_session(session)

    def change_config_option(self, target, parameter, value):
        """
        This function change option in the config file
        """
        self.send_expect("sed -i 's/%s=.*$/%s=%s/'  config/defconfig_%s" %
                         (parameter, parameter, value, target), "# ")

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
        self.kill_all()
        self.target = target
        [arch, _, _, toolchain] = target.split('-')

        if toolchain == "icc":
            icc_vars = os.getenv('ICC_VARS', "/opt/intel/composer_xe_2013/bin/")
            icc_vars += "compilervars.sh"

            if arch == "x86_64":
                icc_arch = "intel64"
            elif arch == "i686":
                icc_arch = "ia32"
            self.send_expect("source " + icc_vars + " " + icc_arch, "# ")

        self.architecture = arch

    def mount_procfs(self):
        """
        Mount proc file system.
        """
        mount_procfs = getattr(self, 'mount_procfs_%s' % self.get_os_type())
        mount_procfs()

    def mount_procfs_linux(self):
        pass

    def mount_procfs_freebsd(self):
        """
        Mount proc file system in Freebsd.
        """
        self.send_expect('mount -t procfs proc /proc', '# ')

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
        # make sure ipv6 enable before scan
        self.enable_tester_ipv6()
        # scan ports before restore interface
        self.scan_ports()
        # restore dut ports to kernel
        self.restore_interfaces()
        # rescan ports after interface up
        self.rescan_ports()
        # load port infor from config file
        self.load_portconf()
        self.mount_procfs()
        # auto detect network topology
        self.map_available_ports()
        # disable tester port ipv6
        self.disable_tester_ipv6()
        # print latest ports_info
        for port_info in self.ports_info:
            self.logger.info(port_info)
        if self.ports_map is None or len(self.ports_map) == 0:
            self.logger.warning("ports_map should not be empty, please check all links")

        # initialize virtualization resource pool
        self.virt_pool = VirtResource(self)

    def restore_interfaces(self):
        """
        Restore all ports's interfaces.
        """
        # no need to restore for all info has been recorded
        if self.read_cache:
            return

        restore_interfaces = getattr(self, 'restore_interfaces_%s' % self.get_os_type())
        return restore_interfaces()

    def restore_interfaces_freebsd(self):
        """
        Restore FreeBSD interfaces.
        """
        self.send_expect("kldunload nic_uio.ko", "#")
        self.send_expect("kldunload contigmem.ko", "#")
        self.send_expect("kldload if_ixgbe.ko", "#", 20)

    def stop_ports(self):
        """
        After all execution done, some special nic like fm10k should be stop
        """
        for (pci_bus, pci_id) in self.pci_devices_info:
            driver = settings.get_nic_driver(pci_id)
            if driver is not None:
                # unbind device driver
                addr_array = pci_bus.split(':')
                domain_id = addr_array[0]
                bus_id = addr_array[1]
                devfun_id = addr_array[2]
                port = GetNicObj(self, domain_id, bus_id, devfun_id)
                port.stop()

    def restore_interfaces_linux(self):
        """
        Restore Linux interfaces.
        """
        for port in self.ports_info:
            pci_bus = port['pci']
            pci_id = port['type']
            # get device driver
            driver = settings.get_nic_driver(pci_id)
            if driver is not None:
                # unbind device driver
                addr_array = pci_bus.split(':')
                domain_id = addr_array[0]
                bus_id = addr_array[1]
                devfun_id = addr_array[2]

                port = GetNicObj(self, domain_id, bus_id, devfun_id)

                self.send_expect('echo %s > /sys/bus/pci/devices/%s\:%s\:%s/driver/unbind'
                                 % (pci_bus, domain_id, bus_id, devfun_id), '# ')
                # bind to linux kernel driver
                self.send_expect('modprobe %s' % driver, '# ')
                self.send_expect('echo %s > /sys/bus/pci/drivers/%s/bind'
                                 % (pci_bus, driver), '# ')
                pull_retries = 5
                while pull_retries > 0:
                    itf = port.get_interface_name()
                    if itf == 'N/A':
                        time.sleep(1)
                        pull_retries -= 1
                    else:
                        break
                if itf == 'N/A':
                    self.logger.warning("Fail to bind the device with the linux driver")
                else:
                    self.send_expect("ifconfig %s up" % itf, "# ")
            else:
                self.logger.info("NOT FOUND DRIVER FOR PORT (%s|%s)!!!" % (pci_bus, pci_id))

    def setup_memory(self, hugepages=-1):
        """
        Setup hugepage on DUT.
        """
        try:
            function_name = 'setup_memory_%s' % self.get_os_type()
            setup_memory = getattr(self, function_name)
            setup_memory(hugepages)
        except AttributeError:
            self.logger.error("%s is not implemented" % function_name)

    def setup_memory_linux(self, hugepages=-1):
        """
        Setup Linux hugepages.
        """
        if self.virttype == 'XEN':
            return
        hugepages_size = self.send_expect("awk '/Hugepagesize/ {print $2}' /proc/meminfo", "# ")
        total_huge_pages = self.get_total_huge_pages()
        total_numa_nodes = self.send_expect("ls /sys/devices/system/node | grep node* | wc -l", "# ")
        numa_service_num = self.get_def_rte_config('CONFIG_RTE_MAX_NUMA_NODES')
        try:
            int(total_numa_nodes)
        except ValueError:
            total_numa_nodes = -1
        if numa_service_num is not None:
            numa = min(int(total_numa_nodes), int(numa_service_num))
        else:
            numa = total_numa_nodes
        force_socket = False

        if int(hugepages_size) < (1024 * 1024):
            if self.architecture == "x86_64":
                arch_huge_pages = hugepages if hugepages > 0 else 4096
            elif self.architecture == "i686":
                arch_huge_pages = hugepages if hugepages > 0 else 512
                force_socket = True
            # set huge pagesize for x86_x32 abi target
            elif self.architecture == "x86_x32":
                arch_huge_pages = hugepages if hugepages > 0 else 256
                force_socket = True
            elif self.architecture == "ppc_64":
                arch_huge_pages = hugepages if hugepages > 0 else 512
            elif self.architecture == "arm64":
                if int(hugepages_size) >= (512 * 1024):
                    arch_huge_pages = hugepages if hugepages > 0 else 8
                else:
                    arch_huge_pages = hugepages if hugepages > 0 else 2048

            if total_huge_pages != arch_huge_pages:
                # before all hugepage average distribution  by all socket,
                # but sometimes create mbuf pool on socket 0 failed when setup testpmd,
                # so set all huge page on socket 0
                if force_socket:
                    self.set_huge_pages(arch_huge_pages, 0)
                else:
                    for numa_id in range(0, int(numa)):
                        self.set_huge_pages(arch_huge_pages, numa_id)
                    if numa == -1:
                        self.set_huge_pages(arch_huge_pages)

        self.mount_huge_pages()
        self.hugepage_path = self.strip_hugepage_path()

    def setup_memory_freebsd(self, hugepages=-1):
        """
        Setup Freebsd hugepages.
        """
        if hugepages is -1:
            hugepages = 4096

        num_buffers = hugepages / 1024
        if num_buffers:
            self.send_expect('kenv hw.contigmem.num_buffers=%d' % num_buffers, "#")

        self.send_expect("kldunload contigmem.ko", "#")
        self.send_expect("kldload ./%s/kmod/contigmem.ko" % self.target, "#")

    def taskset(self, core):
        if self.get_os_type() != 'linux':
            return ''

        return 'taskset %s ' % core

    def is_ssh_session_port(self, pci_bus):
        """
        Check if the pci device is the dut SSH session port.
        """
        port = None
        for port_info in self.ports_info:
            if pci_bus == port_info['pci']:
                port = port_info['port']
                break
        if port and port.get_ipv4_addr() == crbs['IP'].strip():
            return True
        else:
            return False

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
        return self.ports_info[port_num]['ipv6']

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

    def rescan_ports(self):
        """
        Rescan ports information
        """
        if self.read_cache:
            return

        if self.ports_info:
            self.rescan_ports_uncached()
            self.save_serializer_ports()

    def rescan_ports_uncached(self):
        """
        rescan ports and update port's mac address, intf, ipv6 address.
        """
        rescan_ports_uncached = getattr(self, 'rescan_ports_uncached_%s' % self.get_os_type())
        return rescan_ports_uncached()

    def rescan_ports_uncached_linux(self):
        unknow_interface = RED('Skipped: unknow_interface')

        for port_info in self.ports_info:
            port = port_info['port']
            intf = port.get_interface_name()
            port_info['intf'] = intf
            out = self.send_expect("ip link show %s" % intf, "# ")
            if "DOWN" in out:
                self.send_expect("ip link set %s up" % intf, "# ")
                time.sleep(5)
            port_info['mac'] = port.get_mac_addr()
            out = self.send_expect("ip -family inet6 address show dev %s | awk '/inet6/ { print $2 }'"
                                   % intf, "# ")
            ipv6 = out.split('/')[0]
            # Unconnected ports don't have IPv6
            if ":" not in ipv6:
                ipv6 = "Not connected"

            out = self.send_expect("ip -family inet address show dev %s | awk '/inet/ { print $2 }'"
                    % intf, "# ")
            ipv4 = out.split('/')[0]

            port_info['ipv6'] = ipv6
            port_info['ipv4'] = ipv4

    def rescan_ports_uncached_freebsd(self):
        unknow_interface = RED('Skipped: unknow_interface')

        for port_info in self.ports_info:
            port = port_info['port']
            intf = port.get_interface_name()
            if "No such file" in intf:
                self.logger.info("DUT: [%s] %s" % (pci_bus, unknow_interface))
                continue
            self.send_expect("ifconfig %s up" % intf, "# ")
            time.sleep(5)
            macaddr = port.get_mac_addr()
            ipv6 = port.get_ipv6_addr()
            # Unconnected ports don't have IPv6
            if ipv6 is None:
                ipv6 = "Not connected"

            port_info['mac'] = macaddr
            port_info['intf'] = intf
            port_info['ipv6'] = ipv6

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
        self.ports_info = []

        skipped = RED('Skipped: Unknown/not selected')
        
        for (pci_bus, pci_id) in self.pci_devices_info:

            if not settings.accepted_nic(pci_id):
                self.logger.info("DUT: [%s %s] %s" % (pci_bus, pci_id,
                                                      skipped))
                continue
            addr_array = pci_bus.split(':')
            domain_id = addr_array[0]
            bus_id = addr_array[1]
            devfun_id = addr_array[2]
            port = GetNicObj(self, domain_id, bus_id, devfun_id)
            intf = port.get_interface_name()

            macaddr = port.get_mac_addr()
            ipv6 = port.get_ipv6_addr()

            if ipv6 is None:
                ipv6 = "Not available"

            self.logger.warning("NUMA not available on FreeBSD")

            self.logger.info("DUT: [%s %s] %s %s" % (pci_bus, pci_id, intf, ipv6))

            # convert bsd format to linux format
            pci_split = pci_bus.split(':')
            pci_bus_id = hex(int(pci_split[0]))[2:]
            if len(pci_split[1]) == 1:
                pci_dev_str = "0" + pci_split[1]
            else:
                pci_dev_str = pci_split[1]

            pci_str = "%s:%s.%s" % (pci_bus_id, pci_dev_str, pci_split[2])

            # store the port info to port mapping
            self.ports_info.append({'port': port, 'pci': pci_str, 'type': pci_id, 'intf':
                                    intf, 'mac': macaddr, 'ipv6': ipv6, 'numa': -1})

    def setup_virtenv(self, virttype):
        """
        Setup current virtualization hypervisor type and remove elder VM ssh keys
        """
        self.virttype = virttype
        # remove VM rsa keys from tester
        remove_old_rsa_key(self.tester, self.crb['My IP'])

    def generate_sriov_vfs_by_port(self, port_id, vf_num, driver='default'):
        """
        Generate SRIOV VFs with default driver it is bound now or specified driver.
        """
        port = self.ports_info[port_id]['port']
        port_driver = port.get_nic_driver()

        if driver == 'default':
            if not port_driver:
                self.logger.info(
                    "No driver on specified port, can not generate SRIOV VF.")
                return None
        else:
            if port_driver != driver:
                port.bind_driver(driver)
        port.generate_sriov_vfs(vf_num)

        # append the VF PCIs into the ports_info
        sriov_vfs_pci = port.get_sriov_vfs_pci()
        self.ports_info[port_id]['sriov_vfs_pci'] = sriov_vfs_pci

        # instantiate the VF
        vfs_port = []
        for vf_pci in sriov_vfs_pci:
            addr_array = vf_pci.split(':')
            domain_id = addr_array[0]
            bus_id = addr_array[1]
            devfun_id = addr_array[2]
            vf_port = GetNicObj(self, domain_id, bus_id, devfun_id)
            vfs_port.append(vf_port)
        self.ports_info[port_id]['vfs_port'] = vfs_port

        pci = self.ports_info[port_id]['pci']
        self.virt_pool.add_vf_on_pf(pf_pci=pci, vflist=sriov_vfs_pci)

    def destroy_sriov_vfs_by_port(self, port_id):
        port = self.ports_info[port_id]['port']
        vflist = []
        port_driver = port.get_nic_driver()
        if 'sriov_vfs_pci' in self.ports_info[port_id] and \
           self.ports_info[port_id]['sriov_vfs_pci']:
            vflist = self.ports_info[port_id]['sriov_vfs_pci']
        else:
            if not port.get_sriov_vfs_pci():
                return

        if not port_driver:
            self.logger.info(
                "No driver on specified port, skip destroy SRIOV VF.")
        else:
            sriov_vfs_pci = port.destroy_sriov_vfs()
        self.ports_info[port_id]['sriov_vfs_pci'] = []
        self.ports_info[port_id]['vfs_port'] = []

        pci = self.ports_info[port_id]['pci']
        self.virt_pool.del_vf_on_pf(pf_pci=pci, vflist=vflist)

    def destroy_all_sriov_vfs(self):

        if self.ports_info == None:
            return
        for port_id in range(len(self.ports_info)):
            self.destroy_sriov_vfs_by_port(port_id)

    def get_vm_core_list(self):
        return VMCORELIST[self.crb['VM CoreList']]

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

    def disable_tester_ipv6(self):
        for tester_port in self.ports_map:
            if self.tester.ports_info[tester_port]['type'] != 'ixia':
                port = self.tester.ports_info[tester_port]['port']
                port.disable_ipv6()

    def enable_tester_ipv6(self):
        for tester_port in range(len(self.tester.ports_info)):
            if self.tester.ports_info[tester_port]['type'] != 'ixia':
                port = self.tester.ports_info[tester_port]['port']
                port.enable_ipv6()

    def check_port_occupied(self, port):
        out = self.alt_session.send_expect('lsof -i:%d' % port, '# ')
        if out == '':
            return False
        else:
            return True

    def get_maximal_vnc_num(self):
        out = self.send_expect("ps aux | grep '\-vnc' | grep -v grep", '# ')
        if out:
            ports = re.findall(r'-vnc .*?:(\d+)', out)
            for num in range(len(ports)):
                ports[num] = int(ports[num])
                ports.sort()
        else:
            ports = [0, ]
        return ports[-1]

    def close(self):
        """
        Close ssh session of DUT.
        """
        if self.session:
            self.session.close()
            self.session = None
        if self.alt_session:
            self.alt_session.close()
            self.alt_session = None
        if self.host_init_flag:
            self.host_session.close()

    def virt_exit(self):
        """
        Stop all unstopped hypervisors process
        """
        # try to kill all hypervisor process
        for pid in self.virt_pids:
            self.send_expect("kill -s SIGTERM %d" % pid, "# ", alt_session=True)
            time.sleep(3)
        self.virt_pids = []

    def crb_exit(self):
        """
        Recover all resource before crb exit
        """
        self.logger.logger_exit()
        self.enable_tester_ipv6()
        self.close()
