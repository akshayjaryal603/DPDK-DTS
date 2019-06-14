import os
import re

from settings import NICS, load_global_setting, accepted_nic
from settings import DPDK_RXMODE_SETTING, HOST_DRIVER_SETTING, HOST_DRIVER_MODE_SETTING
from ssh_connection import SSHConnection
from crb import Crb
from mydut import MyDut
from tester import Tester
from logger import getLogger
from settings import IXIA, DRIVERS


class DPDKdut(MyDut):

    """
    DPDK project class for DUT. DTS will call set_target function to setup
    build, memory and kernel module.
    """
    
    def __init__(self, crb, serializer, dut_id):

	print("***************** Project_mydut file first line************************")

        super(DPDKdut, self).__init__(crb, serializer, dut_id)
        self.testpmd = None

    def set_target(self, target, bind_dev=True):
        """
        Set env variable, these have to be setup all the time. Some tests
        need to compile example apps by themselves and will fail otherwise.
        Set hugepage on DUT and install modules required by DPDK.
        Configure default ixgbe PMD function.
        """
	print("****************** Project_mydut file set_target function ************************")

        self.target = target
        #self.set_toolchain(target)
        # set env variable
        # These have to be setup all the time. Some tests need to compile
        # example apps by themselves and will fail otherwise.
	print("*********** Changes while")
	self.send_expect("cd ~/dpdk", "#")
        self.send_expect("export RTE_TARGET=" + target, "#")
        self.send_expect("export RTE_SDK=`pwd`", "#")

	if not self.skip_setup:
		self.build_install_dpdk_linux(target, extra_options='')
	
	# create hugepages on LS1046A Board

	self.send_expect("mkdir /mnt/hugepages", "#")
	self.send_expect("mount -t hugetlbfs none /mnt/hugepages", "#")
	self.send_expect("echo 256 > /proc/sys/vm/nr_hugepages", "#")
	
	self.send_expect("fmc -x", "#")

	self.send_expect("fmc -c usdpaa_config_ls1046.xml -p usdpaa_policy_hash_ipv4_1queue.xml -a", "#")

	self.send_expect("pkill l2fwd", "#")
	self.send_expect("pkil l3fwd", "#")
	self.send_expect("pkill l3fwd_lpm", "#")
	self.send_expect("rm -rf /dev/hugepages/*", "#",2)


    def setup_modules(self, target, drivername, drivermode):
        """
        Install DPDK required kernel module on DUT.
        """
        setup_modules = getattr(self, 'setup_modules_%s' % self.get_os_type())
        setup_modules(target, drivername, drivermode)

    def setup_modules_linux(self, target, drivername, drivermode):
	pass

    def restore_modules(self):
        """
        Restore DPDK kernel module on DUT.
        """
        pass

    def restore_modules_linux(self):
        """
        Restore DPDK Linux kernel module on DUT.
        """
        pass

    def set_rxtx_mode(self):
        """
        Set default RX/TX PMD function,
        only i40e support scalar/full RX/TX model.
        ixgbe and fm10k only support vector and no vector model
        all NIC default rx/tx model is vector PMD
        """

        pass

    def set_package(self, pkg_name="", patch_list=[]):
        self.package = pkg_name
        self.patches = patch_list

    def build_install_dpdk(self, target, extra_options=''):
        """
        Build DPDK source code with specified target.
        """
        build_install_dpdk = getattr(self, 'build_install_dpdk_%s' % self.get_os_type())
        build_install_dpdk(target, extra_options)

    def build_install_dpdk_linux(self, target, extra_options):
        """
        Build DPDK source code on linux with specified target.
        """
	#changes to be made later

        build_time = 900
        
	'''if "icc" in target:
            build_time = 700'''
        # clean all
	self.send_expect("cd ~/dpdk", "#")
        self.send_expect("rm -rf " + target, "#")

        # compile
	number_of_cores = 3		#changes made here for dpdk compilationm according to the LS2088ARDB board
	extra_options = "CONFIG_RTE_KNI_KMOD=n CONFIG_RTE_LIBRTE_PMD_OPENSSL=n CONFIG_RTE_EAL_IGB_UIO=n"
        out = self.send_expect("make -j %d install T=%s %s" % 
            (number_of_cores, target, extra_options), "# ", build_time)     #self.number_of_cores changed to number_of_cores

        assert ("Error" not in out), "Compilation error..."
        assert ("No rule to make" not in out), "No rule to make error..."

    def prepare_package(self):
        if not self.skip_setup:
            assert (os.path.isfile(self.package) is True), "Invalid package"

            p_dir, _ = os.path.split(self.base_dir)
            # ToDo: make this configurable
            dst_dir = "/tmp/"

            out = self.send_expect("ls %s && cd %s" % (dst_dir, p_dir),
                                   "#", verify=True)
            if out == -1:
                raise ValueError("Directory %s or %s does not exist,"
                                 "please check params -d"
                                 % (p_dir, dst_dir))
            self.session.copy_file_to(self.package, dst_dir)

            # put patches to p_dir/patches/
            if (self.patches is not None):
                for p in self.patches:
                    self.session.copy_file_to('dep/' + p, dst_dir)

            self.kill_all()

            # enable core dump
            self.send_expect("ulimit -c unlimited", "#")

            # unpack the code and change to the working folder
            self.send_expect("rm -rf %s" % self.base_dir, "#")

            # unpack dpdk
            out = self.send_expect("tar zxf %s%s -C %s" %
                                   (dst_dir, self.package.split('/')[-1], p_dir),
                                   "# ", 20, verify=True)
            if out == -1:
                raise ValueError("Extract dpdk package to %s failure,"
                                 "please check params -d"
                                 % (p_dir))

            # check dpdk dir name is expect
            out = self.send_expect("ls %s" % self.base_dir,
                                   "# ", 20, verify=True)
            if out == -1:
                raise ValueError("dpdk dir %s mismatch, please check params -d"
                                 % self.base_dir)

            if (self.patches is not None):
                for p in self.patches:
                    out = self.send_expect("patch -d %s -p1 < %s" %
                                           (self.base_dir, dst_dir + p), "# ")
                    assert "****" not in out

    def prerequisites(self):
        """
        Copy DPDK package to DUT and apply patch files.
        """
        self.prepare_package()
        self.dut_prerequisites()
        self.stage = "post-init"

    def extra_nic_setup(self):
        """
        Some nic like RRC required additional setup after module installed
        """
        for port_info in self.ports_info:
            netdev = port_info['port']
            netdev.setup()

    def bind_interfaces_linux(self, driver='igb_uio', nics_to_bind=None):
        """
        Bind the interfaces to the selected driver. nics_to_bind can be None
        to bind all interfaces or an array with the port indexes
        """
        pass

    def unbind_interfaces_linux(self, nics_to_bind=None):
        """
        Unbind the interfaces
        """
	pass

    def build_dpdk_apps(self, folder, extra_options=''):
        """
        Build dpdk sample applications.
        """
        build_dpdk_apps = getattr(self, 'build_dpdk_apps_%s' % self.get_os_type())
        return build_dpdk_apps(folder, extra_options)

    def build_dpdk_apps_linux(self, folder, extra_options):
        """
        Build dpdk sample applications on linux.
        """
        # icc compile need more time
        if 'icc' in self.target:
            timeout = 600
        else:
            timeout = 900
        self.send_expect("rm -rf %s" % r'./app/test/test_resource_c.res.o' , "#")
        self.send_expect("rm -rf %s" % r'./app/test/test_resource_tar.res.o' , "#")
        self.send_expect("rm -rf %s" % r'./app/test/test_pci_sysfs.res.o' , "#")
        return self.send_expect("make -C %s %s" % (folder, extra_options),
                                "# ", timeout)    		# here we removed -j %d because we haven't use this for make self.number_of_cores

    def get_blacklist_string(self, target, nic):
        """
        Get black list command string.
        """
        get_blacklist_string = getattr(self, 'get_blacklist_string_%s' % self.get_os_type())
        return get_blacklist_string(target, nic)

    def get_blacklist_string_linux(self, target, nic):
        """
        Get black list command string on Linux.
        """
        blacklist = ''
        dutPorts = self.get_ports(nic)
        self.restore_interfaces()
        self.send_expect('insmod ./%s/kmod/igb_uio.ko' % target, '# ')
        self.bind_interfaces_linux()
        for port in range(0, len(self.ports_info)):
            if(port not in dutPorts):
                blacklist += '-b %s ' % self.ports_info[port]['pci']
        return blacklist

	
    def get_def_rte_config(self, config):     # need ot be change in future
        """
        Get RTE configuration from config/defconfig_*.
        """
        out = self.session.send_command("cat config/defconfig_%s | sed '/^#/d' | sed '/^\s*$/d'"
                                        % self.target, 1)

        def_rte_config = re.findall(config+'=(\S+)', out)
        if def_rte_config:
            return def_rte_config[0]
        else:
            return None

    def set_driver_specific_configurations(self, drivername):
        """
        Set configurations required for specific drivers before compilation.
        """
        # Enable Mellanox drivers
        if drivername == "mlx5_core" or drivername == "mlx4_core":
            self.send_expect("sed -i -e 's/CONFIG_RTE_LIBRTE_MLX5_PMD=n/"
                             + "CONFIG_RTE_LIBRTE_MLX5_PMD=y/' config/common_base", "# ", 30)
            self.send_expect("sed -i -e 's/CONFIG_RTE_LIBRTE_MLX4_PMD=n/"
                             + "CONFIG_RTE_LIBRTE_MLX5_PMD=y/' config/common_base", "# ", 30)

class DPDKtester(Tester):

    """
    DPDK project class for tester. DTS will call prerequisites function to setup
    interface and generate port map.
    """

    def __init__(self, crb, serializer, dut_id):
        self.NAME = "tester"
        super(DPDKtester, self).__init__(crb, serializer)

    def prerequisites(self, perf_test=False):
        """
        Setup hugepage on tester and copy validation required files to tester.
        """
        self.kill_all()

        if not self.skip_setup:
            total_huge_pages = self.get_total_huge_pages()
            hugepages_size = self.send_expect("awk '/Hugepagesize/ {print $2}' /proc/meminfo", "# ")
            if total_huge_pages == 0:
                self.mount_huge_pages()
                if hugepages_size == "524288":
                    self.set_huge_pages(8)
                else:
                    self.set_huge_pages(1024)

            self.session.copy_file_to("dep/tgen.tgz")
            self.session.copy_file_to("dep/tclclient.tgz")
            # unpack tgen
            out = self.send_expect("tar zxf tgen.tgz", "# ")
            assert "Error" not in out
            # unpack tclclient
            out = self.send_expect("tar zxf tclclient.tgz", "# ")
            assert "Error" not in out

        self.send_expect("modprobe uio", "# ")

        self.tester_prerequisites()

        self.set_promisc()
        # use software pktgen for performance test
        if perf_test is True:
            try:
                if self.crb[IXIA] is not None:
                    self.logger.info("Use hardware packet generator")
            except Exception as e:
                self.logger.warning("Use default software pktgen")
                out = self.send_expect("ls /root/igb_uio.ko", "# ")
                assert ("No such file or directory" not in out), "Can not find /root/igb_uio.ko for performance"
                self.setup_memory()

        self.stage = "post-init"

    def setup_memory(self, hugepages=-1):
        """
        Setup hugepage on tester.
        """
        hugepages_size = self.send_expect("awk '/Hugepagesize/ {print $2}' /proc/meminfo", "# ")

        if int(hugepages_size) < (2048 * 2048):
            arch_huge_pages = hugepages if hugepages > 0 else 2048
            total_huge_pages = self.get_total_huge_pages()

        self.mount_huge_pages()
        if total_huge_pages != arch_huge_pages:
            self.set_huge_pages(arch_huge_pages)
