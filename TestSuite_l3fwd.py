"""
DPDK Test suite.
Layer-3 forwarding test script.
"""

import utils
import string
import re
from test_case import TestCase
from exception import VerifyFailure
from settings import HEADER_SIZE
from etgen import IxiaPacketGenerator, SoftwarePacketGenerator
#from mydut import MyDut

class TestL3fwd(TestCase,IxiaPacketGenerator):
#SoftwarePacketGenerator

    path = "./examples/l3fwd/build/"

    test_cases_2_ports = [(1,"1S/2C/1T","%s -c %s -n %d -- -P -p %s  --config '(P0,0,C{0.1.0}), (P1,0,C{1.2.0})'"),          
			  (1,"2S/2C/1T", "%s -c %s -n %d -- -p %s  --config '(P0,0,C{0.1.0}), (P1,0,C{0.2.0}),(P0,1,C{1.1.0}),(P1,1,C{1.2.0})'"),
			  #(1,"2S/2C/1T", "%s -c %s -n %d -- -p %s  --config '(P0,0,C{0.1.0}), (P1,0,C{0.2.0}),(P0,1,C{1.1.0}), (P1,1,C{1.2.0})'"),


 			  #(1,"1S/4C/1T", "%s -c %s -n %d -- -P -p %s  --config '(P0,0,C{1.1.0}), (P1,0,C{1.2.0}),(P0,1,C{1.3.0}),(P1,1,C{1.4.0})'"),
			  #(1,"1S/4C/1T", "%s -c %s -n %d -- -p %s  --config '(P0,0,C{1.1.0}), (P1,0,C{1.2.0}),(P0,1,C{1.3.0}),(P1,1,C{1.4.0})'"),
                          ]

    test_cases_4_ports = [#(1, "1S/1C/1T",
                           #"%s -c %s -n %d -- -P -p %s  --config '(P0,0,C{1.1.0}),(P1,0,C{1.1.0}),(P2,0,C{1.1.0}),(P3,0,C{1.1.0})'"),
                          #(1, "1S/2C/2T",
                          # "%s -c %s -n %d -- -p %s  --config '(P0,0,C{1.1.0}),(P1,0,C{1.1.1}),(P2,0,C{1.2.0}),(P3,0,C{1.2.1})'"),
                          #(1, "1S/4C/1T",
                           #"%s -c %s -n %d -- -P -p %s  --config '(P0,0,C{1.1.0}),(P1,0,C{1.2.0}),(P2,0,C{1.3.0}),(P3,0,C{1.4.0})'"),
                          #(2, "1S/8C/1T",
                          ]

    queues_4_ports = []

    for case in test_cases_4_ports:
        if case[0] * 4 not in queues_4_ports:
            queues_4_ports.append(case[0] * 4)

    host_table = [
        "{{IPv4(10,100,0,1), IPv4(1,2,3,4), 1, 10, IPPROTO_UDP}, P0}",
        "{{IPv4(10,101,0,1), IPv4(1,2,3,4), 1, 10, IPPROTO_UDP}, P0}",
        "{{IPv4(11,100,0,1), IPv4(1,2,3,4), 1, 11, IPPROTO_UDP}, P1}",
        "{{IPv4(11,101,0,1), IPv4(1,2,3,4), 1, 11, IPPROTO_UDP}, P1}",
        "{{IPv4(12,100,0,1), IPv4(1,2,3,4), 1, 12, IPPROTO_UDP}, P2}",
        "{{IPv4(12,101,0,1), IPv4(1,2,3,4), 1, 12, IPPROTO_UDP}, P2}",
        "{{IPv4(13,100,0,1), IPv4(1,2,3,4), 1, 13, IPPROTO_UDP}, P3}",
        "{{IPv4(13,101,0,1), IPv4(1,2,3,4), 1, 13, IPPROTO_UDP}, P3}",
    ]

    lpm_table = [
        "{IPv4(10,100,0,0), 24, P0}",
        "{IPv4(10,101,0,0), 24, P0}",
        "{IPv4(11,100,0,0), 24, P1}",
        "{IPv4(11,101,0,0), 24, P1}",
        "{IPv4(12,100,0,0), 24, P2}",
        "{IPv4(12,101,0,0), 24, P2}",
        "{IPv4(13,100,0,0), 24, P3}",
        "{IPv4(13,101,0,0), 24, P3}",
    ]

    frame_sizes = [64, 72, 128, 256, 512, 1024, 1518, 2048]  # 65, 128

    methods = ['lpm']  #, 'exact']

    #
    #
    # Utility methods and other non-test code.
    #
    # Insert or move non-test functions here.

    def portRepl(self, match):
        """
        Function to replace P([0123]) pattern in tables
        """

        portid = match.group(1)
        self.verify(int(portid) in range(4), "invalid port id")
        if int(portid) >= len(valports):
            return '0'
        else:
            return '%s' % valports[int(portid)]

    #
    # Test cases.
    #

    def set_up_all(self):
        """
        Run at the start of each test suite.


        L3fwd Prerequisites
        """
        # Based on h/w type, choose how many ports to use
        ports = self.dut.get_ports(socket=1)
        if not ports:
            ports = self.dut.get_ports(socket=0)

        self.tester.extend_external_packet_generator(TestL3fwd, self)
        # Verify that enough ports are available
        self.verify(len(ports) >= 2, "Insufficient ports for speed testing")
        
        netdev = self.dut.ports_info[ports[0]]['port']
        
        self.port_socket = netdev.socket
        if self.port_socket == -1: 
            self.port_socket = 0
        

        # Verify that enough threads are available
	cores = self.dut.get_core_list("1S/2C/1T")	
	print("***********Cores", cores)
        self.verify(cores is not None, "Insufficient cores for speed testing")

        global valports
        valports = [_ for _ in ports if self.tester.get_local_port(_) != -1]
        
        self.verify(len(valports) >= 2, "Insufficient active ports for speed testing")

        pat = re.compile("P([0123])")
        # Update config file and rebuild to get best perf on FVL
        self.dut.send_expect("sed -i -e 's/CONFIG_RTE_PCI_CONFIG=n/CONFIG_RTE_PCI_CONFIG=y/' ./config/common_base", "#", 20)
        self.dut.send_expect("sed -i -e 's/CONFIG_RTE_PCI_EXTENDED_TAG=.*$/CONFIG_RTE_PCI_EXTENDED_TAG=\"on\"/' ./config/common_base", "#", 20)
        self.dut.send_expect("sed -i -e 's/define RTE_TEST_RX_DESC_DEFAULT.*$/define RTE_TEST_RX_DESC_DEFAULT 2048/' ./examples/l3fwd/main.c", "#", 20)
        self.dut.send_expect("sed -i -e 's/define RTE_TEST_TX_DESC_DEFAULT.*$/define RTE_TEST_TX_DESC_DEFAULT 2048/' ./examples/l3fwd/main.c", "#", 20)
        self.dut.build_install_dpdk(self.target)

        # Prepare long prefix match table, replace P(x) port pattern
        lpmStr = "static struct ipv4_l3fwd_lpm_route ipv4_l3fwd_lpm_route_array[] = {\\\n"
        for idx in range(len(TestL3fwd.lpm_table)):
            TestL3fwd.lpm_table[idx] = pat.sub(self.portRepl, TestL3fwd.lpm_table[idx])
            lpmStr = lpmStr + ' ' * 4 + TestL3fwd.lpm_table[idx] + ",\\\n"
        lpmStr = lpmStr + "};"
        self.logger.debug(lpmStr)

        # Prepare host route table, replace P(x) port pattern
        exactStr = "static struct ipv4_l3fwd_em_route ipv4_l3fwd_em_route_array[] = {\\\n"
        for idx in range(len(TestL3fwd.host_table)):
            TestL3fwd.host_table[idx] = pat.sub(self.portRepl, TestL3fwd.host_table[idx])
            exactStr = exactStr + ' ' * 4 + TestL3fwd.host_table[idx] + ",\\\n"
        exactStr = exactStr + "};"
        self.logger.debug(exactStr)

        # Compile l3fwd with LPM lookup.
        self.dut.send_expect(r"sed -i '/ipv4_l3fwd_lpm_route_array\[\].*{/,/^\}\;/c\\%s' examples/l3fwd/l3fwd_lpm.c" % lpmStr, "# ")
        out = self.dut.build_dpdk_apps("./examples/l3fwd", "USER_FLAGS=-DAPP_LOOKUP_METHOD=1")
        self.verify("Error" not in out, "compilation error 1")
        self.verify("No such file" not in out, "compilation error 2")

        # Backup the LPM exe and clean up the build.
        self.dut.send_expect("mv -f examples/l3fwd/build/l3fwd examples/l3fwd/build/l3fwd_lpm", "# ")
        out = self.dut.send_expect("make clean -C examples/l3fwd", "# ")

        # Compile l3fwd with hash/exact lookup.
	self.dut.send_expect(r"sed -i -e '/ipv4_l3fwd_em_route_array\[\].*{/,/^\}\;/c\\%s' examples/l3fwd/l3fwd_em.c" % exactStr, "# ")
        out = self.dut.build_dpdk_apps("./examples/l3fwd", "USER_FLAGS=-DAPP_LOOKUP_METHOD=0")

        self.verify("Error" not in out, "compilation error 1")
        self.verify("No such file" not in out, "compilation error 2")

        # Backup the Hash/Exact exe.
        self.dut.send_expect("mv -f examples/l3fwd/build/l3fwd examples/l3fwd/build/l3fwd_exact", "# ")

        self.l3fwd_test_results = {'header': [],
                                   'data': []}

    def flows(self):
        """
        Return a list of packets that implements the flows described in the
        l3fwd test plan.

        """   
        return [
            'IP(src="1.2.3.4",dst="11.100.0.1")',
            'IP(src="1.2.3.4",dst="11.101.0.1")',
            'IP(src="1.2.3.4",dst="10.100.0.1")',
            'IP(src="1.2.3.4",dst="10.101.0.1")',
            'IP(src="1.2.3.4",dst="13.100.0.1")',
            'IP(src="1.2.3.4",dst="13.101.0.1")',
            'IP(src="1.2.3.4",dst="12.100.0.1")',
            'IP(src="1.2.3.4",dst="12.101.0.1")']

    def repl(self, match):
        pid = match.group(1)
        qid = match.group(2)
        self.logger.debug("%s\n" % match.group(3))
        lcid = self.dut.get_lcore_id(match.group(3))
        self.logger.debug("%s\n" % lcid)

        global corelist
        corelist.append(int(lcid))

        self.verify(int(pid) in range(4), "invalid port id")
        self.verify(lcid, "invalid thread id")

        return '%s,%s,%s' % (str(valports[int(pid)]), qid, lcid)

    def set_up(self):
        """
        Run before each test case.
        """
        pass

    def test_perf_rfc2544(self):

        ports = self.dut.get_ports()
	print("****** No. of ports %s", len(ports))
        ports_num = len(ports)
	print("******* Port num", ports_num)
        header_row = ["Frame_size(byte)", "mode", "S/C/T", "zero_loss_throughput(Mpps)", " % zero_loss_rate"]# "LR_tx_pkts(1min)", "LR_rx_pkts(1min)", "LR_loss_pkts(1min)", "% zero_loss_rate", "zero_loss_throughput(Mpps)"]
        self.l3fwd_test_results['header'] = header_row
        self.result_table_create(header_row)
        self.l3fwd_test_results['data'] = []

        for frame_size in TestL3fwd.frame_sizes:

            # Prepare traffic flow
            payload_size = frame_size -  \
                HEADER_SIZE['ip'] - HEADER_SIZE['eth'] - HEADER_SIZE['tcp']

            for _port in range(ports_num):
                dmac = self.dut.get_mac_address(valports[_port])
                flows = ['Ether(dst="%s")/%s/TCP()/("X"*%d)' % (dmac, flow, payload_size) for flow in self.flows()[_port *2:(_port +1)*2]]
                self.tester.scapy_append('wrpcap("dst%d.pcap", [%s])' %(valports[_port],string.join(flows,',')))
            self.tester.scapy_execute()

            self.rst_report("Flows for %d ports, %d frame size.\n" % (ports_num, frame_size),
                       annex=True)
            self.rst_report("%s" % string.join(flows, '\n'),
                       frame=True, annex=True)

            # Prepare the command line
            global corelist
            pat = re.compile("P([0123]),([0123]),(C\{\d.\d.\d\})")

            pat2 = re.compile("C\{\d")
            repl1 = "C{" + str(self.port_socket)

            coreMask = {}
            rtCmdLines = {}
            cmdlist = []
            if ports_num == 4:
                for i in TestL3fwd.test_cases_4_ports:
                    cmdlist.append(i)
            else:
                for i in TestL3fwd.test_cases_2_ports:
                    cmdlist.append(i)
                if 'eagle' in self.nic:
                    del cmdlist[2]
                else:
                    del cmdlist[1]
            for cmdline_pat in cmdlist:
                corelist = []
                rtCmdLines[cmdline_pat[1]] = cmdline_pat[2]
                while pat.search(rtCmdLines[cmdline_pat[1]]):
                    # Change the socket to the NIC's socket
                    if cmdline_pat[1].find('1S')>=0:
                        rtCmdLines[cmdline_pat[1]] = pat2.sub(repl1, rtCmdLines[cmdline_pat[1]])
                    rtCmdLines[cmdline_pat[1]] = pat.sub(self.repl, rtCmdLines[cmdline_pat[1]])

                self.logger.info("%s\n" % str(corelist))
                coreMask[cmdline_pat[1]] = utils.create_mask(set(corelist))

            # measure by two different mode
            for mode in TestL3fwd.methods:

                # start l3fwd
                index = 0
                subtitle = []
                for cores in rtCmdLines.keys():

                    #in order to save time, only some of the cases will be run.
                    if mode == "lpm" and (cores == "1S/2C/1T" or cores == "1S/4C/1T"):
                        info = "Executing l3fwd using %s mode, %d ports, %s and %d frame size.\n" % (
                               mode, ports_num, cores, frame_size)

                        self.logger.info(info)
                        self.rst_report(info, annex=True)

                        subtitle.append(cores)
                        cmdline = rtCmdLines[cores] % (TestL3fwd.path + "l3fwd_" + mode, coreMask[cores],
                                                       self.dut.get_memory_channels(), utils.create_mask(valports[:ports_num]))  #cores
                        if self.nic == "niantic":
                            cmdline = cmdline + " --parse-ptype"

                        if frame_size > 1518:
                            cmdline = cmdline + " --enable-jumbo --max-pkt-len %d" % frame_size
                        self.rst_report(cmdline + "\n", frame=True, annex=True)

                        out = self.dut.send_expect(cmdline, "L3FWD:", 120)

                        # Measure test
                        tgenInput = []
                        for rxPort in range(ports_num):
                            # No use on rx/tx limitation
                            if rxPort % 2 == 0:
                                txIntf = self.tester.get_local_port(valports[rxPort + 1])
                            else:
                                txIntf = self.tester.get_local_port(valports[rxPort - 1])

                            rxIntf = self.tester.get_local_port(valports[rxPort])
                            if rxPort % 2 == 0:
                                tgenInput.append((txIntf, rxIntf, "dst%d.pcap" %valports[rxPort+1]))
                            else:
                                tgenInput.append((txIntf, rxIntf, "dst%d.pcap" %valports[rxPort-1]))

                        zero_loss_rate, tx_pkts, rx_pkts = self.tester.run_rfc2544(tgenInput, delay=60)
                        loss_pkts = tx_pkts - rx_pkts
                        self.dut.send_expect("^C", "#")
                        linerate = self.wirespeed(self.nic, frame_size, ports_num)
                        zero_loss_throughput = (linerate * zero_loss_rate) / 100

                        tx_pkts = utils.human_read_number(tx_pkts)
                        rx_pkts = utils.human_read_number(rx_pkts)
                        loss_pkts = utils.human_read_number(loss_pkts)


                        #data_row = [frame_size, mode, cores, tx_pkts, rx_pkts, loss_pkts, zero_loss_rate, zero_loss_throughput]
                        data_row = [frame_size, mode, cores, zero_loss_throughput, zero_loss_rate]
                        self.result_table_add(data_row)
                        self.l3fwd_test_results['data'].append(data_row)
                    else:
                        pass

                    index += 1

        self.result_table_print()

    def ip(self, port, frag, src, proto, tos, dst, chksum, len, options, version, flags, ihl, ttl, id):
        self.add_tcl_cmd("protocol config -name ip")
        self.add_tcl_cmd('ip config -sourceIpAddr "%s"' % src)
        self.add_tcl_cmd("ip config -sourceIpAddrMode ipRandom")
        self.add_tcl_cmd('ip config -destIpAddr "%s"' % dst)
        self.add_tcl_cmd("ip config -destIpAddrMode ipIdle")
        self.add_tcl_cmd("ip config -ttl %d" % ttl)
        self.add_tcl_cmd("ip config -totalLength %d" % len)
        self.add_tcl_cmd("ip config -fragment %d" % frag)
        self.add_tcl_cmd("ip config -ipProtocol ipV4ProtocolReserved255")
        self.add_tcl_cmd("ip config -identifier %d" % id)
        self.add_tcl_cmd("stream config -framesize %d" % (len + 18))
        self.add_tcl_cmd("ip set %d %d %d" % (self.chasId, port['card'], port['port']))

    def tear_down(self):
        """
        Run after each test case.
        """
        pass

    def tear_down_all(self):
        """
        Run after each test suite.
        """
        pass
