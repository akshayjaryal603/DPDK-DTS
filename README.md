# DPDK-DTS
modification in some DPDK-DTS files according to the system configurations

How to Install DPDK-DTS:-

-> In our case both the machines (DUT(Device under test) & TESTER) have Linux "Ubuntu 18.04-LTS".
-> For installing DPDK-DTS refer this documentation "https://doc.dpdk.org/dts/gsg/".
-> Before installing from git make sure you have git installed in your system otherwise run this command "apt install git" in your terminal.
-> Git clone link for installing DPDK test suite "git clone http://dpdk.org/git/tools/dts".
-> Git clone DPDK from this link "git clone git://dpdk.org/dpdk" if this link is not working then refer to the "DPDK.org".
-> After cloning DPDK run this command inside your terminal to "tar czf dpdk.tar.gz dpdk".
-> Please carefully run all the steps DTS code only support "tar.gz" format.
-> After creating dpdk.tar.gz then move this tar file to dts/dep folder with command "mv dpdk.tar.gz/ ~/dts/dep".

How to Run Hello_World test case in DPDK-DTS:-

-> Make sure your firewall is OFF. For checking status of your firewall run this command "sudo ufw status".
-> Changes made in execution.cfg, conf/crbs.cfg & conf/ports.cfg.
-> First step to make the ssh connection between DUT and TESTER machine in our case both machines are x86 machines.
-> For making ssh connection between DUT and TESTER machine run these basic commands: -
	1.) sudo apt update && sudo apt upgrade
	2.) sudo apt install open ssh-server
	3.) sudo systemctl start ssh
	4.) Make sure you have been set the password for the root access in the linux system.
	5.) For generating ssh key run this command "sudo ssh-keygen -t rsa". This command might be changed according to your security.
	6.) Now run ssh-copy-id -i root@'192.168.3.109'. Here the IP address is of your DUT machine. 
	    You have to follow all the above same steps in your DUT machine to make secure connection between DUT and Tester machine.
-> After following above steps you are successfully run Hello_world test case in DPDK-DTS. 

How to Run L2FWD test case in DPDK-DTS:-

-> For running l2fwd test case first install pktgen on tester machine.
-> Follow this link for installing pktgen "https://pktgen-dpdk.readthedocs.io/en/latest/getting_started.html#running-the-application".
-> Pktgen is used for generating packets. The stable version of pktgen and DPDK is "DPDK v18.02 & DPDK-pktgen v3.5.0".
-> Please follow above step carefully. This version issue is creating a chaos.
-> After installing pktgen for checking your pktgen is running successfully run l2fwd eal command in pktgen terminal.
-> Copy pktgen binary file and Pktgen.lua and paste then inside root directory.
-> To paste binary file to root directory follow this command "sudo mv pktgen /~".
-> Changes made in the etgen.py file regarding cores error. System is not able to fetch the cores because for fetching cores it calls 
   numa node and our machine is not supporting numa node it varies machine to machine. For resolving cores issue, we pass cores manually "cores = [1,2,3]". 
-> Also check the combination of socket, cores and thread in the l2fwd application.
-> Check socket configuration in your system by running "lscpu" commands. If your system support only one socket the you must change
   in the "TEST_SUITE_l2fwd.py" socket-mem = "--socket-mem 512". 
-> After following all the above the steps you can run the l2fwd test case in DPDK-DTS.

How to Run L3FWD test case in DPDK-DTS: -

-> Open "TEST_SUITE_l3fwd.py" and made changes in the test_case_4_port method comments all the lines because our system only supports 2 ports.
-> Error is core combination isn't correct. For resolving this issue made changes in the "crb.py" method name "get_lcore_id()". Here Decrement Coreid by 1 "Coreid = Coreid-1".
-> After all the changes you are successfully run the l3fwd test case. 
