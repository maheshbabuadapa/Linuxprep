 ## IPMI
The Intelligent Platform Management Interface (IPMI) is a set of computer interface specifications for an autonomous computer subsystem that provides management and monitoring capabilities independently of the host system's CPU, firmware (BIOS or UEFI) and operating system.

## Memory
  drop_caches
  Writing to this will cause the kernel to drop clean caches, dentries and inodes from memory, causing that memory to become free.
  ``` 
  To free pagecache:
      echo 1 > /proc/sys/vm/drop_caches
  To free dentries and inodes:
      echo 2 > /proc/sys/vm/drop_caches
  To free pagecache, dentries and inodes:
      echo 3 > /proc/sys/vm/drop_caches
  ```
## Kernel

**Kexec** is a system call that enables you to load and boot into another kernel from the currently running kernel.

Kdump is a standard Linux mechanism to dump machine memory content on kernel crash. Kdump is based on Kexec. Kdump utilizes two kernels: system kernel and dump capture kernel. System kernel is a normal kernel that is booted with special kdump-specific flags. We need to tell the system kernel to reserve some amount of physical memory where dump-capture kernel will be loaded. We need to load the dump capture kernel in advance because at the moment crash happens there is no way to read any data from disk because kernel is broken.



  kernel runtime parameters
  To set the kernel runtime parameters:
    through the /proc filesystem,
    with the sysctl command,
    through the /etc/sysctl.d directory.

  TODO: http://www.certdepot.net/rhel7-use-sysctl/

# system call
  system call is how a program requests a service from an operating system's kernel. This may include hardware-related services, creation and execution of new processes, and communication with integral kernel services such as process scheduling.

  glibc provides wrapper code which abstracts you away from the underlying code which arranges the arguments you’ve passed and enters the kernel.

  privilege levels:
    - Privilege levels are a means of access control. The current privilege level determines which CPU instructions and IO may be performed
    - The kernel runs at the most privileged level, called “Ring 0”. User programs run at a lesser level, typically “Ring 3”.
  interrupts: a way to cause a privilege level change and trigger the kernel to perform some action.
  in order to resume execution the kernel just needs to copy these values from the program stack back into the registers where they belong and execution will resume back in userland.

  On 64bit systems use: syscall and sysret
    - SYSCALL invokes an OS system-call handler at privilege level 0.
    - sysret instruction to resume execution back to where execution left off when the user program used syscall

  syscall(42 , exit_status);
   echo $?
   42

  Linux virtual Dynamic Shared Object (vDSO) is a set of code that is part of the kernel, but is mapped into the address space of a user program to be run in userland. One such call is: gettimeofday.

[special files]
  - block files: hardware files most of them are present in /dev.
  - character device files: Provides a serial stream of input or output.
  - named pipe file: Use mkfifo command.
  - symbolic link file: The inode number for this file and its parent files are same.
  - socket file: to pass information between applications for communication purpose


[LVS Linux Virtual Server]
  Ipvsadm(8)  is  used  to set up, maintain or inspect the virtual server
       table in the Linux kernel. The Linux Virtual  Server  can  be  used  to
       build  scalable  network  services  based  on  a cluster of two or more
       nodes. The active node of the cluster redirects service requests  to  a
       collection  of  server  hosts  that will actually perform the services.
       Supported features include two protocols (TCP and UDP),  three  packet-
       forwarding methods (NAT, tunneling, and direct routing), and eight load
       balancing algorithms (round robin, weighted round robin,  least-connec-
       tion,   weighted   least-connection,  locality-based  least-connection,
       locality-based least-connection with replication,  destination-hashing,
       and source-hashing).



[linux-distro]
  Centos vs Ubuntu server
    Package management system (rpm vs deb)
      CentOS is built from publicly available (Advanced Server flavor) source code provided by Red Hat, Inc.
      Development of Ubuntu is led by UK-based Canonical Ltd
    Application control panel compatibility (CentOS dominates web hosting industry)
    New software will usually come to Ubuntu repos before CentOS
    Support Cycle
      CentOS-5 updates until March 31, 2017
      CentOS-6 updates until November 30, 2020
      CentOS-7 updates until June 30, 2024

    Ubuntu on EC2
      Ubuntu images are published directly into AWS using the same release process as the distribution (Images are regularly updated)
      Ubuntu Server is free of cost, however you can optionally buy support

      CentOS has a longer release cycle (hence more stability, consistency)
      CentOS is officially part of Red Hat (Jan 2014)
    Architectures
      CentOS 6 currently supports x86 and x86_64
      CentOS 7 currently supports x86_64
    Default Settings
      Ubuntu forces sudo use by default and disables the root account

  When running multiple machine with the same distribution, it is interesting to set up a repository cache on your network so that once a package is downloaded from an official repository, all other machines will download it from your local area network.

[Linux-interal]


  "IP forwarding" is a synonym for "routing." It is called "kernel IP forwarding" because it is a feature of the Linux kernel.


[boot process]
  Unified Extensible Firmware Interface (UEFI) Secure Boot.
  A power-on self-test (POST) is a process performed by firmware or software routines immediately after a computer or other digital electronic device is powered on.  POST routines are part of a device's pre-boot sequence and only once they complete successfully is the bootstrap loader code invoked to load an operating system.
  A boot loader is a computer program that loads an operating system.
  When the kernel is loaded, it immediately initializes and configures the computer's memory and configures the various hardware attached to the system, including all processors, I/O subsystems, and storage devices. It then looks for the compressed initrd image in a predetermined location in memory, decompresses it, mounts it, and loads all necessary drivers.
  The kernel then creates a root device, mounts the root partition read-only.
  To set up the user environment, the kernel executes the /sbin/init program.

  The main purpose of initramfs is to enable mounting of the root filesystem. It is a complete set of directories that you would find on a normal root filesystem. It is bundled into a single compressed cpio archive. If you can tell the kernel which filesystem and which filesystem type to mount, you can mostly eliminate the need for an initramfs.



  [process management]
  PROCESS STATE CODES
       D   uninterruptible sleep (usually IO)
       R   runnable (on run queue)
       S   sleeping
       T   traced or stopped
       Z   a defunct ("zombie") process

  kill command will kill a process using the kill signal and PID
  killall command kills all process with a particular name.
  pkill is a lot like killall
  SIGHUP (1)  The SIGHUP signal disconnects a process from the parent process. This an also be used to restart processes. For example, "killall -SIGHUP compiz" will restart Compiz. This is useful for daemons with memory leaks.
  SIGQUIT (3) This is like SIGINT with the ability to make the process produce a core dump.
  SIGKILL (9) The SIGKILL signal forces the process to stop executing immediately. The program cannot ignore this signal. This process does not get to clean-up either.
  SIGTERM (15) This signal requests a process to stop running. This signal can be ignored. The process is given time to gracefully shutdown. When a program gracefully shuts down, that means it is given time to save its progress and release resources. In other words, it is not forced to stop. SIGINT is very similar to SIGTERM.
  SIGINT - This signal is the same as pressing ctrl-c. The process is interrupted and stopped. However, the process can ignore this signal.

  zombie (or defunct) processes are dead processes that still apear in the process table, usually because of bugs and coding errors. A zombie process remains in the operating system and does nothing until the parent process determines that the exit status is no longer needed. Normally, when a process finishes execution, it reports the execution status to its parent process. Until the parent process decides that the child processes exit status is not needed anymore, the child process turns into a defunct or zombie process. It does not use resources and it cannot be scheduled for execution.
  ps aux | grep Z

  An Orphan Process is a process whose parent is dead (terminated). A process with dead parents is adopted by the init process. when a process crashes, it leaves the children processes alive, transforming them into orphan processes. A user can also create a orphan process, by detaching it from the terminal.

  exec is a functionality of an operating system that runs an executable file in the context of an already existing process, replacing the previous executable. This act is also referred to as an overlay.

  fork:  For a process to start the execution of a different program, it first forks to create a copy of itself. Then, the copy, called the "child process", calls the exec system call to overlay itself with the other program.
  The fork operation creates a separate address space for the child. The child process has an exact copy of all the memory segments of the parent process.
  Upon successful completion, fork() returns a value of 0 to the child process and returns the process ID of the child process to the parent process. Otherwise, a value of -1 is returned to the parent process, no child process is created, and the global variable errno is set to indicate the error.

  Traditionally, upon fork() all resources owned by the parent are duplicated and the copy is given to the child. This approach is significantly naïve and inefficient in that it copies much data that might otherwise be shared. Worse still, if the new process were to immediately execute a new image, all that copying would go to waste. In Linux, fork() is implemented through the use of copy-on-write pages. Copy-on-write (or COW) is a technique to delay or altogether prevent copying of the data. Rather than duplicate the process address space, the parent and the child can share a single copy. The data, however, is marked in such a way that if it is written to, a duplicate is made and each process receives a unique copy. Consequently, the duplication of resources occurs only when they are written; until then, they are shared read-only. This technique delays the copying of each page in the address space until it is actually written to. In the case that the pages are never writtenfor example, if exec() is called immediately after fork()they never need to be copied. The only overhead incurred by fork() is the duplication of the parent's page tables and the creation of a unique process descriptor for the child. In the common case that a process executes a new executable image immediately after forking, this optimization prevents the wasted copying of large amounts of data (with the address space, easily tens of megabytes). This is an important optimization because the Unix philosophy encourages quick process execution.


[systemd]
  Debian’s stated reasons for switching back to GNOME was because of its systemd integration.
  systemd is a replacement for the old SysV init system
  When you boot up, init is responsible for loading the appropriate drivers, activating your network connection, launching various system services
  It can also launch services in response to events.

  systemd processes are sfted using systemctl. It aggressively parallelizes service startup accordingly. It will also track services correctly, with or without PID files, and restart them when they terminate unexpectedly.
  The configuration files are declarative instead of procedural as with SysV init, and comparatively short.
  Services can be started when a device is plugged in, when a mount point becomes available, when a path is created or on a timer.
  systemd opens a socket and starts a service, passing the socket to the service.
  A service does not have to daemonize to work with systemd.
  systemd natively supports starting services in their own container.



  journald, an event-logging system that controversially writes to binary files and not text ones.

  udev is a device manager for the Linux kernel. udev primarily manages device nodes in the /dev directory. At the same time, udev also handles all user space events raised while hardware devices are added into the system or removed from it, including firmware loading.
  udev, as a whole, is divided into three parts: (Library libudev that allows access to device information; User space daemon udevd that manages the virtual /dev; Administrative command-line utility udevadm for diagnostics)

  Netlink socket family is a Linux kernel interface used for inter-process communication (IPC) between both the kernel and userspace processes, and between different userspace processes.



[initd]
  When SysV init takes over control from the kernel, the init(8) process reads /etc/inittab and follows the configuration therein.
  - While many people do use the init script /etc/init.d/$name directly, this is actually problematic, as it starts the init script with the current environment, which might be different from the environment available at boot time.
  - On Debian systems, init scripts are parallelized using the startpar program, which reads dependency information from specifically formatted comments in the init scripts.
  - To figure out if a process is running, SysV init sends signal 0 to the process. SysV init can send signal 0 to a PID, but it still does not know if the service terminated long ago and the PID was re-used by the kernel for a different process. It also checks if /proc/$pid/exe is the right executable for the process.
  - Process environments adjustment is either done by the service itself instead of the init system, or not at all.
  - Admin is left with multiple different places to look for whether a service is running; inetd, xinetd, supervisor or circus.
  - SysV init simply expects each and every service to re-implement common functionality.
  - All services that open TCP ports below 1024 are expected to start as root, open the socket, and drop user privileges by themselves.
  - With SysV init, if a service can’t open its log file or can’t connect to syslog for some reason, there is no way for it to notify the administrator of that problem.

[Debian]
  Debian 7 “Wheezy” from 26th of April 2016 to 31st of May 2018
  Debian 6 “Squeeze” until 29th of February 2016

  dpkg-query -l   # list of installed packages


---
[Performance Tuning Guide]
  Red Hat Enterprise Linux
  Perf is a profiler tool for Linux 2.6+ based systems that abstracts away CPU hardware differences in Linux performance measurements and presents a simple commandline interface. Perf is based on the perf_events interface exported by recent versions of the Linux kernel.

  TODO:
    https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Performance_Tuning_Guide/ch01s02.html

  Examining Load Average
    The three load-average values in the first line of top output are the 1-minute, 5-minute and 15-minute average.
    If top reports that your program is taking 45% CPU, 45% of the samples taken by top found your process active on the CPU. The rest of the time your application was in a wait.
    1) load averages measure the trend in CPU utilization not only an instantaneous snapshot, as does percentage
    2) load averages include all demand for the CPU not only how much was active at the time of measurement.
    The point of perfect utilization, meaning that the CPUs are always busy and, yet, no process ever waits for one, is the average matching the number of CPUs. In general, the intuitive idea of load averages is the higher they rise above the number of processors, the more demand there is for the CPUs, and the lower they fall below the number of processors, the more untapped CPU capacity there is.





  iostat
  ionice
  atop
  htop
  sar
  ksar
  vmstat
  iotop
    displays columns for the I/O bandwidth read and written by each process/thread during the sampling period
    iotop --only



[self-signed certificate]
  private key file (server.key), certificate signing request file (server.csr) and webserver certificate file (server.crt)


[repository]
  - EPEL Fedora Extra Packages for Enterprise Linux (EPEL) repository, useful software packages that are not included in the official CentOS or RHEL.
  EPEL is a Fedora Special Interest Group that creates, maintains, and manages a high quality set of open source add-on software packages for Enterprise Linux.
  - IUS repository provides newer versions of some software in the official CentOS and Red Hat repositories. The IUS repository depends on the EPEL repository. The package names in the IUS repository are different from the package names used in the official repositories.
  - Remi repository provides newer versions of the software in the core CentOS and Red Hat Enterprise Linux repositories. The Remi repository depends on the EPEL repository. Package names in the Remi repository are the same as the package names used in the official repositories. This similarity can result in inadvertent package upgrades.


[ssh]
  ssh -L [bind_address:]port:host:hostport
             Specifies that the given port on the local (client) host is to be forwarded to the given host and port on the remote side.  This works by allocating a
             socket to listen to port on the local side, optionally bound to the specified bind_address.  Whenever a connection is made to this port, the connection is
             forwarded over the secure channel, and a connection is made to host port hostport from the remote machine.  Port forwardings can also be specified in the
             configuration file.
             check out "reverse tunnel", as well.

  ssh-keygen -o -p -f id_ecdsa -a 64
    new private key format for OpenSSH, thanks to markus and djm. It’s enabled automatically for keys using ed25519 signatures

[tar archive]
  tar -cvf bob_backup.tar *
  tar -cvpfz
    -p - preserves dates, permissions of the original files
  split -d -b 2000m /path/to/backup.tar.gz /name/of/backup.tar.gz.
    split into 2GB files /name/of/ and be named backup.tar.gz.01
    cat *tar.gz* | tar -xvpzf - -C /
  nc
    “-w1” switch tells netcat to quit if the input stream is idle for more than 1 second.
    -l      Used to specify that nc should listen for an incoming connection rather than initiate a connection to a remote host.
    -p source_port

  tar cvJfh
    create
    verbose
    --xz compression
    use archive file
    follow symbolic links


[file system]
operating system makes no distinction between the name that was originally assigned to a file when it was first created and any hard links that are subsequently created to that file other than that they are merely multiple names for the same file. The rm command superficially appears to remove or delete files. What it really does, however, is to reduce a file's hard link count.

Deleting a file on a Unix file system involves three steps:
  - Removing its directory entry.
  - Releasing the inode to the pool of free inodes.
  - Returning all used disk blocks to the pool of free disk blocks.
After a crash, recovery simply involves reading the journal from the file system and replaying changes from this journal until the file system is consistent again.

journaling:
  A journaling file system is a file system that keeps track of changes not yet committed to the file system's main part by recording the intentions of such changes in a data structure known as a "journal", which is usually a circular log.
  Circular buffering makes a good implementation strategy for a queue that has fixed maximum size. All queue operations are constant time.


[RAID]
  /etc/mdadm.conf
  /proc/mdstat
  mdadm --detail /dev/md0
  The goal of multipath storage is continued data availability in the event of hardware failure or individual path saturation.
  Multipath Device With mdadm
    SCSI LUN (disk drive) known as /dev/sda may also be accessible as /dev/sdb, /dev/sdc, and so on, depending on the specific configuration
    multipath directs the md layer in the Linux kernel to re-route I/O requests from one pathway to another in the event of an I/O path failure
    mdadm -C /dev/md0 --level=multipath --raid-devices=4 /dev/sda1 /dev/sdb1 /dev/sdc1 /dev/sdd1

  mdadm --detail --scan >> /etc/mdadm.conf

[network-internal]
  nethogs is a simple console app that displays bandwidth per process, so you can quickly see who is hogging your network.
  iperf reports bandwidth, delay jitter, and datagram loss.

  Transfer rates in gigabit networks
  Even the slowest DDR2 RAM should be able to handle over 3,000 MB/s of data, the only limiting factor should be how fast our network can run.
  We’re seeing a 111.4 MB/s maximum speed over our gigabit network, which is very close to a gigabit network’s theoretical 125 MB/s.

  ip
  View / Display Routing Table
    ip route list
  All network packets that cannot be sent according to the previous entries of the routing table are sent through the gateway
    ip route add default via 192.168.1.254
    ip route delete 192.168.1.0/24 dev eth0
  Only show running interfaces
    ip link ls up

  ip a list
  ip a show eth0
  ip a add 192.168.1.200/24 dev eth0
  ip a add broadcast 172.20.10.255 dev dummy0
  ip addr add 192.168.1.50/24 brd + dev eth0 label eth0Home
  ip a del 192.168.1.200/24 dev eth0
  ip link set dev eth1 down
  ip n show   # Display neighbour/arp cache


  ip route add default via {GATEWAYIP}
  ip r list
  ip route add {NETWORK/MASK} via {GATEWAYIP}
  ip route add {NETWORK/MASK} dev {DEVICE}
  ip route add default {NETWORK/MASK} dev {DEVICE}
  ip route del default via GW-IP-Address

  ip route list table main
  ip rule ls

  cat /proc/net/arp
  sudo ip -s -s neigh flush all   # flushes arp table
  /sbin/ip route flush table all  # deletes all routing table

  netstat -rn

  ip link add link enp0s8 name enp0s8.100 type vlan id 100

  multicast 224.0.0.0 to 239.255.255.255.
    MAC Address 01:00:5e:xx:xx:xx
  IGMP used to subscribe to multicast channel


  [Interface Bridging]
  Note that a bridge cannot be established over Wi-Fi networks operating in Ad-Hoc or Infrastructure modes.
  modprobe --first-time bridge
  modinfo bridge
  create a file in the /etc/sysconfig/network-scripts/ifcfg-brN
    DEVICE=br0
    TYPE=Bridge
    IPADDR=192.168.1.1
    PREFIX=24
    BOOTPROTO=none
    ONBOOT=yes
    DELAY=0
  DELAY=0, is added to prevent the bridge from waiting while it monitors traffic

  Configure your physical interface in /etc/sysconfig/network-scripts/ifcfg-ethX
    BRIDGE=br0
  The directives are case sensitive.
  ifup device
  Alternatively, to reload all interfaces
    systemctl restart network

  [Interface Bonding]
  bond.conf
  The Linux bonding driver provides a method for aggregating multiple network interfaces into a single logical "bonded" interface.

  - Create a Bond0 Configuration File
  /etc/sysconfig/network-scripts/ifcfg-bond0

  - Modify eth0 and eth1 config files
  MASTER=bond0

  - Load bond driver/module
  vi /etc/modprobe.conf
  alias bond0 bonding
  options bond0 mode=balance-alb miimon=100

  http://www.unixmen.com/linux-basics-create-network-bonding-on-centos-76-5/

  169.254.0.0/16 addresses explained
    http://packetlife.net/blog/2008/sep/24/169-254-0-0-addresses-explained/

  Linux Network Namespaces


[firewalld]
  firewalld daemon manages groups of rules using entities called "zones"

  firewalld
  systemctl status firewalld
  firewall-cmd --get-zones
    block dmz drop external home internal public trusted work
  firewall-cmd --get-default-zone
  firewall-cmd --get-services
  /etc/firewalld/services   # user created services
  /usr/lib/firewalld/services   # default services
    the module name that have to be enabled is listed as well.
  firewall-cmd --zone=home --add-service=high-availability
  firewall-cmd --permanent --zone=home --add-service=high-availability
  firewall-cmd [--zone=<zone>] --list-all
  firewall-cmd --list-all-zones
  firewall-cmd --get-active-zones
  firewall-cmd --get-zone-of-interface=<interface>
  firewall-cmd [ --zone=<zone> ] --list-services
  firewall-cmd [--zone=<zone>] --add-service=<service> [--timeout=<seconds>]
  firewall-cmd [--zone=<zone>] --remove-port=<port>[-<port>]/<protocol> [--timeout=<seconds>]
  firewall-cmd [--zone=<zone>] --add-masquerade
  firewall-cmd [--zone=<zone>] --add-icmp-block=<icmptype>
  firewall-config
  firewall-cmd --panic-on #  to block all network traffic in case of emergency

  Create custom service
  sudo firewall-cmd --set-default-zone=dmz
  sudo firewall-cmd --zone=dmz --change-interface=eth0
  sudo cp /usr/lib/firewalld/services/ssh.xml /etc/firewalld/services/zabbix.xml
  sudo firewall-cmd --reload
  sudo firewall-cmd --zone=dmz --add-service=zabbix --permanent
  sudo firewall-cmd --zone=dmz --list-services


  Masquerading: The addresses of a private network are mapped to and hidden behind a public IP address. This is a form of address translation.
  The zone is stored into the ifcfg of the connection with the ZONE= option.
  If the connection is controlled by NetworkManager, you can also use nm-connection-editor to change the zone.
  For connections handled by network scripts there a limitations: There is no daemon that can tell firewalld to add connections to zones. This is done in the ifcfg-post script only. Push all connections to the default zone that are not set otherwise.


  zones:
  A connection can only be part of one zone
  These are the zones provided by firewalld sorted according to the default trust level of the zones from untrusted to trusted:
    drop
    Any incoming network packets are dropped, there is no reply. Only outgoing network connections are possible.
     block
    Any incoming network connections are rejected with an icmp-host-prohibited message for IPv4 and icmp6-adm-prohibited for IPv6. Only network connections initiated within this system are possible.
     public
    For use in public areas. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.
     external
    For use on external networks with masquerading enabled especially for routers. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.
     dmz
    For computers in your demilitarized zone that are publicly-accessible with limited access to your internal network. Only selected incoming connections are accepted.
     work
    For use in work areas. You mostly trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.
     home
    For use in home areas. You mostly trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.
     internal
    For use on internal networks. You mostly trust the other computers on the networks to not harm your computer. Only selected incoming connections are accepted.
     trusted
    All network connections are accepted.

  Static Firewall (system-config-firewall/lokkit)
  If you want to use your own static firewall rules with the iptables and ip6tables services, install iptables-services and disable firewalld and enable iptables and ip6tables.

  iptables -L

  # you should ensure that the default policy on your INPUT and OUTPUT chains are set to ACCEPT prior to flushing your rules.
  sudo iptables -P INPUT ACCEPT
  sudo iptables -P OUTPUT ACCEPT
  sudo iptables -F

  # conntrack module. This module gives access to commands that can be used to make decisions based on the packet's relationship to previous connections. --ctstate allows us to match packets based on how they are related to packets we've seen before.
  sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

  #
  sudo iptables -I INPUT 1 -i lo -j ACCEPT

  sudo iptables -S
  -P INPUT ACCEPT
  -P FORWARD ACCEPT
  -P OUTPUT ACCEPT
  -A INPUT -i virbr0 -p udp -m udp --dport 53 -j ACCEPT
  -A INPUT -i virbr0 -p tcp -m tcp --dport 53 -j ACCEPT
  -A INPUT -i virbr0 -p udp -m udp --dport 67 -j ACCEPT
  -A INPUT -i virbr0 -p tcp -m tcp --dport 67 -j ACCEPT
  -A FORWARD -d 192.168.122.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  -A FORWARD -s 192.168.122.0/24 -i virbr0 -j ACCEPT
  -A FORWARD -i virbr0 -o virbr0 -j ACCEPT
  -A FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable
  -A FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable
  -A OUTPUT -o virbr0 -p udp -m udp --dport 68 -j ACCEPT

[GDB]
  gcc -dumpspecs

[SDN]
  Software defined networking
  components
    SDN controller = network operating system
    Forwarding devices
    Netw. Applications

  Flow entries on forwarding devices would expire after they time out.

  Forwarding devices provide programmable interface like openflow or they can be software switches like open vSwitch.
    OpenFlow is added as a feature to commercial Ethernet switches, routers and wireless access points – and provides a standardized hook to allow researchers to run experiments, without requiring vendors to expose the internal workings of their network devices.
    Open vSwitch is a production quality, multilayer virtual switch licensed under the open source Apache 2.0 license.  It is designed to enable massive network automation through programmatic extension, while still supporting standard management interfaces and protocols.

  Southbound Interface: SDN controller communicate with forwarding devices. Information includes:
    packet handle instructions
    alerts on packet arrivals on network nodes
    notification of status changes, links going down, statistics information

[syslog-ng]
  Sources are where log information comes from, destinations are where it goes. Filters are used to filter messages on their path through the logging system. All of these configuration options are stored in /etc/syslog-ng/syslog-ng.conf
    netstat -tanpu|grep syslog
  Destinations are where log messages go.
  In theory the syslog server will not be doing much else so it's internal logs can be sent to one file.
    destination d_int
    {
      file("/var/log/localhost/$YEAR/$MONTH/$DAY/messages.log" \
        owner(root) group(root) perm(0600) dir_perm(0700) create_dirs(yes));
    };
  The external messages are to directories in the form of /host/year/month/day/facility.log
    destination d_ext
    {
      # This seperated by severity too.
      file("/var/log/$HOST/$YEAR/$MONTH/$DAY/$FACILITY-$PRIORITY.log" \
        owner(root) group(root) perm(0600) dir_perm(0700) create_dirs(yes));
    };
  Syslog-ng provides more $MACRO expansion options, including numeric $TAG and $PRI fields.

  Configure Sources
    source s_internal
    {
      internal(); # syslog-ng messages
      pipe("/proc/kmsg");
      unix-stream("/dev/log");
    };
    source s_external { udp(ip(192.168.0.1) port(514) ); };
  Log message need to be stored somewhere to be useful, use destinations to accomplish this. Messages can be sent to files, network hosts or programs. These destinations only describe where to put log messages, not which messages to put there.
    destination d_file { file("/var/log/messages"); };  //puts all the messages in one file
    destination d_fancy_file { file("/var/log/$YEAR/$MONTH/$DAY/$FACILITY.$PRIORITY.log" \
        owner(root) group(root) perm(0600) dir_perm(0700) create_dirs(yes)); }; //creates special files for each message type
    destination d_network { udp( "192.168.0.1" port(514) ); };  //sends the messages to a different host, which is hopefully listening
    destination d_program { program("/opt/edoceo/sql2syslog"); };   // send the log messages as one line to the STDIN

  sources messages must now be connected to a destination, optionally with a filter, by the log statement.
    log { source(s_everything); desitnation(d_network); };

  // A single source is sent to multiple destinations.
  source s_all { internal(); pipe("/proc/kmsg"); unix-stream("/dev/log"); };
  destination d_file { file("/var/log/$FACILITY.log"); };
  destination d_date { file("/var/log/$YEAR/$MONTH/$DAY/$FACILITY.log" create_dirs(yes) ); };
  log { source(s_all); destination(d_file); destination(d_date); };

  syslog-ng.conf
  flush_lines is useful on the client side of syslog-ng. You would keep xx messages on the client before flushing to the destination so that you are not flooding the main syslog-ng server

  use_dns If your syslog-ng is behind a firewall and not accessible to the outside of the world then 'yes'; 'persist_only' which checks my /etc/hosts file on my syslog-ng server

  stats_freq statistics messages about dropped log messages. 0 disables STATS

  bad_hostname(default: ^gconfd$ ) - Regex containing hostnames that should not be handled as hostnames
  keep_hostname(yes) - This keeps the hostname if running through a relay or an external server; If you're using $HOST macro, this should be enabled.
  stats_freq(600) and stats_level(2)

  source s_net { tcp((ip(127.0.0.1) port(1000) max-connections 5000)); udp (); };
  destination d_net_auth { file("/var/log/syslog/remote/$HOSTNAME/auth.log"); };
  destination d_net_cron { file("/var/log/syslog/remote/$HOSTNAME/cron.log"); };
  destination d_net_mailwarn { file("/var/log/syslog/remote/$HOSTNAME/mail/mail.warn"); };
  destination d_net_mailerr {file("/var/log/syslog/remote/$HOSTNAME/mail/mail.err"); };

  Errors in syslog-ng are reported in /var/log/errors

  Filtering allows you to specify multiple hosts to filter based on, and into multiple destinations.
  filter <identifier> { expression; };
  filter firewall_ddos_filter { host("10.1.1.1") and match("Denial of Service" value("MESSAGE")); };
  //listens for incoming syslog messages from 10.1.1.1 with a message of 'Denial of Service'.
  filter firewall_ddos_filter { host("10.1.1.1") or host ("10.1.1.2") and match("Denial of Service" value("MESSAGE")); };
  log firewall_ddos_filter { source(s_net); filter(firewall_ddos_filter); destination(d_net_firewall_ddos); };

  filter f_debug { level(debug) and not facility(auth, authpriv, news, mail); };
  filter f_error { level(err .. emerg) ; };
  filter f_messages { level(info,notice,warn) and not facility(auth,authpriv,cron,daemon,mail,news);};

  Statistics
  echo STATS | nc -U /var/run/syslog-ng.ctl
  syslog-ng-ctl stats | sed 's|;|\t|g'  //SourceName, SourceID, SourceInstance, State, Type and Number

  Log Rotate
  /etc/logrotate.conf
  Logs are rotated for 1 month at which point I have a cronjob that tar-zips my old logs and they are moved off to a backup location where they are kept for another month before being rotated off.

  Syslog communicates on UDP port 514
  rsyslog clients add the following line:
  For TCP:  *.* @@ipaddress:1000
  For UDP:  *.* @ipaddress:514


[streaming protocols]
  Streaming may be adaptive. This means that the rate of transfer will automatically change in response to the transfer conditions.
  Adaptive streaming technologies enable the optimum streaming video viewing experience for a diverse range of devices over a broad set of connection speeds.
  Streaming can be broadly divided into on-demand and real-time categories.

  Adaptive Streaming Vendors and Service Providers
    The players fall into three general categories: technology developers, service providers and standard-based technologies.
    Technology providers include
      Adobe with Flash-based Dynamic Streaming
      Apple with HTTP Live Streaming (HLS)
      Microsoft with Smooth Streaming for Silverlight


[proxy]
reverse proxy vs forwarding proxy


[openssl]
echo | openssl s_client -showcerts -servername gnupg.org -connect gnupg.org:443 2>/dev/null | openssl x509 -inform pem -noout -text


---
[LDAP]
  Domain Component
  Organizational Unit
  Groups
  Unit
  Entries

  slapd standalone ldap daemon

  kc07-c1
  kc07-s1

  kc07-s1.saeedab.local
  duser02 USER)@
  duser03 USER)#


  https://www.certdepot.net/rhel7-configure-ldap-directory-service-user-connection/

[nfs]

[Logical volume management]
LVM disk partition
  # resize root disk partition
  sudo poweroff
  sudo fdisk -l
  sudo pvdisplay
  sudo pvcreate /dev/xvdb
  sudo pvdisplay
  sudo vgdisplay
  sudo vgextend centos /dev/xvdb
  sudo vgdisplay
  sudo pvdisplay
  sudo lvdisplay
  sudo lvextend -l +100%FREE /dev/centos/root
  sudo lvdisplay
  sudo xfs_growfs /
  df -h



[cron]
  Minute   Hour   Day of Month       Month          Day of Week        Command
  When cron job is run from the users crontab it is executed as that user.
  It does not however source any files in the users home directory like their .cshrc or .bashrc or any other file.

[mail]
  MTA


  #!/bin/sh
  template=`cat <<TEMPLATE
  Notification Type: $NOTIFICATIONTYPE
  Service: $SERVICEDESC
  Host: $HOSTALIAS
  Address: $HOSTADDRESS
  State: $SERVICESTATE
  Date/Time: $LONGDATETIME
  Additional Info: $SERVICEOUTPUT
  Comment: [$NOTIFICATIONAUTHORNAME] $NOTIFICATIONCOMMENT
  TEMPLATE
  `

  /usr/bin/printf "%b" "$template" | mail -s "$NOTIFICATIONTYPE - $HOSTDISPLAYNAME - $SERVICEDISPLAYNAME is $SERVICESTATE" $USEREMAIL

  echo "Message" | mail -s "Subject" -a /loc/to/attachment.txt email@address
  -q file Sets the message contents from the given file
  -r from address Sets the from address of the e-mail to be sent
  -s subject Sets the e-mail subject

[DNS]
  Domain Name System
  top-level domain, or TLD, is the most general part of the domain, controlled by ICANN (Internet Corporation for Assigned Names and Numbers).
  bare domain (example.com)
  At the top of this system is what are known as "root servers". There are currently 13 root servers in operation.
  SLD, which means second level domain. In ubuntu.com, "ubuntu" portion is called a SLD.
  A fully qualified domain name, often called FQDN, is what we call an absolute domain name.
  "authoritative", meaning that they give answers to queries about domains under their control.
  A zone file is a simple text file that contains the mappings between domain names and IP addresses.
  a record is basically a single mapping between a resource and a name.
  The "domain name server" checks its zone files and it finds that it has a zone file associated with the query.
  A "resolving name server" is basically an intermediary for a user which caches previous query results to improve speed and knows the addresses of the root servers to be able to "resolve" requests made for things it doesn't already know about.
  A zone file describes a DNS "zone", which is basically a subset of the entire DNS naming system.
  zone's $ORIGIN is a parameter equal to the zone's highest level of authority by default.
  Start of Authority, or SOA, record is a mandatory record in all zone files
  @, which is just a placeholder that substitutes the contents of the $ORIGIN
  CNAME records define an alias for canonical name for your server
  CNAME is recommended is to provide an alias for a resource outside of the current zone.
  The "A" record is used to map a host to an IPv4 IP address, while "AAAA" records are used to map a host to an IPv6 address.
  MX records are used to define the mail exchanges that are used for the domain
  NS Records defines the name servers that are used for this zone; for multiple levels of caching.
  The Start of Authority, or SOA, record is a mandatory record in all zone files. It must be the first real record in a file (although $ORIGIN or $TTL specifications may appear above).

  How DNS works?
    At the top of this system is what are known as "root servers".

  A + Dynamic DNS record


  NS record
  SRV record
  TODO: https://www.digitalocean.com/community/tutorials/how-to-configure-bind-as-a-private-network-dns-server-on-centos-7

  SPF
  The Sender Policy Framework (SPF) attempts to control forged email by giving domain owners a way to specify which email sources are legitimate for their domain and which ones aren’t.
  You can add an SPF record to your DNS zone as a TXT record.

  DNSSEC on an Authoritative BIND DNS Server
  DNS Security Extensions (DNSSEC)

[alert]
  monitor notification disk usage

  #!/bin/bash
  CURRENT=$(df / | grep / | awk '{ print $5}' | sed 's/%//g')
  THRESHOLD=90
  if [ "$CURRENT" -gt "$THRESHOLD" ] ; then
      mail -s 'Disk Space Alert' mailid@domainname.com << EOF
  Your root partition remaining free space is critically low. Used: $CURRENT%
  EOF
  fi


[linux-man]
  MANUAL SECTIONS
    The standard sections of the manual include:

    1      User Commands
    2      System Calls
    3      C Library Functions
    4      Devices and Special Files
    5      File Formats and Conventions
    6      Games et. Al.
    7      Miscellanea
    8      System Administration tools and Deamons

  man 5 /etc/crypttab
  man 5 /etc/modprobe.d



[shell]
  KornShell (ksh) is a Unix shell which was developed by David Korn at Bell Labs in the early 1980s and announced at USENIX on July 14, 1983.[1][2] The initial development was based on Bourne shell source code.

  tcsh is a Unix shell based on and compatible with the C shell (csh). It is essentially the C shell with programmable command-line completion, command-line editing, and a few other features.

  #!/bin/bash
  for f in /source/project10/*.pl
  do
     cat -n "$f"
  done

  $@  represent all the arguments in bash.
  1>filename        # Redirect stdout to file "filename."
  2>filename        # Redirect stderr to file "filename."
  2>&1              # Redirects stderr to stdout.
  bad_command >>filename 2>&1       # Appends both stdout and stderr to the file "filename"

  command1 && command2    Command2 is executed if, and only if, command1 returns an exit status of zero
  command1 ││ command2    Command2 is executed if and only if command1 returns a non-zero exit status


  [ -a FILE ]	True if FILE exists.
  [ -s FILE ]	True if FILE exists and has a size greater than zero.
  [ -f FILE ]	True if FILE exists and is a regular file.
  [ -d FILE ]	True if FILE exists and is a directory.
  [ -r FILE ]	True if FILE exists and is readable.
  [ -n STRING ] or [ STRING ]	True if the length of "STRING" is non-zero.
  [ EXPR1 -a EXPR2 ]  True if EXPR1 and EXPR2 are true.

  if [ -r file -a ! -s file ]; then   # if file exists and has size zero.

  pattern matching with the "(( EXPRESSION ))" and "[[ EXPRESSION ]]" constructs.
  if [[ "$gender" == f* ]]


  $ cut - remove sections from each line of files
    Linux command cut is used for text processing.
    cut -c1-3 test.txt  # extracts first 3 characters of each line
    cut -c2 test.txt  # displays 2nd character from each line
    cut -c3- test.txt # extracts from 3rd character to end of each line
    cut -c-8 test.txt #  extracts 8 characters from the beginning of each line
    cut -c- test.txt #  entire line would get printed
    cut -d':' -f1 /etc/passwd   # first field of each lines; using the field delimiter :
    grep "/bin/bash" /etc/passwd | cut -d':' -f1,6      # selecting field 1 and 6
    grep "/bin/bash" /etc/passwd | cut -d':' -f1-4,6,7  # selecting field 1 through 4, 6 and 7
    --output-delimiter='#'  change the output delimiter use the option –output-delimiter
    cut -d ' ' -f3-   # print third field to the rest of line

  $ uniq - report or omit repeated lines
    -c, --count
                prefix lines by the number of occurrences
    -d, --repeated
                only print duplicate lines
    -f, --skip-fields=N
                avoid comparing the first N fields
    -u, --unique
                only print unique lines

    'uniq' does not detect repeated lines unless they are adjacent.
    You may want to sort the input first, or use 'sort -u' without 'uniq'.

  $ sort - sort lines of text files
    -g, --general-numeric-sort
                compare according to general numerical value
    -n, --numeric-sort
                compare according to string numerical value
    -h, --human-numeric-sort
                compare human readable numbers (e.g., 2K 1G)
    -r, --reverse
                reverse the result of comparisons
    -u, --unique
                output only the first of an equal run

    General numeric sort compares the numbers as floats,
    this allows scientific notation eg 1.234E10 but is slower and
    subject to rounding error, numeric sort is a regular sort that
    knows 10 comes after 9.


  $ awk - pattern scanning and text processing language

    Records  are  read  in  one  at a time, and stored in the field variable $0.
    The record is split into fields which are stored in $1, $2, ..., $NF.
    The built-in variable NF is set to the number of fields.
    Regular expressions are enclosed in slashes.


    awk -F':' '{print $3,$4;}' /etc/passwd
    awk -F 'FS' 'commands' inputfilename

  # move find results to a directory
  find . -iname \*abc.conf -print0 |xargs -0 -I '{}' mv '{}' destdirectory
  # find and substitute
  find . -iname \*conf -print0    |xargs -0 sed 's:type1-temp:type3-temp:' -i.bak

  # resize image
  for file in *.JPG; do convert -resize 50%  $file r-$file; done

---
  # smart programming

  MYSQLDUMP="`which mysqldump`"
  DATEBIN="`which date`"
  DUMPDIR="${MAINDIR}/`${DATEBIN} +%Y%m%d%H%M`"
  CONFTABLES=( actions applications autoreg_host conditions config dchecks dhosts \
  drules dservices escalations expressions functions globalmacro graph_theme )
  for table in ${CONFTABLES[*]}; do
        DUMPFILE="${DUMPDIR}/${table}.sql"
        echo "Backuping table ${table}"
  done

---
  bash test
  What are top 10 most downloaded packages?
  reading rpackage log files
    gunzip 2012-10-06.csv.gz

  get package name, 7th field
    awk -F',' '{print $7}' 2012-10-06.csv > inp1.txt

  remove " from the names
    cut -d'"' -f2 inp1.txt > inp2.txt

  sort the package names, every similar name become adjacent
    sort inp2.txt > inp3.txt

  count number of occurrences
    uniq -c inp3.txt > inp4.txt

  sort the package names
    sort -n -r inp4.txt > inp5.txt

  list top 12 packages
    head -n 12 inp5.txt

  gunzip 2012-10-06.csv.gz  > awk -F',' '{print $7}'


  http://rtoodtoo.net/meanings-of-access-modify-change-in-stat-comman/

  chattr -i /etc/resolv.conf
  chattr - change file attributes on a Linux second extended file system
  setfacl - set file access control lists

  sticky bit is a user ownership access right flag that can be assigned to files and directories on Unix-like systems. When a directory's sticky bit is set, the filesystem treats the files in such directories in a special way so only the file's owner, the directory's owner, or root user can rename or delete the file. Without the sticky bit set, any user with write and execute permissions for the directory can rename or delete contained files, regardless of the file's owner. Typically this is set on the /tmp directory to prevent ordinary users from deleting or moving other users' files.

  HERE: variables are not expanded/replaced.
  please="Please may I"
  thanks="thank you"
  cat << \EOF
  $please have some cookies? '\$thanks'
  EOF

  prints out: $please have some cookies? '\$thanks'


     An executable command has file permissions with the set user ID bit
  turned on, and the file is owned by root.  While it is executing, it sets
  the real user ID to the effective user ID.  The command then needs to
  execute a separate command.
  For security sake, what would be the best function to use? system
  B	fork
  C	execvp
  D	popen
  E	execl





  A Prompt the user and call sleep(30).  After the sleep, do a read and check the input.
  B	Prompt the user, then call the read system call while passing it the 30 second timeout value.
  C	Trap the SIGALRM signal.  Call alarm(30), prompt the user and call read.  If the alarm goes off, assign the default.
  D	Call the getinput libc function, passing the prompt string and the timeout value.
  E	Use the ioctl system call to set O_TIMEOUT on the tty device, then display the prompt and call read.
---
[mysql]
  A MySQL MyISAM table is the combination of three files:

  The FRM file is the table definition.
  The MYD file is where the actual data is stored.
  The MYI file is where the indexes created on the table are stored.
  You should be able to restore by copying them in your database folder
  (In linux, the default location is /var/lib/mysql/)
  You should do it while the server is not running.
  this is true only for MyISAM tables. InnoDB stores its tables and indexes in a single tablespace *, which by default consist of the 3 files ibdata1, ib_logfile0, and ib_logfile1.



---
TODO:
  interview preparation
  http://www.gnu.org/software/coreutils/faq/coreutils-faq.html
  http://www.tutorialspoint.com/awk/awk_basic_examples.htm
  http://www.thegeekstuff.com/2010/01/8-powerful-awk-built-in-variables-fs-ofs-rs-ors-nr-nf-filename-fnr/
  http://www.cyberciti.biz/faq/how-to-redirect-output-and-errors-to-devnull/
  http://www.linuxjournal.com/content/hacking-safe-bash
  https://github.com/windowsrefund/safe
  https://github.com/windowsrefund/safe/blob/master/safe.sh
  http://www.linuxjournal.com/content/puppet-and-nagios-roadmap-advanced-configuration
  https://github.com/pdellaert/dhcp_server

  http://www.thegeekstuff.com/2011/04/ps-command-examples/

  general
  http://www.thegeekstuff.com/best-of-the-blog/
