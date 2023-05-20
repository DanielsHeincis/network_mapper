from scapy.all import *
import argparse
import sys
from datetime import datetime, timezone
import json
from ipaddress import IPv4Network, IPv4Address, ip_network
import sys


NETWORK_SIZE = ""
interface_list = get_if_list()
ID_counter = 100
network_ID_counter = 0

# where save results
scan_results = {}


def basic_info():
    router_IP = conf.route.route("0.0.0.0")[2]
    interface_IP = get_if_addr(conf.iface)
    interface_MAC = get_if_hwaddr(conf.iface)
    router_MAC = getmacbyip(router_IP)
    return {"ROUTER_IP": router_IP, "ROUTER_MAC": router_MAC, "INTERFACE_IP": interface_IP, "INTERFACE_MAC": interface_MAC, "INTERFACE_LIST": interface_list}


# initial_vlue_seting
# save programm start time
start_time = datetime.now().astimezone(timezone.utc)
scan_results["BASIC_INFO"] = basic_info()
scan_results["FOUND_ENTITIES"] = {}
scan_results["FOUND_ENTITIES"]["NETWORKS"] = []
scan_results["FOUND_ENTITIES"]["NETWORKS"].append(
    {"NETWORK_ID": network_ID_counter, "ENTITIES": []})
scan_results["FOUND_ENTITIES"]["NETWORKS"][0]["ENTITIES"].append(
    {"ROUTER": {"ID": ID_counter, "ROUTER_IP": scan_results["BASIC_INFO"]["ROUTER_IP"], "ROUTER_MAC": scan_results["BASIC_INFO"]["ROUTER_MAC"]}})
ID_counter += 1
# print(scan_results)

# parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("timeout", type=int, default=10,
                    help="how long to run scan in seconds, for infinetly pass 0")
parser.add_argument("mode", type=str, default="sniff",
                    help="'sniff' for network sniffing, 'arp' for sniff and arp scan, 'ping' for ping scan, 'traceroute' for treacroute scan, 'ip_sniff' to try to sniff trafic that are for specific IP address, 'mac_sniff' to try to sniff trafic that are for specific MAC address")
parser.add_argument("-O", "--directory", type=str, default="./",
                    help="output directory")
parser.add_argument("-o", "--output", type=str, default="network_scan_{}.json".format(start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z").replace(" ", "")),
                    help="filename for output file. Default output file will be in the same directory as this script with file name 'network_scan' and curent timestamp")
parser.add_argument("-s", "--size", type=int, default=24,
                    help="define network mask")
parser.add_argument("-v", "--verbose", default=False, action="store_true",
                    help="use to see detailed output in terminal")
parser.add_argument("-n", "--not-save", default=False, action="store_true",
                    help="use if don't want to save results in file")
parser.add_argument("-a", "--all-interfaces", default=False, action="store_true",
                    help="use if want to scan from all interfaces (don't work if used infinetly long scaning)")
args = parser.parse_args()

# check for invalid input
if args.timeout < 0:
    print("Run time should be positive integer")
    sys.exit(1)


def interface_choice():
    print("List of available interfaces:")
    for i in range(len(interface_list)):
        print(i, ". interface name:", interface_list[i], "\n")
    print("Write number of interface you want to use in scan:")
    interfaces_number = input('> ')
    try:
        interfaces_number = int(interfaces_number)
    except ValueError:
        print("Interface number must be integer!")
        sys.exit(1)
    if interfaces_number in range(len(interface_list)):
        print("You chosed interface", interface_list[interfaces_number])
        return interface_list[interfaces_number]
    else:
        print("You choosed interface number out of range.")
        sys.exit(1)


def scan_summary():
    end_time = datetime.now().astimezone(timezone.utc)
    run_time = end_time - start_time
    return {"SCAN_STARTED": start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "SCAN_ENDED": end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "RUN_TIME": str(run_time)}

# Function to  save results


def save_results(results):
    CHECK_FOLDER = os.path.isdir(args.directory)
    # If folder doesn't exist, then create it.
    if not CHECK_FOLDER:
        os.makedirs(args.directory)
    file_path = os.path.join(args.directory, args.output)
    print("Saving file as {}".format(file_path))
    try:
        with open('{}'.format(file_path), 'w') as outfile:
            json.dump(results, outfile)
    except:
        print("Failed to save results! Trying again.")
        traceback.print_exc(file=sys.stderr)
        #sys.exit(1)
    try:
        with open(r'{}'.format(args.output), 'w') as outfile:
            json.dump(results, outfile)
    except:
        print("Failed to save results!")
        print("Printing results")
        print(results)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


def result_structure_parser(data_list, scan_type, interface):
    global scan_results
    global ID_counter
    global network_ID_counter
    try:
        for i in range(len(scan_results["FOUND_ENTITIES"]["NETWORKS"])):
            #print (scan_results["FOUND_ENTITIES"]["NETWORKS"][i])
            network_id_check = scan_results["FOUND_ENTITIES"]["NETWORKS"][i].get(
                "NETWORK_ID")
            # if network_id_check == network_ID_counter:
            # break
            #print("Found network")
    except:
        network_id_check = None
    if network_id_check == None:
        print("Network ID problem")
        network_ID_counter = 0
    else:
        # this works because first 100 IDs are reserved for network ID
        network_ID_counter = network_id_check + 1
    if (len(data_list)) > 0:
        if scan_type == "arp":
            unique_packets = data_list
        elif scan_type == "ping":
            unique_packets = data_list
        elif scan_type == "traceroute":
            unique_packets = data_list
        else:
            unique_packets = []
            for packet in data_list:
                # print(i)
                try:
                    source_MAC = packet[Ether].src
                except:
                    source_MAC = None
                try:
                    destination_MAC = packet[Ether].dst
                except:
                    destination_MAC = None
                try:
                    source_IP = packet[IP].src
                except:
                    source_IP = None
                # destination IP unused but left for future implementation
                try:
                    destination_IP = packet[IP].dst
                except:
                    destination_IP = None
                packet_data = {"SOURCE_MAC": source_MAC,
                               "IP": source_IP, "CONECTED_MAC": [destination_MAC]}
                if packet_data not in unique_packets:
                    packet_data = {"ID": ID_counter, "MAC": source_MAC, "IP": source_IP, "CONECTED_MAC": [
                        destination_MAC], "INTERFACE": interface}
                    unique_packets.append(packet_data)
                    ID_counter += 1
        for unique_packet in unique_packets:
            key = 'MAC'
            value = unique_packet.get("MAC")
            source_dont_exist = True
            destination_dont_exist = True
            for network in scan_results["FOUND_ENTITIES"]["NETWORKS"]:
                for element in network["ENTITIES"]:
                    # print(element)
                    # check if entity alredy exists
                    if (key, value) in element.items():
                        source_dont_exist = False
                        # if exists check if destination MAC is in connceted MAC list, if not then append
                        if unique_packet["CONECTED_MAC"][0] not in element["CONECTED_MAC"]:
                            element["CONECTED_MAC"].append(
                                unique_packet["CONECTED_MAC"][0])
                    # also check if destination MAC element exist
                    if (key, unique_packet["CONECTED_MAC"][0]) in element.items():
                        destination_dont_exist = False
                        # if exists check if source MAC is in connected MAC list, if not then append
                        if unique_packet["MAC"] not in element["CONECTED_MAC"]:
                            element["CONECTED_MAC"].append(
                                unique_packet["MAC"])
            # if dont exist then create
            if source_dont_exist:
                # network_ID_counter -1 because it is current network ID
                scan_results["FOUND_ENTITIES"]["NETWORKS"][network_ID_counter -
                                                           1]["ENTITIES"].append(unique_packet)
            if destination_dont_exist:
                # if dont exist then create
                # as destination_IP is not saved in unique_packet variable we cant assign  SOURCE_IP
                destination_element = {"ID": ID_counter, "MAC": unique_packet["CONECTED_MAC"][0], "IP": None, "CONECTED_MAC": [
                    unique_packet["MAC"]], "INTERFACE": interface}
                ID_counter += 1

    else:
        print("Didn't capture any packets.")


# function to print results for snifing
def result_print(packet_variable, packet_after_exception_variable):
    if packet_after_exception_variable == None:
        packet_count_after_exception = 0
    else:
        packet_count_after_exception = len(packet_after_exception_variable)
    packet_count = len(packet_variable)
    if packet_count_after_exception > 0:
        print("Snifed", packet_count, "packets. After exception ocured sniffed",
              packet_count_after_exception, "packets.")
    else:
        print("Snifed", packet_count, "packets.")
    try:
        return packet_variable.summary(), packet_after_exception_variable.summary()
    except:
        return packet_variable.summary()


def sniff_all(interface_choice):
    #global result_structure_parser
    # for infinetly long scan
    if args.timeout == 0:
        print("Sniffing in process till manualy stoped.")
        try:
            packets = sniff(iface=interface_choice,
                            prn=lambda x: print(x[IP].src, x[IP].dst))

        except IndexError:
            print("Failed to read IP layer, switching to Ether layer printing")
            packets_after_exception = sniff(
                iface=interface_choice, prn=lambda x: print(x[Ether].src, x[Ether].dst))
    # for scan with timeout
    else:
        # check if scan on all interfaces
        if args.all_interfaces:
            print("Sniffing for all interfaces enabled")
            for i in interface_list:
                print("Now snifing for", args.timeout,
                      "seconds. Using interface ", i)
                packets = sniff(iface=i, timeout=args.timeout)
                result_structure_parser(packets, "snif_all_all_interfaces", i)
        else:
            print("Now snifing for", args.timeout,
                  "seconds. Using interface", interface_choice)
            packets = sniff(iface=interface_choice, timeout=args.timeout)
            result_structure_parser(
                packets, "snif_all_one_interface", interface_choice)

    if args.verbose:
        try:
            result_print(packets, packets_after_exception)
        except:
            result_print(packets, None)



def IP_network_from_ip(IP_variable, mask_size):
    IP_three_octets = IP_variable.split('.')[:-1]
    IP_range = '.'.join(IP_three_octets) + ".0/" + str(mask_size)
    return IP_range


def arp_scan(interface):
    global ID_counter
    results_arp = []
    IP_network = IP_network_from_ip(scan_results["BASIC_INFO"]["ROUTER_IP"])
    print("Do you want to try ARP spoofing (send requests from router IP)? It might affect network processes! Accepted answers y/n:")
    spoof_choice = input('> ')
    if str(spoof_choice) == "y":
        print("Now conducting ARP scan with spoofing. Using interface ", interface)
        arp_request = ARP(
            pdst=IP_network, psrc=scan_results["BASIC_INFO"]["ROUTER_IP"])
    elif str(spoof_choice) == "n":
        print("Now conducting ARP scan. Using interface", interface)
        arp_request = ARP(pdst=IP_network)
    else:
        print("Recived invalid choice. Exiting.")
        sys.exit(1)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered, unanswered = srp(
        arp_request_broadcast, timeout=4, iface=interface,)
    for i in range(0, len(answered)):
        # conected MAC check possibly needed
        entity = {"ID": ID_counter, "MAC": answered[i][1].hwsrc, "IP": answered[i][1].psrc, "CONECTED_MAC": [
            scan_results["BASIC_INFO"]["INTERFACE_MAC"]], "INTERFACE": interface}
        results_arp.append(entity)
        ID_counter += 1
    result_structure_parser(results_arp, "arp", interface)


def ping_scan(interface):
    global ID_counter
    results_ping = []
    print("Choose network mask (default value is 24)")
    mask_choice = input('> ')
    try:
        addresses = IPv4Network(IP_network_from_ip(scan_results["BASIC_INFO"]["ROUTER_IP"], mask_choice))
    except:
        ddresses = IPv4Network(IP_network_from_ip(scan_results["BASIC_INFO"]["ROUTER_IP"], "24"))
    print("Now conducting ping scan for IP addreses " +
          str(addresses) + ". Using interface " + interface)
    for host in addresses:
        if (host in (addresses.network_address, addresses.broadcast_address)):
            # Skip network and broadcast addresses
            continue
        resp = sr1(IP(dst=str(host))/ICMP(),
                   timeout=args.timeout, verbose=False)

        if resp is None:
            print(f"{host} is down or not responding.")
        elif (int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print(f"{host} is blocking ICMP.")
        else:
            print(f"{host} is responding.")
            ip_answered = str(IPv4Address(host))
            mac = getmacbyip(ip_answered)
            entity = {"ID": ID_counter, "MAC": mac, "IP": ip_answered, "CONECTED_MAC": [
                scan_results["BASIC_INFO"]["INTERFACE_MAC"]], "INTERFACE": interface}
            results_ping.append(entity)
            ID_counter += 1
    result_structure_parser(results_ping, "ping", interface)


def arp_sniff(interface):
    print("Now conducting ARP packet sniffing for", args.timeout, "seconds. Using interface", interface)
    ARP_output = []
    packets = sniff(filter="arp", timeout=args.timeout)
    print("Snifed",len(packets),"ARP packets.")
    return result_structure_parser(packets, "sniff_arp", interface)


def traceroute_udp(ip_network_variable, interface):
    global ID_counter
    print("Now conducting traceroute for IP addreses " +
          str(ip_network_variable) + ". Using interface " + interface)
    address_list = list(ip_network(ip_network_variable).hosts())
    results_traceroute = []
    for address in address_list:
        address = str(IPv4Address(address))
        for i in range(1, 10):
            pkt = IP(dst=address, ttl=i) / UDP(dport=33434)
            reply = sr1(pkt, verbose=1, timeout=5)
            if reply is None:
                print("Did not recive answer.")
            elif reply.type == 3:
                print ("Done!", reply.src)
                ip_answered = reply.src
                mac = getmacbyip(ip_answered)
                if mac == None:
                    break
                connected_mac = getmacbyip(address)
                entity = {"ID": ID_counter, "MAC": mac, "IP": ip_answered, "CONECTED_MAC": [
                    connected_mac], "INTERFACE": interface}
                results_traceroute.append(entity)
                ID_counter += 1
                break
            else:
                print (f"{i} hops away: ", reply.src)
                ip_answered = reply.src
                mac = getmacbyip(ip_answered)
                if mac == None:
                    break
                connected_mac = getmacbyip(address)
                entity = {"ID": ID_counter, "MAC": mac, "IP": ip_answered, "CONECTED_MAC": [
                    connected_mac], "INTERFACE": interface}
                results_traceroute.append(entity)
                ID_counter += 1
    result_structure_parser(results_traceroute, "traceroute", interface)


def IP_destination_sniff(interface):
    print("Choose destination IP address wich trafic to sniff")
    IP_choice = input('> ')
    try:
        IPv4Address(IP_choice)
    except:
        print("Entered invalid IPv4 address. Exiting.")
        sys.exit(1)
    
    if args.timeout == 0:
        try:
            packets = sniff(iface=interface, lfilter=lambda x:x[IP].dst == IP_choice, prn=lambda x:print(x[IP].src))
        except IndexError:
            print("Failed to read IP layer, switching to Ether layer printing")
            packets_after_exception = sniff(iface=interface, lfilter=lambda x:x[IP].dst == destination_IP_address, prn=lambda x:print(x[Ether].src))
    else:
        try:
            packets = sniff(iface=interface, timeout=args.timeout, lfilter=lambda x:x[IP].dst == destination_IP_address)
        except:
            print("Failed to sniff with filtering by destination IP!")
            traceback.print_exc(file=sys.stderr)
    try:
        result_structure_parser(packets, "ip_sniff", interface)
        result_structure_parser(packets_after_exception, "ip_sniff", interface)
        result_print(packets, packets_after_exception)
    except:
        result_structure_parser(packets, "ip_sniff", interface)
        packets_after_exception = ""
        result_print(packets, packets_after_exception)

def MAC_destination_sniff(interface):
    print("Choose destination MAC address wich trafic to sniff")
    TARGET_MAC = input('> ')
    try:
        if args.timeout == 0:
            try:
                packets = sniff(iface=interface, lfilter=lambda x:x[Ether].dst == str(TARGET_MAC), prn=lambda x:print(x))
            except IndexError:
                print("Failed to read Ether layer, switching to IP layer printing")
                packets_after_exception = sniff(iface=interface, lfilter=lambda x:x[Ether].dst == str(TARGET_MAC), prn=lambda x:print(x[IP].src))
        else:
            try:
                packets = sniff(iface=interface, timeout=args.timeout, lfilter=lambda x:x[Ether].dst == str(TARGET_MAC))
            except:
                print("Failed to sniff with filtering by destination MAC!")
                traceback.print_exc(file=sys.stderr)
        try:
            result_structure_parser(packets, "mac_sniff", interface)
            result_structure_parser(packets_after_exception, "mac_sniff", interface)
            result_print(packets, packets_after_exception)
        except:
            result_structure_parser(packets, "ip_sniff", interface)
            packets_after_exception = ""
            result_print(packets, packets_after_exception)
    except:
        print("Failed to sniff by destination MAC. Exiting.")
        sys.exit(1)



if not args.all_interfaces:
    user_interface = interface_choice()
if args.mode == "sniff":
    if args.all_interfaces:
        sniff_all(None)
    else:
        sniff_all(user_interface)
if args.mode == "arp_sniff":
    arp_sniff(user_interface)
if args.mode == "arp":
    if args.all_interfaces:
        sniff_all(None)
    else:
        sniff_all(user_interface)
    arp_scan(user_interface)
if args.mode == "ping":
    ping_scan(user_interface)
if args.mode == "traceroute":
    traceroute_udp(IP_network_from_ip(scan_results["BASIC_INFO"]["ROUTER_IP"], "24"), user_interface)
if args.mode == "ip_sniff":
    IP_destination_sniff(interface)
if args.mode == "mac_sniff":
    MAC_destination_sniff(interface)


if args.verbose:
    print(scan_results)
scan_results["SCAN_INFO"] = scan_summary()

if not args.not_save:
    save_results(scan_results)