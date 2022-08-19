#!/usr/bin/python3

import sys, json, os, time

IPS_TO_PODS_PATH = "/usr/bin/ips_to_pods.sh"
GET_HELM_PATH = "/usr/bin/get_helm.sh"
GET_CLUSTER_DNS_PATH = "/usr/bin/get_cluster_dns.sh"
UPDATE_INTERVAL = 30
ip_map = {}
helm_map = {}
pod_to_chart = {}

# strip checksum from the end of a k8s object name
def strip_suffix(name):
	split = name.split("-")
	if len(split) > 1:
		return "-".join(split[:-1])
	return name

def set_helm_map():
	global helm_map
	stream = os.popen(GET_HELM_PATH)
	lines = stream.readlines()
	for line in lines:
		name, chart = line.split()
		helm_map[name] = chart
	#print(json.dumps(helm_map))

def objects_to_charts():
	cmd = r"""kubectl get all -A -l='app.kubernetes.io/managed-by=Helm' -o=jsonpath='{range .items[*]}{.kind}{")*("}{.metadata.name}{")*("}{.metadata.labels}{")*("}{.metadata.annotations}{"\n"}{end}'"""
	stream = os.popen(cmd)
	lines = [line.strip() for line in stream.readlines()]

	obj_to_chart = {}
	for line in lines:
		found = False

		split = [item if len(item) != 0 else r"""{"none": "N0N3"}""" for item in line.split(")*(")]
		if len(split) != 4:
			print("\nUnexpected fetch:", split, end="\n\n")
			continue

		kind, name, temp1, temp2 = split
		if kind == "Pod":
			labels, annotations = json.loads(temp1), json.loads(temp2)
			for v in labels.values():
				if v in helm_map:
					pod_to_chart[name] = helm_map[v]
					found = True
					break
			if found: 
				continue
			for v in annotations.values():
				if v in helm_map:
					pod_to_chart[name] = helm_map[v]
					break
		else:
			labels, annotations = json.loads(temp1), json.loads(temp2)
			for v in labels.values():
				if v in helm_map:
					obj_to_chart[name] = {'kind': kind, 'chart': helm_map[v]}
					found = True
					break
			if found: 
				continue
			for v in annotations.values():
				if v in helm_map:
					obj_to_chart[name] = {'kind': kind, 'chart': helm_map[v]}
					break
	#print(json.dumps(obj_to_chart))
	return obj_to_chart

# services and pods are both checked in the 
# 'pod' mappings
def services_to_charts():
	global pod_to_chart
	cmd = r"""kubectl get services -A -o=jsonpath='{range .items[*]}{.metadata.name}{")*("}{.metadata.labels}{")*("}{.metadata.annotations}{"\n"}{end}'"""
	stream = os.popen(cmd)
	lines = [line.strip() for line in stream.readlines()]

	for line in lines:
		found = False

		split = [item if len(item) != 0 else r"""{"none": "N0N3"}""" for item in line.split(")*(")]
		if len(split) != 3:
			print("\nUnexpected fetch:", split, end="\n\n")
			continue

		name, temp1, temp2 = split
		labels, annotations = json.loads(temp1), json.loads(temp2)
		for v in labels.values():
			if v in helm_map:
				pod_to_chart[name] = helm_map[v]
				found = True
				break
		if found: 
			continue
		for v in annotations.values():
			if v in helm_map:
				pod_to_chart[name] = helm_map[v]
				break

def pods_to_charts():
	global pod_to_chart
	obj_to_chart = objects_to_charts()
	services_to_charts()

	cmd = r"""kubectl get pods -A -o=jsonpath='{range .items[*]}{.metadata.name}{")*("}{.metadata.ownerReferences[0].name}{"\n"}{end}'"""
	stream = os.popen(cmd)
	lines = [line.strip() for line in stream.readlines()]
	for line in lines:
		found = False

		split = [item if len(item) != 0 else "N0N3" for item in line.split(")*(")]
		if len(split) != 2:
			print("\nUnexpected fetch:", split, end="\n\n")
			continue

		name, parent_obj = split
		stripped_parent_obj = strip_suffix(parent_obj)
		if parent_obj in obj_to_chart:
			pod_to_chart[name] = obj_to_chart[parent_obj]["chart"]
		elif stripped_parent_obj in obj_to_chart:
			pod_to_chart[name] = obj_to_chart[stripped_parent_obj]["chart"]


def stub():
	'''
	print(strip_suffix("keycloak-operator-5bc7649f79"))
	print(strip_suffix("coredns-55995c9468"))
	print(strip_suffix("keycloak"))
	return 
	'''
	set_helm_map()
	#pods_to_charts()
	print(json.dumps(objects_to_charts()))
	#print(json.dumps(pod_to_chart))

def check_update_ip_map():
	if time.time() - ip_map["fetched_at"] >= UPDATE_INTERVAL:
		set_pod_ip_map()

def set_pod_ip_map():
	new_ip_map = {}
	stream = os.popen(IPS_TO_PODS_PATH)
	lines = stream.readlines()
	control_plane_ip = lines[0].strip()
	new_ip_map[control_plane_ip] = "control-plane"

	stream = os.popen(GET_CLUSTER_DNS_PATH)
	cluster_dns_ip = stream.read().strip()
	new_ip_map[cluster_dns_ip] = "Cluster-DNS"

	for i in range(1, len(lines)):
		name, ip = lines[i].split()
		if ip == control_plane_ip:
			continue
		new_ip_map[ip] = name
	new_ip_map["fetched_at"] = time.time()

	global ip_map 
	ip_map = new_ip_map

def ip_to_pod_name(ip):
	if ip in ip_map:
		return ip_map[ip]
	return "none"

def pod_name_to_chart(pod_name):
	if pod_name in pod_to_chart:	
		return pod_to_chart[pod_name]
	return "none"

def get_pod_info(pod_dict):
	ret = {}
	ret["name"] = pod_dict["name"]
	ret["namespace"] = pod_dict["namespace"]
	ret["chart"] = pod_name_to_chart(ret["name"])
	return ret

def get_sock_info(args):
	sock = args[0]["sock_arg"]
	ret = {}
	saddr, daddr = sock.get("saddr", "none"), sock.get("daddr", "none")
	sport, dport = sock.get("sport", "none"), sock.get("dport", "none")

	ret["saddr"] = saddr
	ret["daddr"] = daddr
	ret["sport"] = sport
	ret["dport"] = dport
	ret["src"] = saddr+":"+str(sport)
	ret["dest"] = daddr+":"+str(dport)
	check_update_ip_map()
	ret["src_object"] = ip_to_pod_name(saddr)
	ret["dest_object"] = ip_to_pod_name(daddr)
	ret["src_chart"] = pod_name_to_chart(ret["src_object"])
	ret["dest_chart"] = pod_name_to_chart(ret["dest_object"])

	return ret

def get_skb_info(args):
	skb = args[0]["skb_arg"]
	ret = {}
	saddr, daddr = skb.get("saddr", "none"), skb.get("daddr", "none")
	sport, dport = skb.get("sport", "none"), skb.get("dport", "none")

	ret["saddr"] = saddr
	ret["daddr"] = daddr
	ret["sport"] = sport
	ret["dport"] = dport
	ret["src"] = saddr+":"+str(sport)
	ret["dest"] = daddr+":"+str(dport)
	check_update_ip_map()
	ret["src_object"] = ip_to_pod_name(saddr)
	ret["dest_object"] = ip_to_pod_name(daddr)
	ret["src_chart"] = pod_name_to_chart(ret["src_object"])
	ret["dest_chart"] = pod_name_to_chart(ret["dest_object"])

	return ret

def in_aggregate_window(start_of_window):
	window_length = 5
	return time.time() - start_of_window < window_length

def contains_cluster_dns_ip(cluster_dns_ip, new_log_obj):
	if "sock" in new_log_obj:
		return new_log_obj["sock"]["saddr"] == cluster_dns_ip or new_log_obj["sock"]["daddr"] == cluster_dns_ip
	return new_log_obj["skb"]["saddr"] == cluster_dns_ip or new_log_obj["skb"]["daddr"] == cluster_dns_ip

def getSockLogSignature(log_obj):
	return log_obj["sock"]["src"] + log_obj["sock"]["dest"] + log_obj["pod"]["namespace"] + log_obj["pod"]["name"]

def getSkbLogSignature(log_obj):
	return log_obj["function"] + log_obj["skb"]["src"] + log_obj["skb"]["dest"] + log_obj["pod"]["namespace"] + log_obj["pod"]["name"]

def getReadWriteLogSignature(log_obj):
	return log_obj["function"]+log_obj["pod"]["namespace"]+log_obj["pod"]["name"]

def aggregate_tcp(agg_map, log, log_time):
	signature = getSockLogSignature(log)
	if signature in agg_map:
		agg_map[signature]["count"] += 1
		agg_map[signature]["length"] += log["length"]
	else:
		log["count"] = 1
		agg_map[signature] = log
	agg_map[signature]["time"] = log_time

def aggregate_read_write(agg_map, log, log_time):
	signature = getReadWriteLogSignature(log)
	if signature in agg_map:
		agg_map[signature]["count"] += 1
		agg_map[signature]["length"] += log["length"]
	else:
		log["count"] = 1
		agg_map[signature] = log
	agg_map[signature]["time"] = log_time

def aggregate_packet(agg_map, log, log_time):
	signature = getSkbLogSignature(log)
	if signature in agg_map:
		agg_map[signature]["count"] += 1
		agg_map[signature]["length"] += log["length"]
	else:
		log["count"] = 1
		agg_map[signature] = log
	agg_map[signature]["time"] = log_time

def main(): 
	#os.seteuid(0)
	set_helm_map()
	#print(helm_map, file=sys.stderr)
	pods_to_charts()
	set_pod_ip_map()

	stream = os.popen(GET_CLUSTER_DNS_PATH)
	cluster_dns_ip = stream.read().strip()

	start_of_window = time.time()

	tcp_sendmsg_agg = {}
	tcp_recvmsg_agg = {}
	read_write_agg = {}
	packet_rx_agg = {}
	for line in sys.stdin:
		log_obj = json.loads(line)
		if "process_kprobe" in log_obj:
			log_time = log_obj["time"]
			log_obj = log_obj["process_kprobe"]
			fn_name = log_obj["function_name"]
			new_log_obj = {}
			if fn_name == "tcp_connect" or fn_name == "tcp_close":
				new_log_obj = {
					"function": fn_name,
					"pod": get_pod_info(log_obj["process"]["pod"]),
					"sock": get_sock_info(log_obj["args"]),
				}
				new_log_obj["time"] = log_time
				print(json.dumps(new_log_obj))
			elif fn_name == "tcp_sendmsg":
				new_log_obj = {
					"function": fn_name,
					"pod": get_pod_info(log_obj["process"]["pod"]),
					"sock": get_sock_info(log_obj["args"]),
					"length": int(log_obj["args"][1]["size_arg"]),
				}

				aggregate_tcp(tcp_sendmsg_agg, new_log_obj, log_time)
			elif fn_name == "tcp_recvmsg":
				new_log_obj = {
					"function": fn_name,
					"pod": get_pod_info(log_obj["process"]["pod"]),
					"sock": get_sock_info(log_obj["args"]),
					"length": int(log_obj["args"][1]["size_arg"]),
				}

				aggregate_tcp(tcp_recvmsg_agg, new_log_obj, log_time)
			elif fn_name == "__x64_sys_read" or fn_name == "__x64_sys_write":
				new_log_obj = {
					"function": fn_name,
					"pod": get_pod_info(log_obj["process"]["pod"]),
					"length": int(log_obj["args"][0]["size_arg"]),
				}
				aggregate_read_write(read_write_agg, new_log_obj, log_time)
			elif fn_name == "netif_receive_skb" or fn_name == "tcp_v4_rcv":
				new_log_obj = {
					"function": fn_name,
					"pod": get_pod_info(log_obj["process"]["pod"]),
					"skb": get_skb_info(log_obj["args"]),
					"length": int(log_obj["args"][0]["skb_arg"]["len"]),
				}

				aggregate_packet(packet_rx_agg, new_log_obj, log_time)

			if not in_aggregate_window(start_of_window):
				start_of_window = time.time()
				for _, obj in tcp_sendmsg_agg.items():
					print(json.dumps(obj))
				tcp_sendmsg_agg = {}
				for _, obj in tcp_recvmsg_agg.items():
					print(json.dumps(obj))
				tcp_recvmsg_agg = {}
				for _, obj in read_write_agg.items():
					print(json.dumps(obj))
				read_write_agg = {}
				for _, obj in packet_rx_agg.items():
					print(json.dumps(obj))
				packet_rx_agg = {}

main()
