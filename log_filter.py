#!/usr/bin/python3

import sys, json, os, time

IPS_TO_PODS_PATH = "/usr/bin/ips_to_pods.sh"
GET_HELM_PATH = "./get_helm.sh"
UPDATE_INTERVAL = 30
ip_map = {}
helm_map = {}
pod_to_chart = {}

def set_helm_map():
	global helm_map
	stream = os.popen(GET_HELM_PATH)
	lines = stream.readlines()
	for line in lines:
		name, chart = line.split()
		helm_map[name] = chart
	#print(json.dumps(helm_map))

def deployments_to_charts():
	cmd = r"""kubectl get deployments -A -l='app.kubernetes.io/managed-by=Helm' -o=jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels}{"\t"}{.metadata.annotations}{"\n"}{end}'"""
	stream = os.popen(cmd)
	lines = [line.strip() for line in stream.readlines()]

	dep_to_chart = {}
	for line in lines:
		found = False

		name, temp1, temp2 = line.split()
		labels, annotations = json.loads(temp1), json.loads(temp2)
		for v in labels.values():
			if v in helm_map:
				dep_to_chart[name] = helm_map[v]
				found = True
				break
		if found: 
			continue
		for v in annotations.values():
			if v in helm_map:
				dep_to_chart[name] = helm_map[v]
				break

	print(json.dumps(dep_to_chart))

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

	print(json.dumps(obj_to_chart))

def stub():
	set_helm_map()
	#deployments_to_charts()
	objects_to_charts()

def check_update_ip_map():
	if time.time() - ip_map["fetched_at"] >= UPDATE_INTERVAL:
		set_pod_ip_map()

def set_pod_ip_map():
	new_ip_map = {}
	stream = os.popen(IPS_TO_PODS_PATH)
	lines = stream.readlines()
	control_plane_ip = lines[0].strip()
	new_ip_map[control_plane_ip] = "control-plane"

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

def get_pod_info(pod_dict):
	ret = {}
	ret["name"] = pod_dict["name"]
	ret["namespace"] = pod_dict["namespace"]
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

	return ret

def main(): 
	set_pod_ip_map()
	for line in sys.stdin:
		log_obj = json.loads(line)
		if "process_kprobe" in log_obj:
			time = log_obj["time"]
			log_obj = log_obj["process_kprobe"]
			fn_name = log_obj["function_name"]
			new_log_obj = {}
			if fn_name == "tcp_connect" or fn_name == "tcp_close":
				new_log_obj = {
					"function": fn_name,
					"pod": get_pod_info(log_obj["process"]["pod"]),
					"sock": get_sock_info(log_obj["args"]),
				}
				new_log_obj["time"] = time
			elif fn_name == "tcp_sendmsg" or fn_name == "tcp_recvmsg":
				new_log_obj = {
					"function": fn_name,
					"pod": get_pod_info(log_obj["process"]["pod"]),
					"sock": get_sock_info(log_obj["args"]),
					"length": int(log_obj["args"][1]["size_arg"]),
				}
				new_log_obj["time"] = time
			elif fn_name == "__x64_sys_read" or fn_name == "__x64_sys_write":
				new_log_obj = {
					"function": fn_name,
					"pod": get_pod_info(log_obj["process"]["pod"]),
					"length": int(log_obj["args"][0]["size_arg"]),
				}
				new_log_obj["time"] = time
			else:
				continue
			print(json.dumps(new_log_obj))

stub()
