#!/usr/bin/python3

import sys, json, os, time

IPS_TO_PODS_PATH = "/usr/bin/ips_to_pods.sh"
UPDATE_INTERVAL = 30
ip_map = {}

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

def stub():
	print("test")

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

main()
