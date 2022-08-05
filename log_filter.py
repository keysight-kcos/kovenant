#!/usr/bin/python3

import sys, json

def get_pod_info(pod_dict):
	ret = {}
	ret["name"] = pod_dict["name"]
	ret["namespace"] = pod_dict["namespace"]
	return ret

def get_sock_info(args):
	sock = args[0]["sock_arg"]
	print(sock)
	ret = {}
	saddr, daddr, sport, dport = sock["saddr"], sock["daddr"], sock["sport"], sock["dport"]
	ret["saddr"] = saddr
	ret["daddr"] = daddr
	ret["sport"] = sport
	ret["dport"] = dport
	ret["src"] = saddr+str(sport)
	ret["dest"] = daddr+str(dport)
	# add src_pod and dest_pod mappings here
	return ret

def main(): 
	for line in sys.stdin:
		log_obj = json.loads(line)
		if "process_kprobe" in log_obj:
			time = log_obj["time"]
			log_obj = log_obj["process_kprobe"]
			fn_name = log_obj["function_name"]
			new_log_obj = {}
			new_log_obj[fn_name] = {
				"pod": get_pod_info(log_obj["process"]["pod"]),
				"sock": get_sock_info(log_obj["args"]),
				"time": time,
			}
			print(new_log_obj)
		else:
			print("DEBUG: not a kprobe obj")
			continue

main()
