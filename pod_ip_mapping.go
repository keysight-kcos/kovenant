// tetragon json logs -> map pod ips to pod names

/*
	{
		"pod_mapping": {
			"ip": <ip>,
			"pod_name": <pod_name>
		}
	}
*/
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

const HELPER_PATH = "/usr/bin/ips_to_pods.sh"

type pod_mapping struct {
	Ip       string `json:"ip"`
	Pod_name string `json:"pod_name"`
}

type pod_mapping_wrapper struct {
	Pm pod_mapping `json:"pod_mapping"`
}

func createMap() map[string]string {
	ips_to_pods := make(map[string]string)
	cmd := exec.Command(HELPER_PATH)

	stdout, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Scan()
	// Multiple pods share the control-plane id in the kubectl get pods -o wide
	// output. Skipping them for now, but maybe more finetuning is possible.
	control_plane_ip := scanner.Text()
	//fmt.Println("Control plane:", control_plane_ip)

	for scanner.Scan() {
		tup := strings.Split(scanner.Text(), " ")
		if len(tup) != 2 {
			log.Fatal("Malformed row(s) received from 'ip_to_pods.sh'")
		}

		if tup[1] == control_plane_ip {
			continue
		}

		ips_to_pods[tup[1]] = tup[0]
	}

	return ips_to_pods
}

func main() {
	ips_to_pods := createMap()
	out := make([]pod_mapping_wrapper, 0)
	for ip, pod_name := range ips_to_pods {
		out = append(out, pod_mapping_wrapper{
			Pm: pod_mapping{
				Ip:       ip,
				Pod_name: pod_name,
			},
		})
	}
	jsonMapping, err := json.Marshal(out)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(jsonMapping))
}
