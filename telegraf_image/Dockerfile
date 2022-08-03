FROM telegraf:1.19
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
RUN usermod -g 0 telegraf
COPY ./config /.kube/config
COPY ./pod_ip_mapping /usr/bin/pod_ip_mapping
COPY ./ips_to_pods.sh /usr/bin/ips_to_pods.sh
