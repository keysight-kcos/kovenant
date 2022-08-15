FROM telegraf:1.19
#RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
COPY ./kubectl /kubectl
RUN install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

RUN usermod -g 0 telegraf

RUN apt-get update && apt-get install -y --no-install-recommends python3
RUN wget https://get.helm.sh/helm-v3.9.2-linux-amd64.tar.gz && tar -zxvf helm*.gz && install -o root -g root -m 0755 linux-amd64/helm /usr/bin/helm && rm -rf *linux-amd64*
COPY ./config /.kube/config
COPY ./helm /root/.config/helm
COPY ./ips_to_pods.sh /usr/bin/ips_to_pods.sh

COPY ./get_helm.sh /usr/bin/get_helm.sh
COPY ./log_filter.py /usr/bin/log_filter.py
#RUN setcap cap_setuid+ep /usr/bin/python3.9

COPY ./filtered_tetragon_logs.sh /usr/bin/filtered_tetragon_logs.sh

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY ./telegraf.conf /etc/telegraf/telegraf.conf
