#!/usr/bin/python3

import os, requests, json
from jinja2 import Environment, FileSystemLoader

GET_NAMESPACES_PATH = "./get_namespaces.sh"
namespaces = []

BASE_URL = "http://localhost/grafana/api/"

def create_api_token():
	url = "http://admin:admin@localhost/grafana/api/auth/keys"
	data = r"""
	{
		"name": "apikey",
		"role": "Admin"
	}
	"""
	res = requests.post(
		url=url,
		data=data,
		headers={
			"Accept": "application/json",
			"Content-Type": "application/json",
		}
	)
	return res.json()

def postDashboard(url, api_key, dashboard_json):
	res = requests.post(
		url=url,
		data=dashboard_json,
		headers={
			"Accept": "application/json",
			"Content-Type": "application/json",
			"Authorization": f"Bearer {api_key}"
		}
	)
	return res.json()

def get_datasources(url, api_key):
	res = requests.get(
		url=url,
		headers={
			"Accept": "application/json",
			"Content-Type": "application/json",
			"Authorization": f"Bearer {api_key}"
		}
	)
	return res.json()

def get_datasource_uid(api_key, datasources, datasource_name):
	for ds in datasources:
		if ds["name"] == datasource_name:
			return ds["uid"]
	return "not found"

def get_namespaces():
	stream = os.popen(GET_NAMESPACES_PATH)	
	out = stream.read()
	global namespaces
	namespaces = [{'namespace': n.strip(), 'selected': 'false'} for n in out.split("\n") if len(n) > 0]
	namespaces[0]['selected'] = 'true'

def main():
	api_token = create_api_token()["key"]
	datasources = get_datasources(BASE_URL+"datasources", api_token)
	print("datasources:", datasources, end="\n\n")
	prometheus_uid = get_datasource_uid(api_token, datasources, "Prometheus")
	influx_uid = get_datasource_uid(api_token, datasources, "InfluxDB")

	file_loader = FileSystemLoader('.')
	env = Environment(loader=file_loader)

	template = env.get_template("template1.json")
	tetragon_dashboard = "{\"dashboard\":"+template.render(
		id=0,
		title="tetragon-"+os.uname()[1],
		datasource_type_1="influxdb",
		datasource_type_2="prometheus",
		influx_uid=influx_uid,
		prometheus_uid=prometheus_uid,
		bucket_name="Tetragon"
	)+"}"
	print(f"Uploading dashboard 1 to Grafana...")
	res = postDashboard(BASE_URL+"dashboards/db", api_token, tetragon_dashboard)
	print(res, end="\n\n")

	template = env.get_template("template2.json")
	cluster_metrics_dashboard = "{\"dashboard\":"+template.render(
		id=1,
		title="cluster-metrics",
		datasource_type="prometheus",
		datasource_uid=prometheus_uid,
	)+"}"
	print(f"Uploading dashboard 2 to Grafana...")
	res = postDashboard(BASE_URL+"dashboards/db", api_token, cluster_metrics_dashboard)
	print(res)

def stub():
	token = create_api_token()["key"]
	print(get_datasource_uid(token))

main()
