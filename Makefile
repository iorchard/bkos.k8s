SHELL := /bin/bash
STACK := bkos.k8s.lakers
ENDPOINT_IP := 192.168.20.50

stack:
	pulumi stack select $(STACK) 2>/dev/null || pulumi stack init $(STACK)

config:
	pulumi stack select $(STACK)
	pulumi config set 'provider_network_name' 'public-net'
	pulumi config set 'cluster_name' 'lakers'
	pulumi config set 'default_zone_name' 'pbos.local'
	pulumi config set 'dns_zone_name' 'lakers.local'

	pulumi config set --path 'flavor_master.vcpus' 4
	pulumi config set --path 'flavor_master.ram' 4
	pulumi config set --path 'flavor_master.disk' 50
	pulumi config set --path 'flavor_node.vcpus' 4
	pulumi config set --path 'flavor_node.ram' 4
	pulumi config set --path 'flavor_node.disk' 50

	pulumi config set --path 'k8s.master_count' 1
	pulumi config set --path 'k8s.node_count' 1
	pulumi config set --path 'k8s.discovery_url' \
		'http://registry.pbos.local:8087'
	pulumi config set --path 'k8s.subnet_cidr' '10.100.200.0/24'

	pulumi config set --path 'k8s_template.master_lb_enabled' false
	pulumi config set --path 'k8s_template.mlb_fip_enabled' false
	pulumi config set --path 'k8s_template.floating_ip_enabled' false
	pulumi config set --path 'k8s_template.insecure_registry' \
		'registry.pbos.local:5000'
	pulumi config set --path 'k8s_template.container_infra_prefix' \
		'registry.pbos.local:5000/magnum/'
	pulumi config set --path 'k8s_template.hyperkube_prefix' \
		'registry.pbos.local:5000/magnum/'
	pulumi config set --path 'k8s_template.az' 'nova'

#########################################################
# Do Not Edit Below!!!                                  #
#########################################################

	pulumi config set 'openstack:authUrl' 'http://$(ENDPOINT_IP):5000/v3'
	pulumi config set --secret 'openstack:password' 
	pulumi config set 'openstack:projectDomainName' 'default'
	pulumi config set 'openstack:userDomainName' 'default'
	pulumi config set 'openstack:userName' 'admin'
	pulumi config set 'openstack:tenantName' 'admin'

	pulumi config set 'openstack_release' 'yoga'
	pulumi config set 'retain_on_delete' 'False'

	pulumi config set --path 'flavor_bastion.vcpus' 1
	pulumi config set --path 'flavor_bastion.ram' 1
	pulumi config set --path 'flavor_bastion.disk' 80

	pulumi config set --path 'k8s_template.dns_nameserver' '$(ENDPOINT_IP)'
	pulumi config set --path 'k8s_template.network_driver' 'calico'
	pulumi config set --path 'k8s_template.volume_driver' 'cinder'
	pulumi config set --path 'k8s_template.container_runtime' ''
	pulumi config set --path 'k8s_template.boot_volume_size' 50
	pulumi config set --path 'k8s_template.boot_volume_type' 'ceph'
	pulumi config set --path 'k8s_template.etcd_volume_size' 10
	pulumi config set --path 'k8s_template.etcd_volume_type' 'ceph'
	pulumi config set --path 'k8s_template.cinder_csi_enabled' 'true'
	pulumi config set --path 'k8s_template.k8s_ver' '1.21.11'
	pulumi config set --path 'k8s_template.other_ver' '1.21.0'
	pulumi config set --path 'k8s_template.helm_client_url' \
		'$(ENDPOINT_IP):7480/magnum/helm-v3.10.1-linux-amd64.tar.gz'
	pulumi config set --path 'k8s_template.helm_client_sha256' \
		'c12d2cd638f2d066fec123d0bd7f010f32c643afdf288d39a4610b1f9cb32af3'
	pulumi config set --path 'k8s_template.helm_client_tag' 'v3.10.1'
	pulumi config set 'endpoint_ip' '$(ENDPOINT_IP)'

up: check
	pulumi stack select $(STACK)
	pulumi up --yes --skip-preview

down: check 
	pulumi stack select $(STACK)
	pulumi down --yes

refresh:
	pulumi stack select $(STACK)
	pulumi refresh --yes

typehint:
	mypy *.py

lint:
	PYTHONPATH=. pylint *.py

tidy:
	black -l 79 *.py

check: lint typehint

.PHONY: stack typehint lint tidy check up down refresh
