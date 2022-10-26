"""A K8S Provisioning Pulumi Program"""
# pylint: disable=C0103
import os
import pathlib
import string
import random
import ast

from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from jinja2 import Environment
from jinja2 import FileSystemLoader

import pulumi
import pulumi_openstack as openstack
import pulumi_command as command

import utils

def create_dns_record(name: str, zonename: Optional[str], addrs: list) -> None:
    """create dns record for {name}"""
    i = 0
    for s_addr in addrs:
        s_name = f"{name}-{i}" if name != "bastion" else name
        openstack.dns.RecordSet(
            s_name,
            name=f"{s_name}.{zonename}.",
            records=[s_addr],
            ttl=3600,
            type="A",
            zone_id=zone.id,
            opts=pulumi.ResourceOptions(
                provider=padmin,
                depends_on=[zone]
            )
        )
        i += 1

homedir = pathlib.Path.home()
config = pulumi.Config()
os_config = pulumi.Config("openstack")

cluster_name: Optional[str] = config.get("cluster_name")
dns_zone_name: Optional[str] = config.get('dns_zone_name')
bastion_fqdn: str = f"bastion.{dns_zone_name}"
retain_on_delete: Optional[bool]  = ast.literal_eval(str(config.get('retain_on_delete')))

o_k8s_tmpl = config.require_object("k8s_template")
o_k8s = config.require_object("k8s")
dns_nameserver = o_k8s_tmpl.get('dns_nameserver')

realm = f"{homedir}/.bkos/{cluster_name}"
os.makedirs(name=realm, mode=0o700, exist_ok=True)

private_file = f"{realm}/id_rsa"
public_file = f"{private_file}" + ".pub"
if not (os.path.isfile(private_file) and os.path.isfile(public_file)):
    key = rsa.generate_private_key(
        backend=default_backend(), public_exponent=65537, key_size=2048
    )
    private_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    public_key = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
        .decode("utf-8")
    )
    with open(file=private_file, mode="w", encoding="ascii") as f:
        f.write(private_key)
        os.chmod(path=private_file, mode=0o600)
    with open(file=public_file, mode="w", encoding="ascii") as f:
        f.write(public_key)
        os.chmod(path=public_file, mode=0o644)
else:
    # get private/public key
    with open(file=private_file, mode="r", encoding="ascii") as f:
        private_key = f.read()
    with open(file=public_file, mode="r", encoding="ascii") as f:
        public_key = f.read()

project = openstack.identity.Project(
    "project",
    name=f"{cluster_name}",
    description=f"{cluster_name} Project",
    opts=pulumi.ResourceOptions(retain_on_delete=retain_on_delete),
)

s_adminpwfile = f"{realm}/.adminpw"
s_memberpwfile = f"{realm}/.memberpw"
s_readerpwfile = f"{realm}/.readerpw"
# create random password
if os.path.isfile(s_adminpwfile):
    with open(file=s_adminpwfile, mode="r", encoding="ascii") as f:
        adminpw = f.read().rstrip()
else:
    adminpw = ''.join(random.choices(string.ascii_letters + string.digits,
        k=20))
    utils.write_to_file(s_adminpwfile, "w", adminpw, 0o600)

if os.path.isfile(s_memberpwfile):
    with open(file=s_memberpwfile, mode="r", encoding="ascii") as f:
        memberpw = f.read().rstrip()
else:
    memberpw = ''.join(random.choices(string.ascii_letters + string.digits,
        k=20))
    utils.write_to_file(s_memberpwfile, "w", memberpw, 0o600)

if os.path.isfile(s_readerpwfile):
    with open(file=s_readerpwfile, mode="r", encoding="ascii") as f:
        readerpw = f.read().rstrip()
else:
    readerpw = ''.join(random.choices(string.ascii_letters + string.digits,
        k=20))
    utils.write_to_file(s_readerpwfile, "w", readerpw, 0o600)

# create admin user in the project
admin_user = openstack.identity.User(
    "admin_user",
    name=f"{cluster_name}_admin",
    default_project_id=project.id,
    password=adminpw,
    opts=pulumi.ResourceOptions(retain_on_delete=retain_on_delete),
)
member_user = openstack.identity.User(
    "member_user",
    name=f"{cluster_name}_member",
    default_project_id=project.id,
    password=memberpw,
    opts=pulumi.ResourceOptions(retain_on_delete=retain_on_delete),
)
reader_user = openstack.identity.User(
    "reader_user",
    name=f"{cluster_name}_reader",
    default_project_id=project.id,
    password=readerpw,
    opts=pulumi.ResourceOptions(retain_on_delete=retain_on_delete),
)
# get admin role
admin_role = openstack.identity.get_role(name="admin")
member_role = openstack.identity.get_role(name="member")
reader_role = openstack.identity.get_role(name="reader")
# add a role to user
admin_role_assign = openstack.identity.RoleAssignment(
    "admin_role_assign",
    project_id=project.id,
    role_id=admin_role.id,
    user_id=admin_user.id,
    opts=pulumi.ResourceOptions(retain_on_delete=retain_on_delete),
)
member_role_assign = openstack.identity.RoleAssignment(
    "member_role_assign",
    project_id=project.id,
    role_id=member_role.id,
    user_id=member_user.id,
    opts=pulumi.ResourceOptions(retain_on_delete=retain_on_delete),
)
reader_role_assign = openstack.identity.RoleAssignment(
    "reader_role_assign",
    project_id=project.id,
    role_id=reader_role.id,
    user_id=reader_user.id,
    opts=pulumi.ResourceOptions(retain_on_delete=retain_on_delete),
)

# store each rc files
rc = [
    {
        "outfile": f"{realm}/adminrc",
        "username": f"{cluster_name}_admin",
        "password": adminpw,
    },
    {
        "outfile": f"{realm}/memberrc",
        "username": f"{cluster_name}_member",
        "password": memberpw,
    },
    {
        "outfile": f"{realm}/readerrc",
        "username": f"{cluster_name}_reader",
        "password": readerpw,
    },
]
adminrc = ''
memberrc = ''
env = Environment(loader=FileSystemLoader("templates/"))
tmpl = env.get_template("rc.j2")
for r in rc:
    content = tmpl.render(
        r, auth_url=os_config.get("authUrl"), project_name=cluster_name
    )
    with open(file=r["outfile"], mode="w", encoding="utf-8") as f:
        f.write(content)
    os.chmod(path=r["outfile"], mode=0o600)
    # get rc file content for userdata.j2
    with open(file=r["outfile"], mode="r", encoding="utf-8") as f:
        if r["outfile"] == f"{realm}/adminrc":
            adminrc = f.read()
        elif r["outfile"] == f"{realm}/memberrc":
            memberrc = f.read()

# create project admin provider
padmin = openstack.Provider(
    "padmin",
    auth_url=os_config.get("authUrl"),
    project_domain_name="default",
    user_domain_name="default",
    tenant_name=cluster_name,
    user_name=f"{cluster_name}_admin",
    password=adminpw,
    opts=pulumi.ResourceOptions(depends_on=[admin_role_assign]),
)
# create ssh keypair
keypair = openstack.compute.keypair.Keypair(
    "keypair",
    name=f"{cluster_name}_key",
    public_key=public_key,
    opts=pulumi.ResourceOptions(provider=padmin),
)

# create flavors
o_flavor_master = config.require_object("flavor_master")
master_flavor = openstack.compute.Flavor(
    "master_flavor",
    name=f"{cluster_name}-master-flavor",
    vcpus=o_flavor_master.get("vcpus"),
    ram=o_flavor_master.get("ram")*1024,
    disk=o_flavor_master.get("disk"),
    is_public=True,
    opts=pulumi.ResourceOptions(provider=padmin),
)
o_flavor_node = config.require_object("flavor_node")
node_flavor = openstack.compute.Flavor(
    "node_flavor",
    name=f"{cluster_name}-node-flavor",
    vcpus=o_flavor_node.get("vcpus"),
    ram=o_flavor_node.get("ram")*1024,
    disk=o_flavor_node.get("disk"),
    is_public=True,
    opts=pulumi.ResourceOptions(provider=padmin),
)
o_flavor_bastion = config.require_object("flavor_bastion")
bastion_flavor = openstack.compute.Flavor(
    "bastion_flavor",
    name=f"{cluster_name}-bastion-flavor",
    vcpus=o_flavor_bastion.get("vcpus"),
    ram=o_flavor_bastion.get("ram")*1024,
    disk=o_flavor_bastion.get("disk"),
    is_public=False,
    opts=pulumi.ResourceOptions(provider=padmin),
)

# create network/subnet
# get provider network resource
provider_network = openstack.networking.get_network(
    name=config.get("provider_network_name"),
    opts=pulumi.InvokeOptions(provider=padmin),
)
network = openstack.networking.Network(
    f"{cluster_name}-net",
    name=f"{cluster_name}-net",
    admin_state_up=True,
    opts=pulumi.ResourceOptions(provider=padmin),
)
subnet = openstack.networking.Subnet(
    f"{cluster_name}-subnet",
    name=f"{cluster_name}-subnet",
    cidr=o_k8s.get('subnet_cidr'),
    ip_version=4,
    dns_nameservers=[dns_nameserver],
    network_id=network.id,
    opts=pulumi.ResourceOptions(provider=padmin),
)
router = openstack.networking.Router(
    f"{cluster_name}-router",
    name=f"{cluster_name}-router",
    admin_state_up=True,
    external_network_id=provider_network.id,
    opts=pulumi.ResourceOptions(provider=padmin),
)
router_interface = openstack.networking.RouterInterface(
    "routerInterface",
    router_id=router.id,
    subnet_id=subnet.id,
    opts=pulumi.ResourceOptions(provider=padmin),
)
# templating post_install/coredns_configmap/coredns_append/post_run/userdata
tmpl = env.get_template("post_install.yml.j2")
post_install = tmpl.render({
    "cluster_name": f"{cluster_name}"
})
with open(file="files/post_install.yml", mode="w", encoding="utf-8") as f:
    f.write(post_install)

with open(file="files/coredns_configmap.yml", mode="r", encoding="utf-8") as f:
    coredns_configmap = f.read()

tmpl = env.get_template("coredns_default_append.yml.j2")
coredns_default_append = tmpl.render({
    "default_zone_name": config.get("default_zone_name"),
    "dns_nameserver": dns_nameserver,
})
with open(file="files/coredns_default_append.yml",
        mode="w", encoding="utf-8") as f:
    f.write(coredns_default_append)

tmpl = env.get_template("coredns_append.yml.j2")
coredns_append = tmpl.render({
    "dns_zone_name": config.get("dns_zone_name"),
    "dns_nameserver": dns_nameserver,
})
with open(file="files/coredns_append.yml", mode="w", encoding="utf-8") as f:
    f.write(coredns_append)

tmpl = env.get_template("post_run.sh.j2")
post_run = tmpl.render({
    "k8s_ver": o_k8s_tmpl.get("k8s_ver"),
    "helm_ver": o_k8s_tmpl.get("helm_ver"),
    "cluster_name": config.get("cluster_name"),
    "default_zone_name": config.get("default_zone_name"),
    "dns_zone_name": config.get("dns_zone_name"),
})
with open(file="files/post_run.sh", mode="w", encoding="utf-8") as f:
    f.write(post_run)

tmpl = env.get_template("userdata.j2")
userdata = tmpl.render({
    "private_key": private_key,
    "public_key": public_key,
    "openstack_release": config.get("openstack_release"),
    "adminrc": adminrc,
    "memberrc": memberrc,
    "post_install": post_install,
    "coredns_configmap": coredns_configmap,
    "coredns_default_append": coredns_default_append,
    "coredns_append": coredns_append,
    "post_run": post_run,
})
with open(file="files/userdata", mode="w", encoding="utf-8") as f:
    f.write(userdata)

# create cluster template
d_k8s_labels = {
    "container_runtime": o_k8s_tmpl.get('container_runtime'),
    "selinux_mode": "disabled",
    "use_podman": "true",
    "container_infra_prefix": o_k8s_tmpl.get('container_infra_prefix'),
    "hyperkube_prefix": o_k8s_tmpl.get('hyperkube_prefix'),
    "master_lb_floating_ip_enabled": o_k8s_tmpl.get('mlb_fip_enabled'),
    "boot_volume_size": o_k8s_tmpl.get('boot_volume_size'),
    "boot_volume_type": o_k8s_tmpl.get('boot_volume_type'),
    "etcd_volume_size": o_k8s_tmpl.get('etcd_volume_size'),
    "etcd_volume_type": o_k8s_tmpl.get('etcd_volume_type'),
    "cinder_csi_enabled": "true",
    "cinder_csi_plugin_tag": f"v{o_k8s_tmpl.get('other_ver')}",
    "cloud_provider_enabled": "true",
    "cloud_provider_tag": f"v{o_k8s_tmpl.get('other_ver')}",
    "k8s_keystone_auth_tag": f"v{o_k8s_tmpl.get('other_ver')}",
    "keystone_auth_enabled": "true",
    "kube_tag": f"v{o_k8s_tmpl.get('k8s_ver')}-rancher1",
    "ingress_controller": "octavia",
    "octavia_ingress_controller_tag": f"v{o_k8s_tmpl.get('other_ver')}",
    "kube_dashboard_enabled": "false",
    "availability_zone": o_k8s_tmpl.get('az'),
}
cluster_tmpl = openstack.containerinfra.ClusterTemplate(
    f"{cluster_name}-template",
    name=f"{cluster_name}-template",
    coe="kubernetes",
    image="fcos",
    keypair_id=keypair.id,
    insecure_registry=o_k8s_tmpl.get("insecure_registry"),
    fixed_network=network.name,
    fixed_subnet=subnet.name,
    network_driver=o_k8s_tmpl.get("network_driver"),
    master_flavor=master_flavor.id,
    flavor=node_flavor.id,
    volume_driver=o_k8s_tmpl.get("volume_driver"),
    dns_nameserver=dns_nameserver,
    external_network_id=provider_network.id,
    master_lb_enabled=o_k8s_tmpl.get("master_lb_enabled"),
    floating_ip_enabled=o_k8s_tmpl.get("floating_ip_enabled"),
    labels=d_k8s_labels,
    opts=pulumi.ResourceOptions(
        depends_on=[router_interface],
        provider=padmin
    ),
)

cluster = openstack.containerinfra.Cluster(
    f"{cluster_name}",
    name=f"{cluster_name}",
    cluster_template_id=cluster_tmpl.id,
    master_count=o_k8s.get("master_count"),
    node_count=o_k8s.get("node_count"),
    opts=pulumi.ResourceOptions(provider=padmin),
)

## create bastion
# get debian image
bastion_image = openstack.images.get_image(name="bastion")
# create secgroup for bastion
sg = openstack.networking.SecGroup(
    "sg",
    name=f"{cluster_name}-bastion-sg",
    description=f"Security Group for {cluster_name}-bastion",
    opts=pulumi.ResourceOptions(provider=padmin),
)
sg_icmp = openstack.networking.SecGroupRule(
    "sg_icmp",
    direction="ingress",
    ethertype="IPv4",
    protocol="icmp",
    remote_ip_prefix="0.0.0.0/0",
    description="Allow incoming icmp",
    security_group_id=sg.id,
    opts=pulumi.ResourceOptions(provider=padmin),
)
sg_tcp = openstack.networking.SecGroupRule(
    "sg_tcp",
    direction="ingress",
    ethertype="IPv4",
    protocol="tcp",
    remote_ip_prefix="0.0.0.0/0",
    description="Allow incoming tcp",
    security_group_id=sg.id,
    opts=pulumi.ResourceOptions(provider=padmin),
)
sg_udp = openstack.networking.SecGroupRule(
    "sg_udp",
    direction="ingress",
    ethertype="IPv4",
    protocol="udp",
    remote_ip_prefix="0.0.0.0/0",
    description="Allow incoming udp",
    security_group_id=sg.id,
    opts=pulumi.ResourceOptions(provider=padmin),
)

bastion_instance = openstack.compute.Instance(
    "bastion",
    name=f"{cluster_name}-bastion",
    flavor_id=bastion_flavor.id,
    key_pair=keypair.id,
    security_groups=[sg.name],
    user_data=userdata,
    block_devices=[
        openstack.compute.InstanceBlockDeviceArgs(
            source_type="image",
            destination_type="volume",
            delete_on_termination=True,
            volume_size=o_flavor_bastion.get("disk"),
            uuid=bastion_image.id,
        )
    ],
    networks=[
        openstack.compute.InstanceNetworkArgs(name=network.name),
    ],
    opts=pulumi.ResourceOptions(
        provider=padmin,
        depends_on=[cluster],
    ),
)
bastion_fip = openstack.networking.FloatingIp(
    "bastion_fip", pool=config.get("provider_network_name")
)
bastion_fip_assoc = openstack.compute.FloatingIpAssociate(
    "bastion_fip_assoc",
    fixed_ip=bastion_instance.networks[0].fixed_ip_v4,
    floating_ip=bastion_fip.address,
    instance_id=bastion_instance.id,
)
# DNS zone and recordset
email = f"admin@{dns_zone_name}"
zone = openstack.dns.Zone(
    f"{dns_zone_name}",
    name=f"{dns_zone_name}.",
    description=f"{cluster_name} dns zone",
    email=email,
    type="PRIMARY",
    ttl=3600,
    opts=pulumi.ResourceOptions(
        provider=padmin,
        depends_on=[bastion_instance]
    )
)
cluster.master_addresses.apply(
    lambda v: create_dns_record("master", dns_zone_name, v)
)
cluster.node_addresses.apply(
    lambda v: create_dns_record("node", dns_zone_name, v)
)
bastion_fip.address.apply(
    lambda v: create_dns_record("bastion", dns_zone_name, [v])
)
# wait until bastion ssh port is opened
wait_sleep = command.local.Command(
    "wait_sleep",
    create=f"""while true;do
        echo 2>/dev/null > /dev/tcp/{bastion_fqdn}/22 && break || sleep 5;
      done; sleep 120""",
    interpreter=["/bin/bash", "-c"],
    opts=pulumi.ResourceOptions(depends_on=[zone]),
)
bastion_ready = command.remote.Command(
    "bastion_ready",
    connection=command.remote.ConnectionArgs(
        host=bastion_fip.address,
        port=22,
        user="clex",
        private_key=private_key,
    ),
    create="while true;do [ -f $HOME/.i_am_ready ] && exit 0 || sleep 5;done",
    opts=pulumi.ResourceOptions(depends_on=[wait_sleep]),
)

pulumi.export("cluster_name", cluster_name)
pulumi.export("kubeconfig", cluster.kubeconfig)
pulumi.export("api_address", cluster.api_address)
pulumi.export("coe_version", cluster.coe_version)
pulumi.export("container_version", cluster.container_version)
pulumi.export("master_addresses", cluster.master_addresses)
pulumi.export("node_addresses", cluster.node_addresses)
pulumi.export("bastion_fip", bastion_fip.address)
pulumi.export("zone_id", zone.id)
