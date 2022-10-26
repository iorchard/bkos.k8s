"""utils module for main"""
import os
import pulumi

def write_to_file(file: str, mode: str, content: str, filemode: int) -> None:
    """write hosts file with a different mode"""
    with open(file, mode, encoding="utf-8") as o_file:
        o_file.write(f"{content}\n")
    os.chmod(file, filemode)

def _write_to_yaml(file: str, mode: str, content: str, filemode: int) -> None:
    """write vars yaml file"""
    with open(file, mode, encoding="utf-8") as o_file:
        (name, ip_address) = content.split(sep=" ")
        o_file.write(f"  - {{'name': '{name}', 'ip': '{ip_address}'}}\n")
    os.chmod(file, filemode)

def create_hosts(ips: list):
    """create hosts file."""
    for d_host in ips:
        if d_host["name"] == "master":
            pulumi.Output.all(d_host["ip"]).apply(
                lambda v: write_to_file("master_hosts", "w", '\n'.join(v[0]),
                    0o644)
            )
        elif d_host["name"] == "node":
            pulumi.Output.all(d_host["ip"]).apply(
                lambda v: write_to_file("node_hosts", "w", '\n'.join(v[0]),
                    0o644)
            )
        elif d_host["name"] == "bastion":
            pulumi.Output.all(d_host["ip"]).apply(
                lambda v: write_to_file("bastion_hosts", "w", f"{v[0]}", 0o644)
            )
            pulumi.Output.all(d_host["fip"]).apply(
                lambda v: write_to_file("bastion_fip_hosts", "w", f"{v[0]}", 0o644)
            )

    return True
