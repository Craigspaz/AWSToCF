import boto3
import datetime
import json

ec2_client = boto3.client("ec2")

index = 0 # A value to make variable names unique

class AWS_Subnet:
    def __init__(self):
        self.availability_zone = None
        self.availability_zone_id = None
        self.available_ip_address_count = None
        self.cidr_block = None
        self.default_for_az = None
        self.enable_lni_at_device_index = None
        self.map_public_ip_on_launch = None
        self.map_customer_owned_ip_on_launch = None
        self.customer_owned_ipv4_pool = None
        self.state = None
        self.subnet_id = None
        self.vpc = None
        self.owner_id = None
        self.assign_ipv6_address_on_creation = None
        self.ipv6_cidr_block_association_set = None
        self.tags = None
        self.subnet_arn = None
        self.outpost_arn = None
        self.enable_dns64 = None
        self.ipv6_native = None
        self.private_dns_name_options_on_launch = None

        self.cf_name = None

    def to_cloudformation(self):
        global index
        self.cf_name = "Subnet" + str(index)
        index += 1
        result = {
           str(self.cf_name) : {}
        }
        result[self.cf_name]["Type"] = "AWS::EC2::Subnet"
        result[self.cf_name]["Properties"] = {
            "CidrBlock": str(self.cidr_block)
        }
        if self.availability_zone != None:
            result[self.cf_name]["Properties"]["AvailabilityZone"] = self.availability_zone
        if self.enable_dns64 != None:
            result[self.cf_name]["Properties"]["EnableDns64"] = self.enable_dns64
        if self.map_public_ip_on_launch != None:
            result[self.cf_name]["Properties"]["MapPublicIpOnLaunch"] = self.map_public_ip_on_launch
        if self.private_dns_name_options_on_launch != None:
            result[self.cf_name]["Properties"]["PrivateDnsNameOptionsOnLaunch"] = {
                "EnableResourceNameDnsAAAARecord": self.private_dns_name_options_on_launch.get("EnableResourceNameDnsAAAARecord", None),
                "EnableResourceNameDnsARecord": self.private_dns_name_options_on_launch.get("EnableResourceNameDnsARecord", None)
            }
        result[self.cf_name]["Properties"]["VpcId"] = {"Ref": str(self.vpc.cf_name)}
        if self.tags != None:
            result[self.cf_name]["Properties"]["Tags"] = self.tags

        return result

class AWS_Network_Acl:
    def __init__(self):
        self.associations = None
        self.entries = None
        self.is_default = None
        self.network_acl_id = None
        self.tags = None
        self.vpc = None
        self.owner_id = None

        self.cf_name = None

    def to_cloudformation(self):
        global index
        self.cf_name = "NACL" + str(index)
        index += 1
        result = {
           str(self.cf_name) : {}
        }
        result[self.cf_name]["Type"] = "AWS::EC2::NetworkAcl"
        result[self.cf_name]["Properties"] = {}
        if self.tags != None:
            result[self.cf_name]["Properties"]["Tags"] = self.tags
        if self.vpc != None:
            result[self.cf_name]["Properties"]["VpcId"] = {"Ref": str(self.vpc.cf_name)}

        print("Processing NACL Associations")
        for association in self.associations:

            association_name = "NACLAssociation" + str(index)
            index += 1
            result[association_name] = {}
            result[association_name]["Type"] = "AWS::EC2::SubnetNetworkAclAssociation"
            result[association_name]["Properties"] = {
                "NetworkAclId": {"Ref": str(self.cf_name)},
                "SubnetId": {"Ref": str(association.cf_name)}
            }

        print("Processing NACL Entries")
        for entry in self.entries:

            if entry.get("RuleNumber") == 32767:
                print("Found Default Rule so ignoring it...")
                continue

            entry_name = "NACLEntry" + str(index)
            index += 1
            result[entry_name] = {}
            result[entry_name]["Type"] = "AWS::EC2::NetworkAclEntry"
            result[entry_name]["Properties"] = {}
            if "CidrBlock" in entry:
                result[entry_name]["Properties"]["CidrBlock"] = entry.get("CidrBlock")
            result[entry_name]["Properties"]["Egress"] = entry.get("Egress")
            if "Icmp" in entry:
                result[entry_name]["Properties"]["Icmp"] = entry.get("IcmpTypeCode")
            if "Ipv6CidrBlock" in entry:
                result[entry_name]["Properties"]["Ipv6CidrBlock"] = entry.get("Ipv6CidrBlock")
            result[entry_name]["Properties"]["NetworkAclId"] = {"Ref": str(self.cf_name)}
            if "PortRange" in entry:
                result[entry_name]["Properties"]["PortRange"] = entry.get("PortRange")
            if "Protocol" in entry:
                result[entry_name]["Properties"]["Protocol"] = entry.get("Protocol")
            result[entry_name]["Properties"]["RuleAction"] = entry.get("RuleAction")
            result[entry_name]["Properties"]["RuleNumber"] = entry.get("RuleNumber")
            


        return result

class AWS_Internet_Gateway:
    def __init__(self):
        self.attachments = None
        self.internet_gateway_id = None
        self.owner_id = None
        self.tags = None

        self.cf_name = None

    def to_cloudformation(self):
        global index
        self.cf_name = "IGW" + str(index)
        index += 1
        result = {
           str(self.cf_name) : {}
        }
        result[self.cf_name]["Type"] = "AWS::EC2::InternetGateway"
        result[self.cf_name]["Properties"] = {}
        if self.tags != None:
            result[self.cf_name]["Properties"]["Tags"] = self.tags

        print("Checking if IGW is attached to VPC...")
        print(self.attachments)
        for attachment in self.attachments:

            attachment_name = "IGWAttachment" + str(index)
            index += 1
            result[attachment_name] = {}
            result[attachment_name]["Type"] = "AWS::EC2::VPCGatewayAttachment"
            result[attachment_name]["Properties"] = {
                "InternetGatewayId": {"Ref": str(self.cf_name)},
                "VpcId": {"Ref": str(attachment.cf_name)}
            }

        return result

class AWS_Route_Table:
    def __init__(self):
        self.associations = None
        self.propagating_vgws = None
        self.route_table_id = None
        self.routes = None
        self.tags = None
        self.vpc = None
        self.owner_id = None

        self.cf_name = None

    def to_cloudformation(self, igws):
        global index
        self.cf_name = "RouteTable" + str(index)
        index += 1
        result = {
           str(self.cf_name) : {}
        }
        result[self.cf_name]["Type"] = "AWS::EC2::RouteTable"
        result[self.cf_name]["Properties"] = {
            "VpcId": {"Ref": str(self.vpc.cf_name)}
        }
        if self.tags != None:
            result[self.cf_name]["Properties"]["Tags"] = self.tags

        for association in self.associations:
            association_name = "RouteTableAssociation" + str(index)
            index += 1
            result[association_name] = {}
            result[association_name]["Type"] = "AWS::EC2::SubnetRouteTableAssociation"
            result[association_name]["Properties"] = {
                "RouteTableId": {"Ref": str(self.cf_name)},
                "SubnetId": {"Ref": str(association.cf_name)}
            }

        for route in self.routes:
            raw_route = {}
            raw_route["Type"] = "AWS::EC2::Route"
            raw_route["Properties"] = {}

            if "DestinationCidrBlock" in route:
                raw_route["Properties"]["DestinationCidrBlock"] = route.get("DestinationCidrBlock")
            if "DestinationIpv6CidrBlock" in route:
                raw_route["Properties"]["DestinationIpv6CidrBlock"] = route.get("DestinationIpv6CidrBlock")
            if "DestinationPrefixListId" in route:
                # raw_route["Properties"]["DestinationPrefixListId"] = route.get("DestinationPrefixListId")
                continue
            if "EgressOnlyInternetGatewayId" in route:
                # raw_route["Properties"]["EgressOnlyInternetGatewayId"] = route.get("EgressOnlyInternetGatewayId")
                continue
            if "GatewayId" in route:
                resource_id = route.get("GatewayId")
                for igw in igws:
                    if igw.internet_gateway_id == resource_id:
                        raw_route["Properties"]["GatewayId"] = {"Ref": str(igw.cf_name)}
                        break
            if "InstanceId" in route:
                # raw_route["Properties"]["InstanceId"] = route.get("InstanceId")
                continue
            if "LocalGatewayId" in route:
                # raw_route["Properties"]["LocalGatewayId"] = route.get("LocalGatewayId")
                continue
            if "NatGatewayId" in route:
                # raw_route["Properties"]["NatGatewayId"] = route.get("NatGatewayId")
                continue
            if "NetworkInterfaceId" in route:
                # raw_route["Properties"]["NetworkInterfaceId"] = route.get("NetworkInterfaceId")
                continue
            raw_route["Properties"]["RouteTableId"] = {"Ref": str(self.cf_name)}
            if "TransitGatewayId" in route:
                # raw_route["Properties"]["TransitGatewayId"] = route.get("TransitGatewayId")
                continue
            if "VpcEndpointId" in route:
                # raw_route["Properties"]["VpcEndpointId"] = route.get("VpcEndpointId")
                continue
            if "VpcPeeringConnectionId" in route:
                # raw_route["Properties"]["VpcPeeringConnectionId"] = route.get("VpcPeeringConnectionId")
                continue

            if len(raw_route["Properties"]) == 2:
                continue
            route_name = "RouteTableRule" + str(index)
            index += 1
            result[route_name] = raw_route

        return result

class AWS_Security_Group:
    def __init__(self):
        self.description = None
        self.group_name = None
        self.ip_permissions = None
        self.owner_id = None
        self.group_id = None
        self.ip_permissions_egress = None
        self.tags = None
        self.vpc = None

        self.cf_name = None

    def to_cloudformation(self):
        global index
        if self.group_name == "default":
            return {}
        self.cf_name = "SG" + str(index)
        index += 1
        result = {
           str(self.cf_name) : {}
        }
        result[self.cf_name]["Type"] = "AWS::EC2::SecurityGroup"
        result[self.cf_name]["Properties"] = {}
        result[self.cf_name]["Properties"]["GroupDescription"] = self.description
        result[self.cf_name]["Properties"]["GroupName"] = self.group_name
        result[self.cf_name]["Properties"]["VpcId"] = {"Ref": str(self.vpc.cf_name)}
        if self.tags != None:
            result[self.cf_name]["Properties"]["Tags"] = self.tags

        
        for ip_permission in self.ip_permissions:
            sg_rule_name = "SecurityGroupRule" + str(index)
            index += 1
            result[sg_rule_name] = {}
            result[sg_rule_name]["Type"] = "AWS::EC2::SecurityGroupIngress"
            result[sg_rule_name]["Properties"] = {}
            if "IpRanges" in ip_permission and len(ip_permission["IpRanges"]) > 0:
                result[sg_rule_name]["Properties"]["CidrIp"] = ip_permission.get("IpRanges")[0].get("CidrIp")
                result[sg_rule_name]["Properties"]["Description"] = ip_permission.get("IpRanges")[0].get("Description","")
            elif "Ipv6Ranges" in ip_permission and len(ip_permission["Ipv6Ranges"]) > 0:
                result[sg_rule_name]["Properties"]["CidrIpv6"] = ip_permission.get("Ipv6Ranges")[0].get("CidrIpv6")
                result[sg_rule_name]["Properties"]["Description"] = ip_permission.get("Ipv6Ranges")[0].get("Description","")
            if "FromPort" in ip_permission:
                result[sg_rule_name]["Properties"]["FromPort"] = ip_permission.get("FromPort")
            result[sg_rule_name]["Properties"]["GroupId"] = {"Ref": str(self.cf_name)}
            result[sg_rule_name]["Properties"]["IpProtocol"] = ip_permission.get("IpProtocol")
            if "PrefixListIds" in ip_permission and len(ip_permission["PrefixListIds"]) > 0:
                result[sg_rule_name]["Properties"]["SourcePrefixListId"] = ip_permission.get("PrefixListIds")[0].get("PrefixListId")
                result[sg_rule_name]["Properties"]["Description"] = ip_permission.get("PrefixListIds")[0].get("Description","")
            if "UserIdGroupPairs" in ip_permission:
                if "GroupId" in ip_permission["UserIdGroupPairs"]:
                    result[sg_rule_name]["Properties"]["SourceSecurityGroupId"] = ip_permission["UserIdGroupPairs"]["GroupId"]
            if "ToPort" in ip_permission:
                result[sg_rule_name]["Properties"]["ToPort"] = ip_permission.get("ToPort")

        for ip_permission in self.ip_permissions_egress:
            sg_rule_name = "SecurityGroupRule" + str(index)
            index += 1
            result[sg_rule_name] = {}
            result[sg_rule_name]["Type"] = "AWS::EC2::SecurityGroupEgress"
            result[sg_rule_name]["Properties"] = {}
            if "IpRanges" in ip_permission and len(ip_permission["IpRanges"]) > 0:
                result[sg_rule_name]["Properties"]["CidrIp"] = ip_permission.get("IpRanges")[0].get("CidrIp")
                result[sg_rule_name]["Properties"]["Description"] = ip_permission.get("IpRanges")[0].get("Description","")
            if "Ipv6Ranges" in ip_permission and len(ip_permission["Ipv6Ranges"]) > 0:
                result[sg_rule_name]["Properties"]["CidrIpv6"] = ip_permission.get("Ipv6Ranges")[0].get("CidrIpv6")
                result[sg_rule_name]["Properties"]["Description"] = ip_permission.get("Ipv6Ranges")[0].get("Description","")
            if "FromPort" in ip_permission:
                result[sg_rule_name]["Properties"]["FromPort"] = ip_permission.get("FromPort")
            result[sg_rule_name]["Properties"]["GroupId"] = {"Ref": str(self.cf_name)}
            result[sg_rule_name]["Properties"]["IpProtocol"] = ip_permission.get("IpProtocol")
            if "PrefixListIds" in ip_permission and len(ip_permission["PrefixListIds"]) > 0:
                result[sg_rule_name]["Properties"]["DestinationPrefixListId"] = ip_permission.get("PrefixListIds")[0].get("PrefixListId")
                result[sg_rule_name]["Properties"]["Description"] = ip_permission.get("PrefixListIds")[0].get("Description","")
            if "UserIdGroupPairs" in ip_permission:
                if "GroupId" in ip_permission["UserIdGroupPairs"]:
                    result[sg_rule_name]["Properties"]["DestinationSecurityGroupId"] = ip_permission["UserIdGroupPairs"]["GroupId"]
            if "ToPort" in ip_permission:
                result[sg_rule_name]["Properties"]["ToPort"] = ip_permission.get("ToPort")
            


        return result

class AWS_VPC:

    def __init__(self):
        self.vpc_id = None
        self.cidr_block = None
        self.state = None
        self.owner_id = None
        self.instance_tenancy = None
        self.ipv6_cidr_block_association_set = None
        self.cidr_block_association_set = None
        self.is_default = None
        self.tags = None

        self.subnets = []

        self.cf_name = None

    def to_cloudformation(self):
        global index
        self.cf_name = "VPC" + str(index)
        index += 1
        result = {
           str(self.cf_name) : {}
        }
        result[self.cf_name]["Type"] = "AWS::EC2::VPC"
        result[self.cf_name]["Properties"] = {
            "CidrBlock": str(self.cidr_block)
        }
        if self.instance_tenancy != None:
            result[self.cf_name]["Properties"]["InstanceTenancy"] = self.instance_tenancy
        if self.tags != None:
            result[self.cf_name]["Properties"]["Tags"] = self.tags

        return result


def fetch_internet_gateways(ec2_client, vpcs):
    igws = []

    pagination_token = None
    while True:
        results = None
        if pagination_token == None:
            results = ec2_client.describe_internet_gateways()
        else:
            results = ec2_client.describe_internet_gateways(NextToken=pagination_token)
        if results != None:
            pagination_token = results.get("NextToken", None)

            for igw in results["InternetGateways"]:
                raw_igw = AWS_Internet_Gateway()
                raw_igw.attachments = []
                for attachment in igw.get("Attachments", []):
                    if attachment.get("State") == "available" or attachment.get("State") == "attached" or attachment.get("State") == "attaching":
                        for vpc in vpcs:
                            if vpc.vpc_id == attachment.get("VpcId"):
                                raw_igw.attachments.append(vpc)
                                break
                raw_igw.internet_gateway_id = igw.get("InternetGatewayId")
                raw_igw.owner_id = igw.get("OwnerId")
                raw_igw.tags = igw.get("Tags", None)

                igws.append(raw_igw)
        
        if pagination_token == None:
            break
    return igws 

def fetch_route_tables(ec2_client, subnets, vpcs):
    route_tables = []

    pagination_token = None
    while True:
        results = None
        if pagination_token == None:
            results = ec2_client.describe_route_tables()
        else:
            results = ec2_client.describe_route_tables(NextToken=pagination_token)
        if results != None:
            pagination_token = results.get("NextToken", None)

            for route_table in results["RouteTables"]:
                raw_route_table = AWS_Route_Table()
                raw_route_table.associations = []
                for associations in route_table.get("Associations"):
                    association_state = associations.get("AssociationState", None)
                    if association_state != None and (association_state.get("State") != "associated" and association_state.get("State") != "associating"):
                        print("Skipping route table that is disassociated or disassociating")
                        continue
                    for subnet in subnets:
                        if subnet.subnet_id == associations.get("SubnetId"):
                            raw_route_table.associations.append(subnet)
                            break
                raw_route_table.propagating_vgws = route_table.get("PropagatingVgws", None)
                raw_route_table.route_table_id = route_table.get("RouteTableId")
                raw_route_table.routes = route_table.get("Routes", None)
                raw_route_table.tags = route_table.get("Tags", None)
                for vpc in vpcs:
                    if vpc.vpc_id == route_table.get("VpcId"):
                        raw_route_table.vpc = vpc
                        break
                raw_route_table.owner_id = route_table.get("OwnerId")

                route_tables.append(raw_route_table)
        
        if pagination_token == None:
            break
    return route_tables

def fetch_security_groups(ec2_client, vpcs):
    security_groups = []

    pagination_token = None
    while True:
        results = None
        if pagination_token == None:
            results = ec2_client.describe_security_groups()
        else:
            results = ec2_client.describe_security_groups(NextToken=pagination_token)
        if results != None:
            pagination_token = results.get("NextToken", None)

            for sg in results["SecurityGroups"]:
                raw_sg = AWS_Security_Group()
                raw_sg.description = sg.get("Description")
                raw_sg.group_name = sg.get("GroupName")
                raw_sg.ip_permissions = sg.get("IpPermissions", None)
                raw_sg.owner_id = sg.get("OwnerId")
                raw_sg.group_id = sg.get("GroupId")
                raw_sg.ip_permissions_egress = sg.get("IpPermissionsEgress", None)
                raw_sg.tags = sg.get("Tags", None)
                for vpc in vpcs:
                    if vpc.vpc_id == sg.get("VpcId"):
                        raw_sg.vpc = vpc
                        break

                security_groups.append(raw_sg)
        
        if pagination_token == None:
            break
    return security_groups

def fetch_vpc(ec2_client):
    vpcs = []

    pagination_token = None
    while True:
        results = None
        if pagination_token == None:
            results = ec2_client.describe_vpcs()
        else:
            results = ec2_client.describe_vpcs(NextToken=pagination_token)
        if results != None:
            pagination_token = results.get("NextToken", None)

            for vpc in results["Vpcs"]:
                if vpc.get("state") == "pending":
                    print("Found VPC in the pending state so skipping...")
                    continue

                raw_vpc = AWS_VPC()
                raw_vpc.cidr_block = vpc.get("CidrBlock")
                raw_vpc.state = vpc.get("state")
                raw_vpc.vpc_id = vpc.get("VpcId")
                raw_vpc.instance_tenancy = vpc.get("InstanceTenancy")
                raw_vpc.ipv6_cidr_block_association_set = vpc.get("Ipv6CidrBlockAssociationSet", None)
                raw_vpc.cidr_block_association_set = vpc.get("CidrBlockAssociationSet", None)
                raw_vpc.is_default = vpc.get("IsDefault")
                raw_vpc.tags = vpc.get("Tags", None)

                vpcs.append(raw_vpc)
        
        if pagination_token == None:
            break
    return vpcs

def fetch_subnets(ec2_client, vpcs):
    subnets = []

    pagination_token = None
    while True:
        results = None
        if pagination_token == None:
            results = ec2_client.describe_subnets()
        else:
            results = ec2_client.describe_subnets(NextToken=pagination_token)
        if results != None:
            pagination_token = results.get("NextToken", None)

            for subnet in results["Subnets"]:
                if subnet.get("State") == "pending":
                    print("Skipping subnet that is in pending state...")
                    continue

                raw_subnet = AWS_Subnet()
                raw_subnet.availability_zone = subnet.get("AvailabilityZone")
                raw_subnet.availability_zone_id = subnet.get("AvailabilityZoneId")
                raw_subnet.available_ip_address_count = subnet.get("AvailableIpAddressCount")
                raw_subnet.cidr_block = subnet.get("CidrBlock")
                raw_subnet.default_for_az = subnet.get("DefaultForAz")
                raw_subnet.enable_lni_at_device_index = subnet.get("EnableLniAtDeviceIndex")
                raw_subnet.map_public_ip_on_launch = subnet.get("MapPublicIpOnLaunch")
                raw_subnet.map_customer_owned_ip_on_launch = subnet.get("MapCustomerOwnedIpOnLaunch")
                raw_subnet.customer_owned_ipv4_pool = subnet.get("CustomerOwnedIpv4Pool")
                raw_subnet.state = subnet.get("State")
                raw_subnet.subnet_id = subnet.get("SubnetId")

                for vpc in vpcs:
                    if vpc.vpc_id == subnet.get("VpcId"):
                        raw_subnet.vpc = vpc
                        break
                
                raw_subnet.owner_id = subnet.get("OwnerId")
                raw_subnet.assign_ipv6_address_on_creation = subnet.get("AssignIpv6AddressOnCreation")
                raw_subnet.ipv6_cidr_block_association_set = subnet.get("Ipv6CidrBlockAssociationSet", None)
                raw_subnet.tags = subnet.get("Tags", None)
                raw_subnet.subnet_arn = subnet.get("SubnetArn")
                raw_subnet.outpost_arn = subnet.get("OutpostArn")
                raw_subnet.enable_dns64 = subnet.get("EnableDns64")
                raw_subnet.ipv6_native = subnet.get("Ipv6Native")
                raw_subnet.private_dns_name_options_on_launch = subnet.get("PrivateDnsNameOptionsOnLaunch", None)

                subnets.append(raw_subnet)
                raw_subnet.vpc.subnets.append(raw_subnet)
        
        if pagination_token == None:
            break
    return subnets

def fetch_network_acl(ec2_client, subnets, vpcs):
    network_acls = []

    pagination_token = None
    while True:
        results = None
        if pagination_token == None:
            results = ec2_client.describe_network_acls()
        else:
            results = ec2_client.describe_network_acls(NextToken=pagination_token)
        if results != None:
            pagination_token = results.get("NextToken", None)

            for network_acl in results["NetworkAcls"]:
                raw_network_acl = AWS_Network_Acl()
                raw_network_acl.associations = []
                for association in network_acl.get("Associations", []):
                    subnet_id = association.get("SubnetId", None)
                    if subnet_id != None:
                        for subnet in subnets:
                            if subnet.subnet_id == subnet_id:
                                raw_network_acl.associations.append(subnet)
                                break
                raw_network_acl.entries = network_acl.get("Entries", None)
                raw_network_acl.is_default = network_acl.get("IsDefault")
                raw_network_acl.network_acl_id = network_acl.get("NetworkAclId")
                raw_network_acl.tags = network_acl.get("Tags", None)
                for vpc in vpcs:
                    if vpc.vpc_id == network_acl.get("VpcId"):
                        raw_network_acl.vpc = vpc
                        break
                raw_network_acl.owner_id = network_acl.get("OwnerId")

                network_acls.append(raw_network_acl)
        
        if pagination_token == None:
            break
    return network_acls

vpcs = fetch_vpc(ec2_client)
subnets = fetch_subnets(ec2_client, vpcs)
network_acls = fetch_network_acl(ec2_client, subnets, vpcs)
igws = fetch_internet_gateways(ec2_client, vpcs)
route_tables = fetch_route_tables(ec2_client, subnets, vpcs)
security_groups = fetch_security_groups(ec2_client, vpcs)

result_cloudformation_json = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Template based on resources as of: " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    "Parameters": {

    },
    "Resources": {

    }
}

for vpc in vpcs:
    res = vpc.to_cloudformation()
    for key in res:
        result_cloudformation_json["Resources"][key] = res[key]

for subnet in subnets:
    res = subnet.to_cloudformation()
    for key in res:
        result_cloudformation_json["Resources"][key] = res[key]

for igw in igws:
    res = igw.to_cloudformation()
    for key in res:
        result_cloudformation_json["Resources"][key] = res[key]

for nacl in network_acls:
    res = nacl.to_cloudformation()
    for key in res:
        result_cloudformation_json["Resources"][key] = res[key]

for route_table in route_tables:
    res = route_table.to_cloudformation(igws)
    for key in res:
        result_cloudformation_json["Resources"][key] = res[key]

for sg in security_groups:
    res = sg.to_cloudformation()
    for key in res:
        result_cloudformation_json["Resources"][key] = res[key]

print(result_cloudformation_json)

results_file = open("results.json", "w")
results_file.write(json.dumps(result_cloudformation_json, indent=4))
results_file.close()