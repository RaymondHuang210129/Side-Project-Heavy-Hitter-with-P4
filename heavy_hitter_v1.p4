//////////////////////////////////////////////////////
//header def
//////////////////////////////////////////////////////
header_type ethernet_t
{
	fields
	{
		dstAddr:	48;
		srcAddr:	48;
		ethertype:	16;
	}
}
header_type ipv4_t
{
	fields
	{
		version:		4;
		ihl:			4;
        diffserv:		8;
        totalLen:		16;
        identification:	16;
        flags:			3;
        fragOffset:		13;
        ttl:			8;
        protocol:		8;
        hdrChecksum:	16;
        srcAddr:		32;
        dstAddr:		32;
        options:		*;
	}
	length: ihl * 4;
	max_length: 60;
}
header_type udp_t
{
	fields
	{
		src_port:	16;
		dst_port:	16;
		len:		16;
		checksum:	16;
	}
}

header_type packet_metadata_t
{
	fields
	{
		hashed_key:	4; //table size: 15
		udp_src_ip: 16;
		key_buf:	4;
		ip_buf:		16;
		count_buf:	10;
		count_buf2:	10;
		is_init:	1;
	}
}

///////////////////////////////////////////////////////
//header instantiate
///////////////////////////////////////////////////////

header ethernet_t ethernet;
header ipv4_t ipv4;
header udp_t udp;
metadata packet_metadata_t packet_metadata;

///////////////////////////////////////////////////////
//parser
///////////////////////////////////////////////////////

parser start
{
	return ethernet;
}
parser ethernet
{
	extract(ethernet);
	return select(latest.ethertype)
	{
		0x800:		ipv4_is_init;
		default:	ingress;
	}
}
parser ipv4_is_init
{
	extract(ipv4);
	return select(latest.ihl)
	{
		0x06:		ingress;
		default:	ipv4;
	}
}
parser ipv4
{
	return select(latest.protocal)
	{
		0x11:		udp;
		default:	ingress;
	}
}
parser udp
{
	extract(udp);
	return select(latest.len)
	{
		default:	ingress;
	}
}

////////////////////////////////////////////////
//register
////////////////////////////////////////////////

register addr_table_1
{
	width:	16;
	instance_count:	16;
}
register addr_table_2
{
	width:	16;
	instance_count:	16;
}
register addr_table_3
{
	width:	16;
	instance_count:	16;
}
register addr_table_4
{
	width:	16;
	instance_count:	16;
}
register count_table_1
{
	width:	10;
	instance_count:16;
	saturating;
}
register count_table_2
{
	width:	10;
	instance_count:16;
	saturating;
}
register count_table_3
{
	width:	10;
	instance_count:16;
	saturating;
}
register count_table_4
{
	width:	10;
	instance_count:16;
	saturating;
}

////////////////////////////////////////////////////////
//calculation
////////////////////////////////////////////////////////
field_list udp_source_field
{
	packet_metadata.udp_src_ip;
}
field_list_calculation hash_function_1
{
	input
	{
		udp_source_field;
	}
	algorithm: xor16;
	output_width: 16;
}
field_list_calculation hash_function_2
{
	input
	{
		udp_source_field;
	}
	algorithm: csum16;
	output_width: 16;
}
field_list_calculation hash_function_3
{
	input
	{
		udp_source_field;
	}
	algorithm: crc16;
	output_width: 16;
}
field_list_calculation hash_function_4
{
	input
	{
		udp_source_field;
	}
	algorithm: crc32;
	output_width: 16;
}
field_list_calculation ipv4_checksum
{
    input 
    {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}
calculated_field ipv4.hdrChecksum  
{
    verify ipv4_checksum;
    update ipv4_checksum;
}
action _drop() 
{
    drop();
}
////////////////////////////////////////////////////////
//table & action
////////////////////////////////////////////////////////

action replace_table_1()
{
	modify_field(packet_metadata.is_init, 0);
	modify_field(packet_metadata.udp_src_ip, udp.src_port); //(dest, value)
	modify_field_with_hash_based_offset(packet_metadata.hashed_key, 0, hash_function_1, 16); //(dest, base, field_list_calc, size)
	register_read(packet_metadata.ip_buf, addr_table_1, packet_metadata.hashed_key);
	if(packet_metadata.ip_buf == 0)
	{
		register_write(addr_table_1, packet_metadata.hashed_key, packet_metadata.ip_buf);
		register_write(count_table_1, packet_metadata.hashed_key, 1);
	}
	else if(packet_metadata.ip_buf == packet_metadata.udp_src_ip)
	{
		register_read(packet_metadata.count_buf, count_table_1, packet_metadata.hashed_key);
		register_write(count_table_1, packet_metadata.hashed_key, packet_metadata.count_buf + 1);
	}
	else
	{
		register_read(packet_metadata.ip_buf, addr_table_1, packet_metadata.hashed_key);
		register_read(packet_metadata.count_buf, count_table_1, packet_metadata.hashed_key);
		register_write(addr_table_1, packet_metadata.hashed_key, packet_metadata.udp_src_ip);
		register_write(count_table_1, packet_metadata.hashed_key, 1);
	}
}
action replace_table_2()
{
	if(packet_metadata.ip_buf == packet_metadata.udp_src_ip)
	{
		no_op();
	}
	else
	{
		modify_field(packet_metadata.udp_src_ip, packet_metadata.ip_buf);
		modify_field_with_hash_based_offset(packet_metadata.hashed_key, 0, hash_function_2, 16);
		register_read(packet_metadata.ip_buf, addr_table_2, packet_metadata.hashed_key);
		register_read(packet_metadata.count_buf, count_table_2, packet_metadata.hashed_key);
		if(packet_metadata.ip_buf == 0)
		{
			register_write(addr_table_2, packet_metadata.hashed_key, packet_metadata.ip_buf);
			register_write(count_table_2, packet_metadata.hashed_key, 1);
		}
		else if(packet_metadata.ip_buf == packet_metadata.udp_src_ip)
		{
			register_read(packet_metadata.count_buf2, count_table_2, packet_metadata.hashed_key);
			register_write(count_table_2, packet_metadata.hashed_key, packet_metadata.count_buf + packet_metadata.count_buf2);
		}
		else
		{
			register_read(packet_metadata.count_buf2, count_table_2, packet_metadata.hashed_key);
			if(packet_metadata.count_buf2 < packet_metadata.count_buf)
			{
				register_read(packet_metadata.ip_buf, addr_table_2, packet_metadata.hashed_key);
				register_write(addr_table_2, packet_metadata.hashed_key, packet_metadata.udp_src_ip);
				register_write(count_table_2, packet_metadata.hashed_key, packet_metadata.count_buf);
				modify_field(packet_metadata.count_buf, packet_metadata.count_buf2);
			}
			else
			{
				no_op();
			}
		}
	}
}
action replace_table_3()
{
	if(packet_metadata.ip_buf == packet_metadata.udp_src_ip)
	{
		no_op();
	}
	else
	{
		modify_field(packet_metadata.udp_src_ip, packet_metadata.ip_buf);
		modify_field_with_hash_based_offset(packet_metadata.hashed_key, 0, hash_function_3, 16);
		register_read(packet_metadata.ip_buf, addr_table_3, packet_metadata.hashed_key);
		register_read(packet_metadata.count_buf, count_table_3, packet_metadata.hashed_key);
		if(packet_metadata.ip_buf == 0)
		{
			register_write(addr_table_3, packet_metadata.hashed_key, packet_metadata.ip_buf);
			register_write(count_table_3, packet_metadata.hashed_key, 1);
		}
		else if(packet_metadata.ip_buf == packet_metadata.udp_src_ip)
		{
			register_read(packet_metadata.count_buf2, count_table_3, packet_metadata.hashed_key);
			register_write(count_table_3, packet_metadata.hashed_key, packet_metadata.count_buf + packet_metadata.count_buf2);
		}
		else
		{
			register_read(packet_metadata.count_buf2, count_table_3, packet_metadata.hashed_key);
			if(packet_metadata.count_buf2 < packet_metadata.count_buf)
			{
				register_read(packet_metadata.ip_buf, addr_table_3, packet_metadata.hashed_key);
				register_write(addr_table_3, packet_metadata.hashed_key, packet_metadata.udp_src_ip);
				register_write(count_table_3, packet_metadata.hashed_key, packet_metadata.count_buf);
				modify_field(packet_metadata.count_buf, packet_metadata.count_buf2);
			}
			else
			{
				no_op();
			}
		}
	}
}
action replace_table_4()
{
	if(packet_metadata.ip_buf == packet_metadata.udp_src_ip)
	{
		no_op();
	}
	else
	{
		modify_field(packet_metadata.udp_src_ip, packet_metadata.ip_buf);
		modify_field_with_hash_based_offset(packet_metadata.hashed_key, 0, hash_function_4, 16);
		register_read(packet_metadata.ip_buf, addr_table_4, packet_metadata.hashed_key);
		register_read(packet_metadata.count_buf, count_table_4, packet_metadata.hashed_key);
		if(packet_metadata.ip_buf == 0)
		{
			register_write(addr_table_4, packet_metadata.hashed_key, packet_metadata.ip_buf);
			register_write(count_table_4, packet_metadata.hashed_key, 1);
		}
		else if(packet_metadata.ip_buf == packet_metadata.udp_src_ip)
		{
			register_read(packet_metadata.count_buf2, count_table_4, packet_metadata.hashed_key);
			register_write(count_table_4, packet_metadata.hashed_key, packet_metadata.count_buf + packet_metadata.count_buf2);
		}
		else
		{
			register_read(packet_metadata.count_buf2, count_table_4, packet_metadata.hashed_key);
			if(packet_metadata.count_buf2 < packet_metadata.count_buf)
			{
				register_read(packet_metadata.ip_buf, addr_table_4, packet_metadata.hashed_key);
				register_write(addr_table_4, packet_metadata.hashed_key, packet_metadata.udp_src_ip);
				register_write(count_table_4, packet_metadata.hashed_key, packet_metadata.count_buf);
				modify_field(packet_metadata.count_buf, packet_metadata.count_buf2);
			}
			else
			{
				no_op();
			}
		}
	}
}
action reset_register()
{
	modify_field(packet_metadata.is_init, 1);
	register_write(addr_table_1, 0, 0);
	register_write(addr_table_1, 1, 0);
	register_write(addr_table_1, 2, 0);
	register_write(addr_table_1, 3, 0);
	register_write(addr_table_1, 4, 0);
	register_write(addr_table_1, 5, 0);
	register_write(addr_table_1, 6, 0);
	register_write(addr_table_1, 7, 0);
	register_write(addr_table_1, 8, 0);
	register_write(addr_table_1, 9, 0);
	register_write(addr_table_1, 10, 0);
	register_write(addr_table_1, 11, 0);
	register_write(addr_table_1, 12, 0);
	register_write(addr_table_1, 13, 0);
	register_write(addr_table_1, 14, 0);
	register_write(addr_table_1, 15, 0);
	register_write(addr_table_2, 0, 0);
	register_write(addr_table_2, 1, 0);
	register_write(addr_table_2, 2, 0);
	register_write(addr_table_2, 3, 0);
	register_write(addr_table_2, 4, 0);
	register_write(addr_table_2, 5, 0);
	register_write(addr_table_2, 6, 0);
	register_write(addr_table_2, 7, 0);
	register_write(addr_table_2, 8, 0);
	register_write(addr_table_2, 9, 0);
	register_write(addr_table_2, 10, 0);
	register_write(addr_table_2, 11, 0);
	register_write(addr_table_2, 12, 0);
	register_write(addr_table_2, 13, 0);
	register_write(addr_table_2, 14, 0);
	register_write(addr_table_2, 15, 0);
	register_write(addr_table_3, 0, 0);
	register_write(addr_table_3, 1, 0);
	register_write(addr_table_3, 2, 0);
	register_write(addr_table_3, 3, 0);
	register_write(addr_table_3, 4, 0);
	register_write(addr_table_3, 5, 0);
	register_write(addr_table_3, 6, 0);
	register_write(addr_table_3, 7, 0);
	register_write(addr_table_3, 8, 0);
	register_write(addr_table_3, 9, 0);
	register_write(addr_table_3, 10, 0);
	register_write(addr_table_3, 11, 0);
	register_write(addr_table_3, 12, 0);
	register_write(addr_table_3, 13, 0);
	register_write(addr_table_3, 14, 0);
	register_write(addr_table_3, 15, 0);
	register_write(addr_table_4, 0, 0);
	register_write(addr_table_4, 1, 0);
	register_write(addr_table_4, 2, 0);
	register_write(addr_table_4, 3, 0);
	register_write(addr_table_4, 4, 0);
	register_write(addr_table_4, 5, 0);
	register_write(addr_table_4, 6, 0);
	register_write(addr_table_4, 7, 0);
	register_write(addr_table_4, 8, 0);
	register_write(addr_table_4, 9, 0);
	register_write(addr_table_4, 10, 0);
	register_write(addr_table_4, 11, 0);
	register_write(addr_table_4, 12, 0);
	register_write(addr_table_4, 13, 0);
	register_write(addr_table_4, 14, 0);
	register_write(addr_table_4, 15, 0);
	register_write(count_table_1, 0, 0);
	register_write(count_table_1, 1, 0);
	register_write(count_table_1, 2, 0);
	register_write(count_table_1, 3, 0);
	register_write(count_table_1, 4, 0);
	register_write(count_table_1, 5, 0);
	register_write(count_table_1, 6, 0);
	register_write(count_table_1, 7, 0);
	register_write(count_table_1, 8, 0);
	register_write(count_table_1, 9, 0);
	register_write(count_table_1, 10, 0);
	register_write(count_table_1, 11, 0);
	register_write(count_table_1, 12, 0);
	register_write(count_table_1, 13, 0);
	register_write(count_table_1, 14, 0);
	register_write(count_table_1, 15, 0);
	register_write(count_table_2, 0, 0);
	register_write(count_table_2, 1, 0);
	register_write(count_table_2, 2, 0);
	register_write(count_table_2, 3, 0);
	register_write(count_table_2, 4, 0);
	register_write(count_table_2, 5, 0);
	register_write(count_table_2, 6, 0);
	register_write(count_table_2, 7, 0);
	register_write(count_table_2, 8, 0);
	register_write(count_table_2, 9, 0);
	register_write(count_table_2, 10, 0);
	register_write(count_table_2, 11, 0);
	register_write(count_table_2, 12, 0);
	register_write(count_table_2, 13, 0);
	register_write(count_table_2, 14, 0);
	register_write(count_table_2, 15, 0);
	register_write(count_table_3, 0, 0);
	register_write(count_table_3, 1, 0);
	register_write(count_table_3, 2, 0);
	register_write(count_table_3, 3, 0);
	register_write(count_table_3, 4, 0);
	register_write(count_table_3, 5, 0);
	register_write(count_table_3, 6, 0);
	register_write(count_table_3, 7, 0);
	register_write(count_table_3, 8, 0);
	register_write(count_table_3, 9, 0);
	register_write(count_table_3, 10, 0);
	register_write(count_table_3, 11, 0);
	register_write(count_table_3, 12, 0);
	register_write(count_table_3, 13, 0);
	register_write(count_table_3, 14, 0);
	register_write(count_table_3, 15, 0);
	register_write(count_table_4, 0, 0);
	register_write(count_table_4, 1, 0);
	register_write(count_table_4, 2, 0);
	register_write(count_table_4, 3, 0);
	register_write(count_table_4, 4, 0);
	register_write(count_table_4, 5, 0);
	register_write(count_table_4, 6, 0);
	register_write(count_table_4, 7, 0);
	register_write(count_table_4, 8, 0);
	register_write(count_table_4, 9, 0);
	register_write(count_table_4, 10, 0);
	register_write(count_table_4, 11, 0);
	register_write(count_table_4, 12, 0);
	register_write(count_table_4, 13, 0);
	register_write(count_table_4, 14, 0);
	register_write(count_table_4, 15, 0);

}
action set_nhop(nhop_ipv4, port)
{
    modify_field(custom_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}
table ipv4_lpm
{
    reads
    {
        ipv4.dstAddr : lpm;
    }
	actions
	{
        set_nhop;
        _drop;
    }
    size: 1024;
}
table process
{
	actions
	{
		replace_table_1;
		replace_table_2;
		replace_table_3;
		replace_table_4;
	}
}
table init
{
	actions
	{
		reset_register;
	}
}
action set_dmac(dmac)
{
    modify_field(ethernet.dstAddr, dmac);
}
table forward
{
    reads
    {
        custom_metadata.nhop_ipv4 : exact;
    }
    actions
    {
        set_dmac;
        _drop;
    }
    size: 512;
}
action rewrite_mac(smac)
{
    modify_field(ethernet.srcAddr, smac);
}
table send_frame
{
    reads
    {
        standard_metadata.egress_port: exact;
    }
    actions
    {
        rewrite_mac;
        _drop;
    }
    size: 256;
}
///////////////////////////////////////////////////////////
//ingress & egress
///////////////////////////////////////////////////////////
control ingress
{
	if(ipv4.ihl == 0x06)
	{
		apply(init);
	}
	if(valid(udp))
	{
		apply(process);
		apply(ipv4_lpm);
		apply(forward);
	}
}
control egress
{
    if(packet_metadata.is_init == 0)
    {
    	apply(send_frame);
    }
    else
    {
    	drop();
    }
}