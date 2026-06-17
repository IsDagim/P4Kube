/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

#include "include/headers.p4"

#define BUCKET_SIZE 6
#define COUNTER_WIDTH 16

#include "include/parsers.p4"

Register<bit<32>, bit<32>>(MAX_IPV4_ADDRESSES) ip_addresses;
Register<bit<32>, bit<32>>(MAX_IPV4_ADDRESSES) port_to_ip;
Register<bit<4>, bit<32>>(MAX_IPV4_ADDRESSES) quic_id_to_ip;
Register<bit<16>, bit<32>>(10) node_port;
Register<bit<16>, bit<32>>(10) replica_count;
Register<bit<32>, bit<32>>(10) virtual_ip;
Register<bit<32>, bit<32>>(100) replica_request_counter;
Register<bit<32>, bit<32>>(1) debug_hash_value;
Register<bit<32>, bit<32>>(1) debug_src_addr;
Register<bit<16>, bit<32>>(1) debug_src_port;

control SwitchIngress(
    inout headers hdr,
    inout metadata meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
) {
    bit<16> num_groups;
    bit<16> priv_port;

    Hash<bit<14>>(HashAlgorithm_t.CRC16) ecmp_hash;

    action ones_complement_sum(in bit<16> x, in bit<16> y, out bit<16> sum) {
        bit<17> ret = (bit<17>)x + (bit<17>)y;
        if (ret[16:16] == 1) {
            ret = ret + 1;
        }
        sum = ret[15:0];
    }

    action subtract(inout bit<16> sum, bit<16> d) {
        ones_complement_sum(sum, ~d, sum);
    }

    action subtract32(inout bit<16> sum, bit<32> d) {
        ones_complement_sum(sum, ~(bit<16>)d[15:0], sum);
        ones_complement_sum(sum, ~(bit<16>)d[31:16], sum);
    }

    action add(inout bit<16> sum, bit<16> d) {
        ones_complement_sum(sum, d, sum);
    }

    action add32(inout bit<16> sum, bit<32> d) {
        ones_complement_sum(sum, (bit<16>)d[15:0], sum);
        ones_complement_sum(sum, (bit<16>)d[31:16], sum);
    }

    action encode_and_replace(in bit<32> server_id, in bit<32> target_ip) {
        bit<16> sum = 0;
        subtract(sum, hdr.tcp.checksum);
        subtract(sum, hdr.tcp.srcPort);
        subtract32(sum, hdr.ipv4.srcAddr);
        subtract32(sum, hdr.timestamp.tsval);
        hdr.ipv4.srcAddr = target_ip;
        hdr.tcp.srcPort = 80;
        hdr.timestamp.tsval = (bit<32>)(hdr.timestamp.tsval & 0xfffffff0) + server_id;
        add32(sum, hdr.ipv4.srcAddr);
        add32(sum, hdr.timestamp.tsval);
        add(sum, hdr.tcp.srcPort);
        hdr.tcp.checksum = ~sum;
    }

    action decode() {
        meta.port_id = (bit<32>)hdr.timestamp.tsecr & 15;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action ipv4_forward(macAddr_t dstAddr, PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        bit<32> target_ip1 = 0x0A000002;
        bit<32> target_ip2 = 0x0A000003;
        bit<32> target_ip3 = 0x0A000004;
        bit<32> target_ip4 = 0x0A000005;
        bit<32> target_ip5 = 0x0A000006;
        bit<32> target_ip6 = 0x0A000007;
        bit<32> target_ip7 = 0x0A000008;
        bit<32> target_ip8 = 0x0A000009;
        bit<32> target_ip9 = 0x0A00000A;
        bit<32> target_ip10 = 0x0A00000B;

        bit<16> node_port_0;
        bit<16> node_port_1;
        bit<16> node_port_2;
        bit<16> node_port_3;
        bit<16> node_port_4;
        bit<16> node_port_5;
        bit<16> node_port_6;
        bit<16> node_port_7;
        bit<16> node_port_8;
        bit<16> node_port_9;

        node_port_0 = node_port.read((bit<32>)0);
        node_port_1 = node_port.read((bit<32>)1);
        node_port_2 = node_port.read((bit<32>)2);
        node_port_3 = node_port.read((bit<32>)3);
        node_port_4 = node_port.read((bit<32>)4);
        node_port_5 = node_port.read((bit<32>)5);
        node_port_6 = node_port.read((bit<32>)6);
        node_port_7 = node_port.read((bit<32>)7);
        node_port_8 = node_port.read((bit<32>)8);
        node_port_9 = node_port.read((bit<32>)9);

        bit<32> subnet_mask = 0xFFFFFF00;
        bit<32> subnet_prefix = 0x0A000000;

        if (hdr.quic.isValid() && ((hdr.ipv4.dstAddr & subnet_mask) == subnet_prefix)) {
            if ((hdr.quic.hdr_type == 1) && (hdr.quic.pkt_type == (bit<2>)0)) {
                bit<32> replica_offset = 0;
                bit<32> base_ip = 0;
                bit<32> node_port_index = 0;
                bit<32> replica_counter_value = 0;
                bit<32> dpl = hdr.ipv4.dstAddr & 15;

                num_groups = 0;
                node_port_index = dpl - 2;
                replica_offset = (dpl - 2) * 10;
                base_ip = hdr.ipv4.dstAddr;
                num_groups = replica_count.read(dpl - 2);

                if (num_groups == 0) {
                    drop();
                }

                bit<14> raw_hash_udp = ecmp_hash.get({
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.udp.srcPort,
                    hdr.udp.dstPort,
                    hdr.ipv4.protocol,
                    base_ip
                });

                bit<4> h_udp = raw_hash_udp[3:0];

                if (num_groups == 1) {
                    meta.ecmpHash = 0;
                } else if (num_groups == 2) {
                    meta.ecmpHash = (bit<14>)h_udp[0:0];
                } else if (num_groups == 3) {
                    if (h_udp < 5) {
                        meta.ecmpHash = 0;
                    } else if (h_udp < 10) {
                        meta.ecmpHash = 1;
                    } else {
                        meta.ecmpHash = 2;
                    }
                } else if (num_groups == 4) {
                    meta.ecmpHash = (bit<14>)h_udp[1:0];
                } else if (num_groups == 5) {
                    if (h_udp < 3) {
                        meta.ecmpHash = 0;
                    } else if (h_udp < 6) {
                        meta.ecmpHash = 1;
                    } else if (h_udp < 9) {
                        meta.ecmpHash = 2;
                    } else if (h_udp < 12) {
                        meta.ecmpHash = 3;
                    } else {
                        meta.ecmpHash = 4;
                    }
                } else if (num_groups == 6) {
                    if (h_udp < 3) {
                        meta.ecmpHash = 0;
                    } else if (h_udp < 6) {
                        meta.ecmpHash = 1;
                    } else if (h_udp < 9) {
                        meta.ecmpHash = 2;
                    } else if (h_udp < 12) {
                        meta.ecmpHash = 3;
                    } else if (h_udp < 14) {
                        meta.ecmpHash = 4;
                    } else {
                        meta.ecmpHash = 5;
                    }
                } else if (num_groups == 7) {
                    if (h_udp < 2) {
                        meta.ecmpHash = 0;
                    } else if (h_udp < 4) {
                        meta.ecmpHash = 1;
                    } else if (h_udp < 6) {
                        meta.ecmpHash = 2;
                    } else if (h_udp < 8) {
                        meta.ecmpHash = 3;
                    } else if (h_udp < 10) {
                        meta.ecmpHash = 4;
                    } else if (h_udp < 12) {
                        meta.ecmpHash = 5;
                    } else {
                        meta.ecmpHash = 6;
                    }
                } else if (num_groups == 8) {
                    meta.ecmpHash = (bit<14>)h_udp[2:0];
                } else if (num_groups == 9) {
                    if (h_udp < 2) {
                        meta.ecmpHash = 0;
                    } else if (h_udp < 4) {
                        meta.ecmpHash = 1;
                    } else if (h_udp < 6) {
                        meta.ecmpHash = 2;
                    } else if (h_udp < 8) {
                        meta.ecmpHash = 3;
                    } else if (h_udp < 10) {
                        meta.ecmpHash = 4;
                    } else if (h_udp < 12) {
                        meta.ecmpHash = 5;
                    } else if (h_udp < 13) {
                        meta.ecmpHash = 6;
                    } else if (h_udp < 14) {
                        meta.ecmpHash = 7;
                    } else {
                        meta.ecmpHash = 8;
                    }
                } else {
                    if (h_udp < 2) {
                        meta.ecmpHash = 0;
                    } else if (h_udp < 4) {
                        meta.ecmpHash = 1;
                    } else if (h_udp < 6) {
                        meta.ecmpHash = 2;
                    } else if (h_udp < 8) {
                        meta.ecmpHash = 3;
                    } else if (h_udp < 10) {
                        meta.ecmpHash = 4;
                    } else if (h_udp < 11) {
                        meta.ecmpHash = 5;
                    } else if (h_udp < 12) {
                        meta.ecmpHash = 6;
                    } else if (h_udp < 13) {
                        meta.ecmpHash = 7;
                    } else if (h_udp < 14) {
                        meta.ecmpHash = 8;
                    } else {
                        meta.ecmpHash = 9;
                    }
                }

                bit<32> replica_index = replica_offset + (bit<32>)meta.ecmpHash;

                bit<16> sum = 0;
                subtract(sum, hdr.udp.checksum);
                subtract(sum, hdr.udp.dstPort);
                subtract32(sum, hdr.ipv4.dstAddr);

                hdr.ipv4.dstAddr = ip_addresses.read(replica_index);
                hdr.udp.dstPort = node_port.read(node_port_index);

                add32(sum, hdr.ipv4.dstAddr);
                add(sum, hdr.udp.dstPort);
                hdr.udp.checksum = ~sum;

                ipv4_lpm.apply();
            }
        } else if (hdr.tcp.isValid() && hdr.tcp.dstPort == 80 && ((hdr.ipv4.dstAddr & subnet_mask) == subnet_prefix)) {
            bit<32> replica_offset = 0;
            bit<32> base_ip = 0;
            bit<32> node_port_index = 0;
            bit<32> replica_counter_value = 0;
            bit<32> dpl = hdr.ipv4.dstAddr & 15;

            num_groups = 0;
            node_port_index = dpl - 2;
            replica_offset = (dpl - 2) * 10;
            base_ip = hdr.ipv4.dstAddr;
            num_groups = replica_count.read(dpl - 2);

            if (num_groups == 0) {
                drop();
            } else if (hdr.tcp.syn == 0 && hdr.timestamp.isValid()) {
                decode();

                bit<16> sum = 0;
                subtract(sum, hdr.tcp.checksum);
                subtract(sum, hdr.tcp.dstPort);
                subtract32(sum, hdr.ipv4.dstAddr);

                hdr.tcp.dstPort = node_port.read(node_port_index);
                hdr.ipv4.dstAddr = port_to_ip.read(meta.port_id);

                add32(sum, hdr.ipv4.dstAddr);
                add(sum, hdr.tcp.dstPort);
                hdr.tcp.checksum = ~sum;

                ipv4_lpm.apply();
            } else {
                bit<14> raw_hash_tcp = ecmp_hash.get({
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort,
                    hdr.ipv4.protocol,
                    base_ip
                });

                bit<4> h_tcp = raw_hash_tcp[3:0];

                if (num_groups == 1) {
                    meta.ecmpHash = 0;
                } else if (num_groups == 2) {
                    meta.ecmpHash = (bit<14>)h_tcp[0:0];
                } else if (num_groups == 3) {
                    if (h_tcp < 5) {
                        meta.ecmpHash = 0;
                    } else if (h_tcp < 10) {
                        meta.ecmpHash = 1;
                    } else {
                        meta.ecmpHash = 2;
                    }
                } else if (num_groups == 4) {
                    meta.ecmpHash = (bit<14>)h_tcp[1:0];
                } else if (num_groups == 5) {
                    if (h_tcp < 3) {
                        meta.ecmpHash = 0;
                    } else if (h_tcp < 6) {
                        meta.ecmpHash = 1;
                    } else if (h_tcp < 9) {
                        meta.ecmpHash = 2;
                    } else if (h_tcp < 12) {
                        meta.ecmpHash = 3;
                    } else {
                        meta.ecmpHash = 4;
                    }
                } else if (num_groups == 6) {
                    if (h_tcp < 3) {
                        meta.ecmpHash = 0;
                    } else if (h_tcp < 6) {
                        meta.ecmpHash = 1;
                    } else if (h_tcp < 9) {
                        meta.ecmpHash = 2;
                    } else if (h_tcp < 12) {
                        meta.ecmpHash = 3;
                    } else if (h_tcp < 14) {
                        meta.ecmpHash = 4;
                    } else {
                        meta.ecmpHash = 5;
                    }
                } else if (num_groups == 7) {
                    if (h_tcp < 2) {
                        meta.ecmpHash = 0;
                    } else if (h_tcp < 4) {
                        meta.ecmpHash = 1;
                    } else if (h_tcp < 6) {
                        meta.ecmpHash = 2;
                    } else if (h_tcp < 8) {
                        meta.ecmpHash = 3;
                    } else if (h_tcp < 10) {
                        meta.ecmpHash = 4;
                    } else if (h_tcp < 12) {
                        meta.ecmpHash = 5;
                    } else {
                        meta.ecmpHash = 6;
                    }
                } else if (num_groups == 8) {
                    meta.ecmpHash = (bit<14>)h_tcp[2:0];
                } else if (num_groups == 9) {
                    if (h_tcp < 2) {
                        meta.ecmpHash = 0;
                    } else if (h_tcp < 4) {
                        meta.ecmpHash = 1;
                    } else if (h_tcp < 6) {
                        meta.ecmpHash = 2;
                    } else if (h_tcp < 8) {
                        meta.ecmpHash = 3;
                    } else if (h_tcp < 10) {
                        meta.ecmpHash = 4;
                    } else if (h_tcp < 12) {
                        meta.ecmpHash = 5;
                    } else if (h_tcp < 13) {
                        meta.ecmpHash = 6;
                    } else if (h_tcp < 14) {
                        meta.ecmpHash = 7;
                    } else {
                        meta.ecmpHash = 8;
                    }
                } else {
                    if (h_tcp < 2) {
                        meta.ecmpHash = 0;
                    } else if (h_tcp < 4) {
                        meta.ecmpHash = 1;
                    } else if (h_tcp < 6) {
                        meta.ecmpHash = 2;
                    } else if (h_tcp < 8) {
                        meta.ecmpHash = 3;
                    } else if (h_tcp < 10) {
                        meta.ecmpHash = 4;
                    } else if (h_tcp < 11) {
                        meta.ecmpHash = 5;
                    } else if (h_tcp < 12) {
                        meta.ecmpHash = 6;
                    } else if (h_tcp < 13) {
                        meta.ecmpHash = 7;
                    } else if (h_tcp < 14) {
                        meta.ecmpHash = 8;
                    } else {
                        meta.ecmpHash = 9;
                    }
                }

                bit<32> replica_index = replica_offset + (bit<32>)meta.ecmpHash;

                bit<16> sum = 0;
                subtract(sum, hdr.tcp.checksum);
                subtract(sum, hdr.tcp.dstPort);
                subtract32(sum, hdr.ipv4.dstAddr);

                hdr.ipv4.dstAddr = ip_addresses.read(replica_index);

                replica_counter_value = 0;
                replica_counter_value = replica_request_counter.read(replica_index);
                replica_counter_value = replica_counter_value + 1;
                replica_request_counter.write(replica_index, replica_counter_value);

                hdr.tcp.dstPort = node_port.read(node_port_index);

                add32(sum, hdr.ipv4.dstAddr);
                add(sum, hdr.tcp.dstPort);
                hdr.tcp.checksum = ~sum;

                ipv4_lpm.apply();
            }
        } else if (hdr.tcp.isValid()) {
            debug_src_addr.write(0, hdr.ipv4.srcAddr);
            debug_src_port.write(0, hdr.tcp.srcPort);

            bit<32> server_id = (bit<32>)ig_intr_md.ingress_port;
            port_to_ip.write(server_id, hdr.ipv4.srcAddr);

            bit<32> target_ip = 0;

            if (hdr.tcp.srcPort == node_port_0) {
                target_ip = target_ip1;
            } else if (hdr.tcp.srcPort == node_port_1) {
                target_ip = target_ip2;
            } else if (hdr.tcp.srcPort == node_port_2) {
                target_ip = target_ip3;
            } else if (hdr.tcp.srcPort == node_port_3) {
                target_ip = target_ip4;
            } else if (hdr.tcp.srcPort == node_port_4) {
                target_ip = target_ip5;
            } else if (hdr.tcp.srcPort == node_port_5) {
                target_ip = target_ip6;
            } else if (hdr.tcp.srcPort == node_port_6) {
                target_ip = target_ip7;
            } else if (hdr.tcp.srcPort == node_port_7) {
                target_ip = target_ip8;
            } else if (hdr.tcp.srcPort == node_port_8) {
                target_ip = target_ip9;
            } else if (hdr.tcp.srcPort == node_port_9) {
                target_ip = target_ip10;
            }

            if (target_ip != 0) {
                encode_and_replace(server_id, target_ip);
            }

            ipv4_lpm.apply();
        } else if (hdr.info.isValid()) {
            bit<32> offset = 0;

            if (hdr.info.virtualIP == 0x0a000002) {
                offset = 0;
            } else if (hdr.info.virtualIP == 0x0a000003) {
                offset = 10;
            } else if (hdr.info.virtualIP == 0x0a000004) {
                offset = 20;
            } else if (hdr.info.virtualIP == 0x0a000005) {
                offset = 30;
            } else if (hdr.info.virtualIP == 0x0a000006) {
                offset = 40;
            } else if (hdr.info.virtualIP == 0x0a000007) {
                offset = 50;
            } else if (hdr.info.virtualIP == 0x0a000008) {
                offset = 60;
            } else if (hdr.info.virtualIP == 0x0a000009) {
                offset = 70;
            } else if (hdr.info.virtualIP == 0x0a00000A) {
                offset = 80;
            } else if (hdr.info.virtualIP == 0x0a00000B) {
                offset = 90;
            } else {
                drop();
            }

            if (offset == 0) {
                virtual_ip.write(0, hdr.info.virtualIP);
                node_port.write(0, hdr.info.port);
                replica_count.write(0, hdr.info.replicas);
            } else if (offset == 10) {
                virtual_ip.write(1, hdr.info.virtualIP);
                node_port.write(1, hdr.info.port);
                replica_count.write(1, hdr.info.replicas);
            } else if (offset == 20) {
                virtual_ip.write(2, hdr.info.virtualIP);
                node_port.write(2, hdr.info.port);
                replica_count.write(2, hdr.info.replicas);
            } else if (offset == 30) {
                virtual_ip.write(3, hdr.info.virtualIP);
                node_port.write(3, hdr.info.port);
                replica_count.write(3, hdr.info.replicas);
            } else if (offset == 40) {
                virtual_ip.write(4, hdr.info.virtualIP);
                node_port.write(4, hdr.info.port);
                replica_count.write(4, hdr.info.replicas);
            } else if (offset == 50) {
                virtual_ip.write(5, hdr.info.virtualIP);
                node_port.write(5, hdr.info.port);
                replica_count.write(5, hdr.info.replicas);
            } else if (offset == 60) {
                virtual_ip.write(6, hdr.info.virtualIP);
                node_port.write(6, hdr.info.port);
                replica_count.write(6, hdr.info.replicas);
            } else if (offset == 70) {
                virtual_ip.write(7, hdr.info.virtualIP);
                node_port.write(7, hdr.info.port);
                replica_count.write(7, hdr.info.replicas);
            } else if (offset == 80) {
                virtual_ip.write(8, hdr.info.virtualIP);
                node_port.write(8, hdr.info.port);
                replica_count.write(8, hdr.info.replicas);
            } else if (offset == 90) {
                virtual_ip.write(9, hdr.info.virtualIP);
                node_port.write(9, hdr.info.port);
                replica_count.write(9, hdr.info.replicas);
            }

            if (hdr.info.replicas >= 1) {
                ip_addresses.write(offset + 0, hdr.ips[0].ipAddress);
            }
            if (hdr.info.replicas >= 2) {
                ip_addresses.write(offset + 1, hdr.ips[1].ipAddress);
            }
            if (hdr.info.replicas >= 3) {
                ip_addresses.write(offset + 2, hdr.ips[2].ipAddress);
            }
            if (hdr.info.replicas >= 4) {
                ip_addresses.write(offset + 3, hdr.ips[3].ipAddress);
            }
            if (hdr.info.replicas >= 5) {
                ip_addresses.write(offset + 4, hdr.ips[4].ipAddress);
            }
            if (hdr.info.replicas >= 6) {
                ip_addresses.write(offset + 5, hdr.ips[5].ipAddress);
            }
            if (hdr.info.replicas >= 7) {
                ip_addresses.write(offset + 6, hdr.ips[6].ipAddress);
            }
            if (hdr.info.replicas >= 8) {
                ip_addresses.write(offset + 7, hdr.ips[7].ipAddress);
            }
            if (hdr.info.replicas >= 9) {
                ip_addresses.write(offset + 8, hdr.ips[8].ipAddress);
            }
            if (hdr.info.replicas >= 10) {
                ip_addresses.write(offset + 9, hdr.ips[9].ipAddress);
            }
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

control SwitchEgress(
    inout headers hdr,
    inout metadata meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md
) {
    apply { }
}

control SwitchIngressDeparser(
    packet_out packet,
    inout headers hdr,
    in metadata meta,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.quic);
        packet.emit(hdr.nop1);
        packet.emit(hdr.nop2);
        packet.emit(hdr.ss);
        packet.emit(hdr.nop3);
        packet.emit(hdr.sackw);
        packet.emit(hdr.sack);
        packet.emit(hdr.nop4);
        packet.emit(hdr.timestamp);
    }
}

control SwitchEgressDeparser(
    packet_out packet,
    inout headers hdr,
    in metadata meta,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md
) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.quic);
        packet.emit(hdr.nop1);
        packet.emit(hdr.nop2);
        packet.emit(hdr.ss);
        packet.emit(hdr.nop3);
        packet.emit(hdr.sackw);
        packet.emit(hdr.sack);
        packet.emit(hdr.nop4);
        packet.emit(hdr.timestamp);
    }
}

Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;
