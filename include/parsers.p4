parser SwitchIngressParser(
    packet_in packet,
    out headers hdr,
    out metadata meta,
    out ingress_intrinsic_metadata_t ig_intr_md
) {
    bit<16> number_replicas_remaining_to_parse;

    state start {
        packet.extract(ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.tcpLength = hdr.ipv4.totalLen - 20;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort, hdr.udp.srcPort) {
            (7777, _): parse_info;
            (_, 4433): parse_quic;
            (4433, _): parse_quic;
            default: accept;
        }
    }

    state parse_quic {
        packet.extract(hdr.quic);
        transition accept;
    }

    state parse_info {
        packet.extract(hdr.info);
        verify(hdr.info.replicas <= 10, error.BadReplicaCount);
        number_replicas_remaining_to_parse = hdr.info.replicas;
        transition select(hdr.info.replicas) {
            1: parse_ips;
            2: parse_ips;
            3: parse_ips;
            4: parse_ips;
            5: parse_ips;
            6: parse_ips;
            7: parse_ips;
            8: parse_ips;
            9: parse_ips;
            10: parse_ips;
            default: accept;
        }
    }

    state parse_ips {
        packet.extract(hdr.ips.next);
        number_replicas_remaining_to_parse = number_replicas_remaining_to_parse - 1;
        transition select(number_replicas_remaining_to_parse) {
            0: accept;
            default: parse_ips;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        packet.extract(hdr.nop1);
        transition select(hdr.nop1.kind) {
            1: parse_nop;
            2: parse_ss;
            4: parse_sack;
            8: parse_ts;
            default: accept;
        }
    }

    state parse_nop {
        packet.extract(hdr.nop2);
        transition select(hdr.nop2.kind) {
            1: parse_nop2;
            8: parse_ts;
            default: accept;
        }
    }

    state parse_nop2 {
        packet.extract(hdr.nop3);
        transition select(hdr.nop3.kind) {
            8: parse_ts;
            default: accept;
        }
    }

    state parse_ss {
        packet.extract(hdr.ss);
        packet.extract(hdr.nop3);
        transition select(hdr.nop3.kind) {
            4: parse_sack;
            8: parse_ts;
            default: accept;
        }
    }

    state parse_sack {
        packet.extract(hdr.sackw);
        packet.extract(hdr.sack);
        packet.extract(hdr.nop4);
        transition select(hdr.nop4.kind) {
            8: parse_ts;
            default: accept;
        }
    }

    state parse_ts {
        packet.extract(hdr.timestamp);
        transition accept;
    }
}
parser SwitchEgressParser(
    packet_in packet,
    out headers hdr,
    out metadata meta,
    out egress_intrinsic_metadata_t eg_intr_md
) {
    state start {
        packet.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort, hdr.udp.srcPort) {
            (7777, _): parse_info;
            (_, 4433): parse_quic;
            (4433, _): parse_quic;
            default: accept;
        }
    }

    state parse_quic {
        packet.extract(hdr.quic);
        transition accept;
    }

    state parse_info {
        packet.extract(hdr.info);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        packet.extract(hdr.nop1);
        transition select(hdr.nop1.kind) {
            1: parse_nop;
            2: parse_ss;
            4: parse_sack;
            8: parse_ts;
            default: accept;
        }
    }

    state parse_nop {
        packet.extract(hdr.nop2);
        transition select(hdr.nop2.kind) {
            1: parse_nop2;
            8: parse_ts;
            default: accept;
        }
    }

    state parse_nop2 {
        packet.extract(hdr.nop3);
        transition select(hdr.nop3.kind) {
            8: parse_ts;
            default: accept;
        }
    }

    state parse_ss {
        packet.extract(hdr.ss);
        packet.extract(hdr.nop3);
        transition select(hdr.nop3.kind) {
            4: parse_sack;
            8: parse_ts;
            default: accept;
        }
    }

    state parse_sack {
        packet.extract(hdr.sackw);
        packet.extract(hdr.sack);
        packet.extract(hdr.nop4);
        transition select(hdr.nop4.kind) {
            8: parse_ts;
            default: accept;
        }
    }

    state parse_ts {
        packet.extract(hdr.timestamp);
        transition accept;
    }
}
