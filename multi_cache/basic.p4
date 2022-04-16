/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define KV_ENTRIES 1

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> READ_BIT = 0x52;  // R
const bit<8> WRITE_BIT = 0x57; // W
const bit<8> INBOUND = 0x49;   // I
const bit<8> OUTBOUND = 0x4F;  // O

const bit<8> EMPTY_FL = 0;
const bit<8> RESUB_FL_1 = 1;
const bit<8> CLONE_FL_1 = 2;
const bit<8> RECIRC_FL_1 = 3;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header kv_t {
    bit<8>  rw;
    bit<8>  direction;
    bit<32> key;
    bit<32> value;
}

struct meta_t {
    @field_list(RESUB_FL_1, CLONE_FL_1)
    bit <8> f1;
    @field_list(RECIRC_FL_1)
    bit<16> f2;
    @field_list(CLONE_FL_1)
    bit<8>  f3;
    @field_list(RESUB_FL_1)
    bit<32> f4;
    bit<1> to_recirculate;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp;
    kv_t         kv;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout meta_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition parse_udp;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_kv;
    }

    state parse_kv {
        packet.extract(hdr.kv);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout meta_t meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout meta_t meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(KV_ENTRIES) l1_cache_key;
    register<bit<32>>(KV_ENTRIES) l1_cache_value;
    register<bit<32>>(KV_ENTRIES) l2_cache_key;
    register<bit<32>>(KV_ENTRIES) l2_cache_value;
    register<bit<32>>(KV_ENTRIES) l3_cache_key;
    register<bit<32>>(KV_ENTRIES) l3_cache_value;
    register<bit<32>>(KV_ENTRIES) l4_cache_key;
    register<bit<32>>(KV_ENTRIES) l4_cache_value;
    bit<32> key_position;
    bit<32> evicted_key_1;
    bit<32> evicted_value_1;
    bit<32> evicted_key_2;
    bit<32> evicted_value_2;
    bit<32> current_key;
    bit<32> current_value;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action change_direction() {
        ip4Addr_t tmp = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tmp;
        bit<16> tmp2 = hdr.udp.srcPort;
        hdr.udp.srcPort = hdr.udp.dstPort;
        hdr.udp.dstPort = tmp2;
        hdr.kv.direction = OUTBOUND;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action init() {
        evicted_key_2 = 0x0000;
        evicted_value_2 = 0x0000;
        meta.to_recirculate = 0x0;
    }

    action compute_hashes(bit<32> key) {
        hash(key_position, HashAlgorithm.crc32, (bit<32>)0, {key}, (bit<32>)KV_ENTRIES);
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
        init();
        compute_hashes(hdr.kv.key);
        if (hdr.kv.direction == OUTBOUND) {
            /**
             ** Three kinds of packet will triggers the operations in this condition:
             ** (1) When P4 recieves KVStore's read query replies, it puts KV
             **     at layer 1 cache and shift the existed KVs backward
             ** (2) When P4 receives KVStore's write query replies, it promotes KV
             **     at current layer to layer 1 and shift back other KVs that is
             **     in front of the original KV. If K does not exists in cache,
             **     perform same operation as (1).
             ** (3) When P4 receives recirculated read query requests, the packet
             **     itself has been modified as an outbound reply packet and it
             **     promotes KV at current layer to layer 1 and shift back other KVs
             **     that is infront of the original KV. If K does not exists in
             **     cache, perform same operation as (1).
             **/

            // layer 1
            // following register operations can be done atomically in tofino P4
            l1_cache_key.read(evicted_key_1, key_position);
            l1_cache_value.read(evicted_value_1, key_position);
            l1_cache_key.write(key_position, hdr.kv.key);
            l1_cache_value.write(key_position, hdr.kv.value);

            // layer 2
            if (hdr.kv.key != evicted_key_1 && hdr.kv.key != evicted_key_2) {
                // following register operations can be done atomically in tofino P4
                l2_cache_key.read(evicted_key_2, key_position);
                l2_cache_value.read(evicted_value_2, key_position);
                l2_cache_key.write(key_position, evicted_key_1);
                l2_cache_value.write(key_position, evicted_value_1);
            }

            // layer 3
            if (hdr.kv.key != evicted_key_1 && hdr.kv.key != evicted_key_2) {
                // following register operations can be done atomically in tofino P4
                l3_cache_key.read(evicted_key_1, key_position);
                l3_cache_value.read(evicted_value_1, key_position);
                l3_cache_key.write(key_position, evicted_key_2);
                l3_cache_value.write(key_position, evicted_value_2);
            }

            // layer 4
            if (hdr.kv.key != evicted_key_1 && hdr.kv.key != evicted_key_2) {
                // following register operations can be done atomically in tofino P4
                l4_cache_key.write(key_position, evicted_key_1);
                l4_cache_value.write(key_position, evicted_value_1);
            }

        } else if (hdr.kv.direction == INBOUND && hdr.kv.rw == READ_BIT) {
            // when original read query packet arrives, search the key in cache
            // layer 1
            l1_cache_key.read(current_key, key_position);
            l1_cache_value.read(current_value, key_position);

            // layer 2
            if (current_key != hdr.kv.key) {
                l2_cache_key.read(current_key, key_position);
                l2_cache_value.read(current_value, key_position);
            }

            // layer 3
            if (current_key != hdr.kv.key) {
                l3_cache_key.read(current_key, key_position);
                l3_cache_value.read(current_value, key_position);
            }

            // layer 4
            if (current_key != hdr.kv.key) {
                l4_cache_key.read(current_key, key_position);
                l4_cache_value.read(current_value, key_position);
            }

            if (current_key == hdr.kv.key) {
                // key has found, recirculate the packet
                hdr.kv.value = current_value;
                meta.to_recirculate = 0x1;
            }
        }
        if (meta.to_recirculate == 1) {
            change_direction();
        }
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout meta_t meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        if (meta.to_recirculate == 1) {
            recirculate_preserving_field_list(0);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout meta_t meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.kv);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
