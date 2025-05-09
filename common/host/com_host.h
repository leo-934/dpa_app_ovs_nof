#include <stdint.h>

#define MATCH_VAL_BSIZE 64

struct mlx5_ifc_dr_match_spec_bits {
	uint8_t smac_47_16[0x20];

	uint8_t smac_15_0[0x10];
	uint8_t ethertype[0x10];

	uint8_t dmac_47_16[0x20];

	uint8_t dmac_15_0[0x10];
	uint8_t first_prio[0x3];
	uint8_t first_cfi[0x1];
	uint8_t first_vid[0xc];

	uint8_t ip_protocol[0x8];
	uint8_t ip_dscp[0x6];
	uint8_t ip_ecn[0x2];
	uint8_t cvlan_tag[0x1];
	uint8_t svlan_tag[0x1];
	uint8_t frag[0x1];
	uint8_t ip_version[0x4];
	uint8_t tcp_flags[0x9];

	uint8_t tcp_sport[0x10];
	uint8_t tcp_dport[0x10];

	uint8_t reserved_at_c0[0x18];
	uint8_t ip_ttl_hoplimit[0x8];

	uint8_t udp_sport[0x10];
	uint8_t udp_dport[0x10];

	uint8_t src_ip_127_96[0x20];

	uint8_t src_ip_95_64[0x20];

	uint8_t src_ip_63_32[0x20];

	uint8_t src_ip_31_0[0x20];

	uint8_t dst_ip_127_96[0x20];

	uint8_t dst_ip_95_64[0x20];

	uint8_t dst_ip_63_32[0x20];

	uint8_t dst_ip_31_0[0x20];
};