/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012, 2013 Markus Amend <markus@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <daniel@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

/* TODO
 * check all possible frame combinations for their behavior
 * with respect to endianess (little / big)
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <asm/byteorder.h>
#include <arpa/inet.h>     /* for inet_ntop() */

#include "proto.h"
#include "dissector_80211.h"
#include "built_in.h"
#include "pkt_buff.h"
#include "oui.h"
#include "linktype.h"

#define	TU		0.001024

/* Note: Fields are encoded in little-endian! */
struct ieee80211_frm_ctrl {
	union {
		u16 frame_control;
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
		__extension__ u16 proto_version:2,
				  type:2,
				  subtype:4,
				  to_ds:1,
				  from_ds:1,
				  more_frags:1,
				  retry:1,
				  power_mgmt:1,
				  more_data:1,
				  wep:1,
				  order:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
		__extension__ u16 subtype:4,
				  type:2,
				  proto_version:2,
				  order:1,
				  wep:1,
				  more_data:1,
				  power_mgmt:1,
				  retry:1,
				  more_frags:1,
				  from_ds:1,
				  to_ds:1;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		};
	};
} __packed;

/* Management Frame start */
/* Note: Fields are encoded in little-endian! */
struct ieee80211_mgmt {
	u16 duration;
	u8 da[6];
	u8 sa[6];
	u8 bssid[6];
	u16 seq_ctrl;
} __packed;

struct ieee80211_mgmt_auth {
	u16 auth_alg;
	u16 auth_transaction;
	u16 status_code;
	/* possibly followed by Challenge text */
	u8 variable[0];
} __packed;

struct ieee80211_mgmt_deauth {
	u16 reason_code;
} __packed;

struct ieee80211_mgmt_assoc_req {
	u16 capab_info;
	u16 listen_interval;
	/* followed by SSID and Supported rates */
	u8 variable[0];
} __packed;

struct ieee80211_mgmt_assoc_resp {
	u16 capab_info;
	u16 status_code;
	u16 aid;
	/* followed by Supported rates */
	u8 variable[0];
} __packed;

struct ieee80211_mgmt_reassoc_resp {
	u16 capab_info;
	u16 status_code;
	u16 aid;
	/* followed by Supported rates */
	u8 variable[0];
} __packed;

struct ieee80211_mgmt_reassoc_req {
	u16 capab_info;
	u16 listen_interval;
	u8 current_ap[6];
	/* followed by SSID and Supported rates */
	u8 variable[0];
} __packed;

struct ieee80211_mgmt_disassoc {
	u16 reason_code;
} __packed;

struct ieee80211_mgmt_probe_req {
} __packed;

struct ieee80211_mgmt_beacon {
	u64 timestamp;
	u16 beacon_int;
	u16 capab_info;
	/* followed by some of SSID, Supported rates,
	  * FH Params, DS Params, CF Params, IBSS Params, TIM */
	u8 variable[0];
} __packed;

struct ieee80211_mgmt_probe_resp {
	u8 timestamp[8];
	u16 beacon_int;
	u16 capab_info;
	/* followed by some of SSID, Supported rates,
	  * FH Params, DS Params, CF Params, IBSS Params, TIM */
	u8 variable[0];
} __packed;
/* Management Frame end */

/* Control Frame start */
/* Note: Fields are encoded in little-endian! */
struct ieee80211_ctrl {
} __packed;

struct ieee80211_ctrl_rts {
	u16 duration;
	u8 da[6];
	u8 sa[6];	
} __packed;

struct ieee80211_ctrl_cts {
	u16 duration;
	u8 da[6];
} __packed;

struct ieee80211_ctrl_ack {
	u16 duration;
	u8 da[6];
} __packed;

struct ieee80211_ctrl_ps_poll {
	u16 aid;
	u8 bssid[6];
	u8 sa[6];
} __packed;

struct ieee80211_ctrl_cf_end {
	u16 duration;
	u8 bssid[6];
	u8 sa[6];
} __packed;

struct ieee80211_ctrl_cf_end_ack {
	u16 duration;
	u8 bssid[6];
	u8 sa[6];
} __packed;
/* Control Frame end */

/* Data Frame start */
/* Note: Fields are encoded in little-endian! */
struct ieee80211_data {
} __packed;

/* TODO: Extend */
/* Data Frame end */

struct element_reserved {
	u8 len;
} __packed;

struct element_ssid {
	u8 len;
	u8 SSID[0];
} __packed;

struct element_supp_rates {
	u8 len;
	u8 rates[0];
} __packed;

struct element_fh_ps {
	u8 len;
	u16 dwell_time;
	u8 hop_set;
	u8 hop_pattern;
	u8 hop_index;
} __packed;

struct element_dsss_ps {
	u8 len;
	u8 curr_ch;
} __packed;

struct element_cf_ps {
	u8 len;
	u8 cfp_cnt;
	u8 cfp_period;
	u16 cfp_max_dur;
	u16 cfp_dur_rem;
} __packed;

struct element_tim {
	u8 len;
	u8 dtim_cnt;
	u8 dtim_period;
	u8 bmp_cntrl;
	u8 part_virt_bmp[0];
} __packed;

struct element_ibss_ps {
	u8 len;
	u16 atim_win;
} __packed;

struct element_country_tripled {
	u8 frst_ch;
	u8 nr_ch;
	u8 max_trans;
} __packed;

struct element_country {
	u8 len;
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
	u8 country_first;
	u8 country_sec;
	u8 country_third;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 country_third;
	u8 country_sec;
	u8 country_first;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
	/* triplet may repeat */
	struct element_country_tripled tripled [0];
	/* end triplet */
	u8 pad[0];
} __packed;

struct element_hop_pp {
	u8 len;
	u8 prime_radix;
	u8 nr_ch;
} __packed;

struct element_hop_pt {
	u8 len;
	u8 flag;
	u8 nr_sets;
	u8 modules;
	u8 offs;
	u8 rand_tabl[0];
} __packed;

struct element_req {
	u8 len;
	u8 req_elem_idl[0];
} __packed;

struct element_bss_load {
	u8 len;
	u16 station_cnt;
	u8 ch_util;
	u16 avlb_adm_cap;
} __packed;

struct element_edca_ps {
	u8 len;
	u8 qos_inf;
	u8 res;
	u32 ac_be;
	u32 ac_bk;
	u32 ac_vi;
	u32 ac_vo;
} __packed;

struct element_tspec {
	union {
		u32 len_ts_info;
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
		__extension__ u32 len:8,
				  traffic_type:1,
				  tsid:4,
				  direction:2,
				  access_policy:2,
				  aggr:1,
				  apsd:1,
				  user_prior:3,
				  tsinfo_ack_pol:2,
				  schedule:1,
				  res:7;
#elif defined(__BIG_ENDIAN_BITFIELD)
		__extension__ u32 len:8,
				  res:7,
				  schedule:1,
				  tsinfo_ack_pol:2,
				  user_prior:3,
				  apsd:1,
				  aggr:1,
				  access_policy:2,
				  direction:2,
				  tsid:4,
				  traffic_type:1;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		};
	};
	u16 nom_msdu_size;
	u16 max_msdu_size;
	u32 min_srv_intv;
	u32 max_srv_intv;
	u32 inactive_intv;
	u32 susp_intv;
	u32 srv_start_time;
	u32 min_data_rate;
	u32 mean_data_rate;
	u32 peak_data_rate;
	u32 burst_size;
	u32 delay_bound;
	u32 min_phy_rate;
	u16 surplus_bandw_allow;
	u16 med_time;
} __packed;

struct element_tclas {
	u8 len;
	u8 user_priority;
	u8 frm_class[0];
} __packed;

struct element_tclas_frm_class {
	u8 type;
	u8 mask;
	u8 param[0];
} __packed;

struct element_tclas_type0 {
	u8 sa[6];
	u8 da[6];
	u16 type;
} __packed;

struct element_tclas_type1 {
	u8 version;
	u8 subparam[0];
} __packed;

struct element_tclas_type1_ip4 {
	u32 sa;
	u32 da;
	u16 sp;
	u16 dp;
	u8 dscp;
	u8 proto;
	u8 reserved;
} __packed;

struct element_tclas_type1_ip6 {
	struct in6_addr sa;
	struct in6_addr da;
	u16 sp;
	u16 dp;
	union {
		u8 flow_label[3];
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		__extension__ u8  flow_label3:8;
		__extension__ u8  flow_label2:8;
		__extension__ u8  flow_label1:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
		__extension__ u8  flow_label1:8;
		__extension__ u8  flow_label2:8;
		__extension__ u8  flow_label3:8;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		};
	};
} __packed;

struct element_tclas_type2 {
	u16 vlan_tci;
} __packed;

struct element_tclas_type3 {
	u16 offs;
	u8 value[0];
	u8 mask[0];
} __packed;

struct element_tclas_type4 {
	u8 version;
	u8 subparam[0];
} __packed;

struct element_tclas_type4_ip4 {
	u32 sa;
	u32 da;
	u16 sp;
	u16 dp;
	u8 dscp;
	u8 proto;
	u8 reserved;
} __packed;

struct element_tclas_type4_ip6 {
	struct in6_addr sa;
	struct in6_addr da;
	u16 sp;
	u16 dp;
	u8 dscp;
	u8 nxt_hdr;
	union {
		u8 flow_label[3];
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		__extension__ u8  flow_label3:8;
		__extension__ u8  flow_label2:8;
		__extension__ u8  flow_label1:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
		__extension__ u8  flow_label1:8;
		__extension__ u8  flow_label2:8;
		__extension__ u8  flow_label3:8;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		};
	};
} __packed;

struct element_tclas_type5 {
	u8 pcp;
	u8 cfi;
	u8 vid;
} __packed;

struct element_schedule {
	u8 len;
	u16 inf;
	u32 start;
	u32 serv_intv;
	u16 spec_intv;
} __packed;

struct element_chall_txt {
	u8 len;
	u8 chall_txt[0];
} __packed;

struct element_pwr_constr {
	u8 len;
	u8 local_pwr_constr;
} __packed;

struct element_pwr_cap {
	u8 len;
	u8 min_pwr_cap;
	u8 max_pwr_cap;
} __packed;

struct element_tpc_req {
	u8 len;
} __packed;

struct element_tpc_rep {
	u8 len;
	u8 trans_pwr;
	u8 link_marg;
} __packed;

struct element_supp_ch {
	u8 len;
	u8 first_ch_nr[0];
	u8 nr_ch[0];
} __packed;

struct element_supp_ch_tuple {
	u8 first_ch_nr;
	u8 nr_ch;
} __packed;

struct element_ch_sw_ann {
	u8 len;
	u8 switch_mode;
	u8 new_nr;
	u8 switch_cnt;
} __packed;

struct element_meas_basic {
	u8 ch_nr;
	u64 start;
	u16 dur;
} __packed;

struct element_meas_cca {
	u8 ch_nr;
	u64 start;
	u16 dur;
} __packed;

struct element_meas_rpi {
	u8 ch_nr;
	u64 start;
	u16 dur;
} __packed;

struct element_meas_ch_load {
	u8 op_class;
	u8 ch_nr;
	u16 rand_intv;
	u16 dur;
	u8 sub[0];
} __packed;

struct element_meas_noise {
	u8 op_class;
	u8 ch_nr;
	u16 rand_intv;
	u16 dur;
	u8 sub[0];
} __packed;

struct element_meas_beacon {
	u8 op_class;
	u8 ch_nr;
	u16 rand_intv;
	u16 dur;
	u8 mode;
	u8 bssid[6];
	u8 sub[0];
} __packed;

struct element_meas_frame {
	u8 op_class;
	u8 ch_nr;
	u16 rand_intv;
	u16 dur;
	u8 frame;
	u8 mac[6];
	u8 sub[0];
} __packed;

struct element_meas_sta {
	u8 peer_mac[6];
	u16 rand_intv;
	u16 dur;
	u8 group_id;
	u8 sub[0];
} __packed;

struct element_meas_lci {
	u8 loc_subj;
	u8 latitude_req_res;
	u8 longitude_req_res;
	u8 altitude_req_res;
	u8 sub[0];
} __packed;

struct element_meas_trans_str_cat {
	u16 rand_intv;
	u16 dur;
	u8 peer_sta_addr[6];
	u8 traffic_id;
	u8 bin_0_range;
	u8 sub[0];
} __packed;

struct element_meas_mcast_diag {
	u16 rand_intv;
	u16 dur;
	u8 group_mac[6];
	u8 mcast_triggered[0];
	u8 sub[0];
} __packed;

struct element_meas_loc_civic {
	u8 loc_subj;
	u8 civic_loc;
	u8 loc_srv_intv_unit;
	u16 loc_srv_intv;
	u8 sub[0];
} __packed;

struct element_meas_loc_id {
	u8 loc_subj;
	u8 loc_srv_intv_unit;
	u16 loc_srv_intv;
	u8 sub[0];
} __packed;

struct element_meas_pause {
	u8 time;
	u8 sub[0];
} __packed;

struct element_meas_req {
	u8 len;
	u8 token;
	u8 req_mode;
	u8 type;
	u8 req[0];
} __packed;

struct element_meas_rep {
	u8 len;
	u8 token;
	u8 rep_mode;
	u8 type;
	u8 rep[0];
} __packed;

struct element_quiet {
	u8 len;
	u8 cnt;
	u8 period;
	u16 dur;
	u16 offs;
} __packed;

struct element_ibss_dfs {
	u8 len;
	u8 owner[6];
	u8 rec_intv;
	u8 ch_map[0];
} __packed;

struct element_ibss_dfs_tuple {
	u8 ch_nr;
	u8 map;
} __packed;

struct element_erp {
	u8 len;
	u8 param;
} __packed;

struct element_ts_del {
	u8 len;
	u32 delay;
} __packed;

struct element_tclas_proc {
	u8 len;
	u8 proc;
} __packed;

struct element_ht_cap {
	u8 len;
	union {
		u16 info;
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
		__extension__ u16 ldpc:1,
				  supp_width:1,
				  sm_pwr:2,
				  ht_green:1,
				  gi_20mhz:1,
				  gi_40mhz:1,
				  tx_stbc:1,
				  rx_stbc:2,
				  ht_ack:1,
				  max_msdu_length:1,
				  dsss_ck_mode:1,
				  res:1,
				  forty_int:1,
				  prot_supp:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
		__extension__ u16 rx_stbc:2,
				  ht_ack:1,
				  max_msdu_length:1,
				  dsss_ck_mode:1,
				  res:1,
				  forty_int:1,
				  prot_supp:1,
				  ldpc:1,
				  supp_width:1,
				  sm_pwr:2,
				  ht_green:1,
				  gi_20mhz:1,
				  gi_40mhz:1,
				  tx_stbc:1;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		};
	};
	u8 param;
	union {
		u8 mcs_set[16];
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
		__extension__ u8  bitmask1:8;
		__extension__ u8  bitmask2:8;
		__extension__ u8  bitmask3:8;
		__extension__ u8  bitmask4:8;
		__extension__ u8  bitmask5:8;
		__extension__ u8  bitmask6:8;
		__extension__ u8  bitmask7:8;
		__extension__ u8  bitmask8:8;
		__extension__ u8  bitmask9:8;
		__extension__ u8  bitmask10_res:8;
		__extension__ u16 supp_rate_res:16;
		__extension__ u32 tx_param_res:32;
		
#elif defined(__BIG_ENDIAN_BITFIELD)
		__extension__ u32 tx_param_res:32;
		__extension__ u16 supp_rate_res:16;
		__extension__ u8  bitmask10_res:8;
		__extension__ u8  bitmask9:8;
		__extension__ u8  bitmask8:8;
		__extension__ u8  bitmask7:8;
		__extension__ u8  bitmask6:8;
		__extension__ u8  bitmask5:8;
		__extension__ u8  bitmask4:8;
		__extension__ u8  bitmask3:8;
		__extension__ u8  bitmask2:8;
		__extension__ u8  bitmask1:8;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
		};
	};
	u16 ext_cap;
	u32 beam_cap;
	u8 asel_cap;
} __packed;

struct element_qos_cap {
	u8 len;
	u8 info;
} __packed;

struct element_ext_supp_rates {
	u8 len;
	u8 rates[0];
} __packed;

struct element_vend_spec {
	u8 len;
	u8 oui[0];
	u8 specific[0];
} __packed;

struct ieee80211_radiotap_header {
	u8 version;	/* set to 0 */
	u8 pad;
	u16 len;	/* entire length */
	u32 present;	/* fields present */
} __packed;

static int8_t len_neq_error(u8 len, u8 intended)
{
	if(intended != len) {
		tprintf("Length should be %u Bytes", intended);
		return 1;
	}

	return 0;
}

static int8_t len_lt_error(u8 len, u8 intended)
{
	if(len < intended) {
		tprintf("Length should be greater %u Bytes", intended);
		return 1;
	}

	return 0;
}

static float data_rates(u8 id)
{
	/* XXX Why not (id / 2.f)? */
	switch (id) {
	case   2: return  1.0f;
	case   3: return  1.5f;
	case   4: return  2.0f;
	case   5: return  2.5f;
	case   6: return  3.0f;
	case   9: return  4.5f;
	case  11: return  5.5f;
	case  12: return  6.0f;
	case  18: return  9.0f;
	case  22: return 11.0f;
	case  24: return 12.0f;
	case  27: return 13.5f;
	case  36: return 18.0f;
	case  44: return 22.0f;
	case  48: return 24.0f;
	case  54: return 27.0f;
	case  66: return 33.0f;
	case  72: return 36.0f;
	case  96: return 48.0f;
	case 108: return 54.0f;
	}

	return 0.f;
}

struct subelement {
	u8 id;
	u8 len;
	u8 data[0];
} __packed;


static int8_t subelements(struct pkt_buff *pkt, u8 len)
{
	u8 i, j;
	u8 *data;
	
	for (i=0; i<len;) {
		struct subelement *sub;

		sub = (struct subelement *) pkt_pull(pkt, sizeof(*sub));
		if (sub == NULL)
			return 0;

		tprintf(", Subelement ID %u, ", sub->id);
		tprintf("Length %u, ", sub->len);

		data = pkt_pull(pkt, sub->len);
		if (data == NULL)
			return 0;

		tprintf("Data: 0x");
		for(j=0; j < sub->len; j++)
			tprintf("%.2x ", data[j]);

		i += sub->len + 1;
	}

	/* Not needed ?! Should break before*/
	/*
	 *if (i != len) {
	 *	tprintf("Length error");
	 *	return 0;
	 *}
	 */

      return 1;
}

static int8_t inf_reserved(struct pkt_buff *pkt, u8 *id)
{
	u8 i;
	u8 *data;
	struct element_reserved *reserved;

	reserved = (struct element_reserved *) pkt_pull(pkt, sizeof(*reserved));
	if (reserved == NULL)
		return 0;

	tprintf(" Reserved (%u, Len (%u)): ", *id, reserved->len);

	data = pkt_pull(pkt, reserved->len);
	if (data == NULL)
		return 0;

	tprintf("Data 0x");
	for (i = 0; i < reserved->len; i++)
		tprintf("%.2x", data[i]);

	return 1;
}

static int8_t inf_ssid(struct pkt_buff *pkt, u8 *id)
{
	u8 i;
	struct element_ssid *ssid;
	char *ssid_name;

	ssid = (struct element_ssid *) pkt_pull(pkt, sizeof(*ssid));
	if (ssid == NULL)
		return 0;

	tprintf(" SSID (%u, Len (%u)): ", *id, ssid->len);

	if ((ssid->len - sizeof(*ssid) + 1) > 0) {
		ssid_name = (char *) pkt_pull(pkt, ssid->len);
		if (ssid_name == NULL)
			return 0;

		for (i = 0; i < ssid->len; i++)
			tprintf("%c",ssid_name[i]);
	} else {
		tprintf("Wildcard SSID");
	}

	return 1;
}

static int8_t inf_supp_rates(struct pkt_buff *pkt, u8 *id)
{
	u8 i;
	u8 *rates;
	struct element_supp_rates *supp_rates;

	supp_rates = (struct element_supp_rates *)
			pkt_pull(pkt, sizeof(*supp_rates));
	if (supp_rates == NULL)
		return 0;

	tprintf(" Supp. Rates (%u, Len (%u)): ", *id, supp_rates->len);
	if (len_lt_error(supp_rates->len, 1))
		return 0;

	if ((supp_rates->len - sizeof(*supp_rates) + 1) > 0) {
		rates = pkt_pull(pkt, supp_rates->len);
		if (rates == NULL)
			return 0;

		for (i = 0; i < supp_rates->len; i++)
			tprintf("%g%s ", ((rates[i] & 0x80) >> 7) ?
					data_rates(rates[i] & 0x3f) :
					((rates[i] & 0x3f) * 0.5),
					((rates[i] & 0x80) >> 7) ? "(B)" : "");
		return 1;
	}

	return 0;
}

static int8_t inf_fh_ps(struct pkt_buff *pkt, u8 *id)
{
	struct element_fh_ps *fh_ps;

	fh_ps =	(struct element_fh_ps *) pkt_pull(pkt, sizeof(*fh_ps));
	if (fh_ps == NULL)
		return 0;

	tprintf(" FH Param Set (%u, Len(%u)): ", *id, fh_ps->len);
	if (len_neq_error(fh_ps->len, 5))
		return 0;
	tprintf("Dwell Time: %fs, ", le16_to_cpu(fh_ps->dwell_time) * TU);
	tprintf("HopSet: %u, ", fh_ps->hop_set);
	tprintf("HopPattern: %u, ", fh_ps->hop_pattern);
	tprintf("HopIndex: %u", fh_ps->hop_index);

	return 1;
}

static int8_t inf_dsss_ps(struct pkt_buff *pkt, u8 *id)
{
	struct element_dsss_ps *dsss_ps;

	dsss_ps = (struct element_dsss_ps *) pkt_pull(pkt, sizeof(*dsss_ps));
	if (dsss_ps == NULL)
		return 0;

	tprintf(" DSSS Param Set (%u, Len(%u)): ", *id, dsss_ps->len);
	if (len_neq_error(dsss_ps->len, 1))
		return 0;
	tprintf("Current Channel: %u", dsss_ps->curr_ch);

	return 1;
}

static int8_t inf_cf_ps(struct pkt_buff *pkt, u8 *id)
{
	struct element_cf_ps *cf_ps;

	cf_ps = (struct element_cf_ps *) pkt_pull(pkt, sizeof(*cf_ps));
	if (cf_ps == NULL)
		return 0;

	tprintf(" CF Param Set (%u, Len(%u)): ", *id, cf_ps->len);
	if (len_neq_error(cf_ps->len, 6))
		return 0;
	tprintf("CFP Count: %u, ", cf_ps->cfp_cnt);
	tprintf("CFP Period: %u, ", cf_ps->cfp_period);
	tprintf("CFP MaxDur: %fs, ", le16_to_cpu(cf_ps->cfp_max_dur) * TU);
	tprintf("CFP DurRem: %fs", le16_to_cpu(cf_ps->cfp_dur_rem) * TU);

	return 1;
}

static int8_t inf_tim(struct pkt_buff *pkt, u8 *id)
{
	struct element_tim *tim;
	u8 i;

	tim = (struct element_tim *) pkt_pull(pkt, sizeof(*tim));
	if (tim == NULL)
		return 0;

	tprintf(" TIM (%u, Len(%u)): ", *id, tim->len);
	if (len_lt_error(tim->len, 3))
		return 0;
	tprintf("DTIM Count: %u, ", tim->dtim_cnt);
	tprintf("DTIM Period: %u, ", tim->dtim_period);
	tprintf("Bitmap Control: %u, ", tim->bmp_cntrl);
	if ((tim->len - sizeof(*tim) + 1) > 0) {
		u8 *bmp = pkt_pull(pkt, (tim->len - sizeof(*tim) + 1));
		if (bmp == NULL)
			return 0;

		tprintf("Partial Virtual Bitmap: 0x");
		for (i = 0; i < (tim->len - sizeof(*tim) + 1); i++)
			tprintf("%.2x", bmp[i]);
	}

	return 1;
}

static int8_t inf_ibss_ps(struct pkt_buff *pkt, u8 *id)
{
	struct element_ibss_ps *ibss_ps;

	ibss_ps = (struct element_ibss_ps *) pkt_pull(pkt, sizeof(*ibss_ps));
	if (ibss_ps == NULL)
		return 0;

	tprintf(" IBSS Param Set (%u, Len(%u)): ", *id, ibss_ps->len);
	if (len_neq_error(ibss_ps->len, 2))
		return 0;
	tprintf("ATIM Window: %fs", le16_to_cpu(ibss_ps->atim_win) * TU);

	return 1;
}

static int8_t inf_country(struct pkt_buff *pkt, u8 *id)
{
	u8 i;
	u8 *pad;
	struct element_country *country;

	country = (struct element_country *) pkt_pull(pkt, sizeof(*country));
	if (country == NULL)
		return 0;

	tprintf(" Country (%u, Len(%u)): ", *id, country->len);
	if (len_lt_error(country->len, 6))
		return 0;
	tprintf("Country String: %c%c%c", country->country_first,
		country->country_sec, country->country_third);

	for (i = country->len % 3; i < (country->len - 3); i += 3) {
		struct element_country_tripled *country_tripled;

		country_tripled = (struct element_country_tripled *)
				    pkt_pull(pkt, sizeof(*country_tripled));
		if (country_tripled == NULL)
			return 0;

		if(country_tripled->frst_ch >= 201) {
			tprintf("Oper Ext ID: %u, ", country_tripled->frst_ch);
			tprintf("Operating Class: %u, ", country_tripled->nr_ch);
			tprintf("Coverage Class: %u", country_tripled->max_trans);
		} else {
			tprintf("First Ch Nr: %u, ", country_tripled->frst_ch);
			tprintf("Nr of Ch: %u, ", country_tripled->nr_ch);
			tprintf("Max Transmit Pwr Lvl: %u", country_tripled->max_trans);
		}
	}

	if(country->len % 3) {
		pad = pkt_pull(pkt, 1);
		if (pad == NULL)
			return 0;

		tprintf(", Pad: 0x%x", *pad);
	}

	return 1;
}

static int8_t inf_hop_pp(struct pkt_buff *pkt, u8 *id)
{
	struct element_hop_pp *hop_pp;

	hop_pp = (struct element_hop_pp *) pkt_pull(pkt, sizeof(*hop_pp));
	if (hop_pp == NULL)
		return 0;

	tprintf(" Hopping Pattern Param (%u, Len(%u)): ", *id, hop_pp->len);
	if (len_neq_error(hop_pp->len, 2))
		return 0;
	tprintf("Prime Radix: %u, ", hop_pp->prime_radix);
	tprintf("Nr of Ch: %u", hop_pp->nr_ch);

	return 1;
}

static int8_t inf_hop_pt(struct pkt_buff *pkt, u8 *id)
{
	size_t i;
	u8 *rand_tabl;
	struct element_hop_pt *hop_pt;

	hop_pt = (struct element_hop_pt *) pkt_pull(pkt, sizeof(*hop_pt));
	if (hop_pt == NULL)
		return 0;

	tprintf(" Hopping Pattern Table (%u, Len(%u)): ", *id, hop_pt->len);
	if (len_lt_error(hop_pt->len, 4))
		return 0;
	tprintf("Flag: %u, ", hop_pt->flag);
	tprintf("Nr of Sets: %u, ", hop_pt->nr_sets);
	tprintf("Modulus: %u, ", hop_pt->modules);
	tprintf("Offs: %u", hop_pt->offs);

	if ((hop_pt->len - sizeof(*hop_pt) + 1) > 0) {
		rand_tabl = pkt_pull(pkt, (hop_pt->len - sizeof(*hop_pt) + 1));
		if (rand_tabl == NULL)
			return 0;

		tprintf(", Rand table: 0x");
		for (i = 0; i < (hop_pt->len - sizeof(*hop_pt) + 1); i++)
			tprintf("%.2x", rand_tabl[i]);
	}

	return 1;
}

static int8_t inf_req(struct pkt_buff *pkt, u8 *id)
{
	size_t i;
	struct element_req *req;
	u8 *req_ids;

	req = (struct element_req *) pkt_pull(pkt, sizeof(*req));
	if (req == NULL)
		return 0;

	tprintf(" Request Element (%u, Len(%u)): ", *id, req->len);
	if ((req->len - sizeof(*req) + 1) > 0) {
		req_ids = pkt_pull(pkt, (req->len - sizeof(*req) + 1));
		if (req_ids == NULL)
			return 0;

		tprintf(", Requested Element IDs: ");
		for (i = 0; i < (req->len - sizeof(*req) + 1); i++)
			tprintf("%u ", req_ids[i]);
	}

	return 1;
}

static int8_t inf_bss_load(struct pkt_buff *pkt, u8 *id)
{
	struct element_bss_load *bss_load;

	bss_load = (struct element_bss_load *) pkt_pull(pkt, sizeof(*bss_load));
	if (bss_load == NULL)
		return 0;

	tprintf(" BSS Load element (%u, Len(%u)): ", *id, bss_load->len);
	if (len_neq_error(bss_load->len, 5))
		return 0;
	tprintf("Station Count: %u, ", le16_to_cpu(bss_load->station_cnt));
	tprintf("Channel Utilization: %u, ", bss_load->ch_util);
	tprintf("Available Admission Capacity: %uus",
		bss_load->avlb_adm_cap * 32);

	return 1;
}

static int8_t inf_edca_ps(struct pkt_buff *pkt, u8 *id)
{
	u32 ac_be, ac_bk, ac_vi, ac_vo;
	struct element_edca_ps *edca_ps;

	edca_ps = (struct element_edca_ps *) pkt_pull(pkt, sizeof(*edca_ps));
	if (edca_ps == NULL)
		return 0;

	ac_be = le32_to_cpu(edca_ps->ac_be);
	ac_bk = le32_to_cpu(edca_ps->ac_bk);
	ac_vi = le32_to_cpu(edca_ps->ac_vi);
	ac_vo = le32_to_cpu(edca_ps->ac_vo);

	tprintf(" EDCA Param Set (%u, Len(%u)): ", *id, edca_ps->len);
	if (len_neq_error(edca_ps->len, 18))
		return 0;
	tprintf("QoS Info: 0x%x (-> EDCA Param Set Update Count (%u),"
		"Q-Ack (%u), Queue Re (%u), TXOP Req(%u), Res(%u)), ",
		edca_ps->qos_inf, edca_ps->qos_inf >> 4,
		(edca_ps->qos_inf >> 3) & 1, (edca_ps->qos_inf >> 2) & 1,
		(edca_ps->qos_inf >> 1) & 1, edca_ps->qos_inf & 1);
	tprintf("Reserved: 0x%x, ", edca_ps->res);
	tprintf("AC_BE Param Rec: 0x%x (-> AIFSN (%u), ACM (%u), ACI (%u),"
		"Res (%u), ECWmin (%u), ECWmax(%u)), TXOP Limit (%uus)), ", ac_be,
		ac_be >> 28, (ac_be >> 27) & 1, (ac_be >> 25) & 3,
		(ac_be >> 24) & 1, (ac_be >> 20) & 15, (ac_be >> 16) & 15,
		bswap_16(ac_be & 0xFFFF) * 32);
	tprintf("AC_BK Param Rec: 0x%x (-> AIFSN (%u), ACM (%u), ACI (%u),"
		"Res (%u), ECWmin (%u), ECWmax(%u)), TXOP Limit (%uus)), ", ac_bk,
		ac_bk >> 28, (ac_bk >> 27) & 1, (ac_bk >> 25) & 3,
		(ac_bk >> 24) & 1, (ac_bk >> 20) & 15, (ac_bk >> 16) & 15,
		bswap_16(ac_bk & 0xFFFF) * 32);
	tprintf("AC_VI Param Rec: 0x%x (-> AIFSN (%u), ACM (%u), ACI (%u),"
		"Res (%u), ECWmin (%u), ECWmax(%u)), TXOP Limit (%uus)), ", ac_vi,
		ac_vi >> 28, (ac_vi >> 27) & 1, (ac_vi >> 25) & 3,
		(ac_vi >> 24) & 1, (ac_vi >> 20) & 15, (ac_vi >> 16) & 15,
		bswap_16(ac_vi & 0xFFFF) * 32);
	tprintf("AC_VO Param Rec: 0x%x (-> AIFSN (%u), ACM (%u), ACI (%u),"
		"Res (%u), ECWmin (%u), ECWmax(%u)), TXOP Limit (%uus)", ac_vo,
		ac_vo >> 28, (ac_vo >> 27) & 1, (ac_vo >> 25) & 3,
		(ac_vo >> 24) & 1, (ac_vo >> 20) & 15, (ac_vo >> 16) & 15,
		bswap_16(ac_vo & 0xFFFF) * 32);

	return 1;
}

static int8_t inf_tspec(struct pkt_buff *pkt, u8 *id)
{
	u16 nom_msdu_size, surplus_bandw_allow;
	struct element_tspec *tspec;

	tspec = (struct element_tspec *) pkt_pull(pkt, sizeof(*tspec));
	if (tspec == NULL)
		return 0;

	nom_msdu_size = le16_to_cpu(tspec->nom_msdu_size);
	surplus_bandw_allow = le16_to_cpu(tspec->surplus_bandw_allow);

	tprintf(" TSPEC (%u, Len(%u)): ", *id, tspec->len);
	if (len_neq_error(tspec->len, 55))
		return 0;
	tprintf("Traffic Type: %u, ", tspec->traffic_type);
	tprintf("TSID: %u, ", tspec->tsid);
	tprintf("Direction: %u, ", tspec->direction);
	tprintf("Access Policy: %u, ", tspec->access_policy);
	tprintf("Aggregation: %u, ", tspec->aggr);
	tprintf("APSD: %u, ", tspec->apsd);
	tprintf("User Priority: %u, ", tspec->user_prior);
	tprintf("TSinfo Ack Policy: %u, ", tspec->tsinfo_ack_pol);
	tprintf("Schedule: %u, ", tspec->schedule);
	tprintf("Reserved: 0x%x, ", tspec->res);
	tprintf("Nominal MSDU Size: %uB (Fixed (%u)), ",
		nom_msdu_size >> 1, nom_msdu_size & 1);
	tprintf("Maximum MSDU Size: %uB, ", le16_to_cpu(tspec->max_msdu_size));
	tprintf("Minimum Service Interval: %uus, ",
		le32_to_cpu(tspec->min_srv_intv));
	tprintf("Maximum Service Interval: %uus, ",
		le32_to_cpu(tspec->max_srv_intv));
	tprintf("Inactivity Interval: %uus, ",
		le32_to_cpu(tspec->inactive_intv));
	tprintf("Suspension Interval: %uus, ", le32_to_cpu(tspec->susp_intv));
	tprintf("Service Start Time: %uus, ",
		le32_to_cpu(tspec->srv_start_time));
	tprintf("Minimum Data Rate: %ub/s, ",le32_to_cpu(tspec->min_data_rate));
	tprintf("Mean Data Rate: %ub/s, ", le32_to_cpu(tspec->mean_data_rate));
	tprintf("Peak Data Rate: %ub/s, ",le32_to_cpu(tspec->peak_data_rate));
	tprintf("Burst Size: %uB, ", le32_to_cpu(tspec->burst_size));
	tprintf("Delay Bound: %uus, ", le32_to_cpu(tspec->delay_bound));
	tprintf("Minimum PHY Rate: %ub/s, ", le32_to_cpu(tspec->min_phy_rate));
	tprintf("Surplus Bandwidth: %u.%u, ", surplus_bandw_allow >> 13,
		surplus_bandw_allow & 0x1FFF);
	tprintf("Medium Time: %uus", le16_to_cpu(tspec->med_time) * 32);

	return 1;
}

static const char *class_type(u8 type)
{
	switch (type) {
	case   0: return "Ethernet parameters";
	case   1: return "TCP/UDP IP parameters";
	case   2: return "IEEE 802.1Q parameters";
	case   3: return "Filter Offset parameters";
	case   4: return "IP and higher layer parameters";
	case   5: return "IEEE 802.1D/Q parameters";
	default: return "Reserved";
	}
}

static int8_t inf_tclas(struct pkt_buff *pkt, u8 *id)
{
	struct element_tclas *tclas;
	struct element_tclas_frm_class *frm_class;

	tclas =	(struct element_tclas *) pkt_pull(pkt, sizeof(*tclas));
	if (tclas == NULL)
		return 0;

	frm_class = (struct element_tclas_frm_class *)
				pkt_pull(pkt, sizeof(*frm_class));
	if (frm_class == NULL)
		return 0;

	tprintf(" TCLAS (%u, Len(%u)): ", *id, tclas->len);
	if (len_lt_error(tclas->len, 3))
		return 0;
	tprintf("User Priority: %u, ", tclas->user_priority);
	tprintf("Classifier Type: %s (%u), ", class_type(frm_class->type),
						  frm_class->type);
	tprintf("Classifier Mask: 0x%x, ", frm_class->mask);

	if(frm_class->type == 0) {
		struct element_tclas_type0 *type0;
		
		type0 =	(struct element_tclas_type0 *)
				  pkt_pull(pkt, sizeof(*type0));
		if (type0 == NULL)
			return 0;
		
		/* I think little endian, like the rest */
		tprintf("Src Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, ",
		type0->sa[5], type0->sa[4], type0->sa[3],
		type0->sa[2], type0->sa[1], type0->sa[0]);
		tprintf("Dst Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, ",
		type0->da[5], type0->da[4], type0->da[3],
		type0->da[2], type0->da[1], type0->da[0]);
		tprintf("Type: 0x%x", le16_to_cpu(type0->type));
	}
	else if(frm_class->type == 1) {
		struct element_tclas_type1 *type1;
		
		type1 =	(struct element_tclas_type1 *)
				  pkt_pull(pkt, sizeof(*type1));
		if (type1 == NULL)
			return 0;
		
		tprintf("Version: %u, ", type1->version);
		/* big endian format follows */
		if(type1->version == 4) {
			struct element_tclas_type1_ip4 *type1_ip4;
			char src_ip[INET_ADDRSTRLEN];
			char dst_ip[INET_ADDRSTRLEN];
			 
			type1_ip4 = (struct element_tclas_type1_ip4 *)
					  pkt_pull(pkt, sizeof(*type1_ip4));
			if (type1_ip4 == NULL)
				return 0;

			inet_ntop(AF_INET, &type1_ip4->sa, src_ip, sizeof(src_ip));
			inet_ntop(AF_INET, &type1_ip4->da, dst_ip, sizeof(dst_ip));
			 
			tprintf("Src IP: %s, ", src_ip);
			tprintf("Dst IP: %s, ", dst_ip);
			tprintf("Src Port: %u, ", ntohs(type1_ip4->sp));
			tprintf("Dst Port: %u, ", ntohs(type1_ip4->dp));
			tprintf("DSCP: 0x%x, ", type1_ip4->dscp);
			tprintf("Proto: %u, ", type1_ip4->proto);
			tprintf("Res: 0x%x", type1_ip4->reserved);
		}
		else if(type1->version == 6) {
			struct element_tclas_type1_ip6 *type1_ip6;
			char src_ip[INET6_ADDRSTRLEN];
			char dst_ip[INET6_ADDRSTRLEN];

			type1_ip6 = (struct element_tclas_type1_ip6 *)
					  pkt_pull(pkt, sizeof(*type1_ip6));
			if (type1_ip6 == NULL)
				return 0;

			inet_ntop(AF_INET6, &type1_ip6->sa,
				  src_ip, sizeof(src_ip));
			inet_ntop(AF_INET6, &type1_ip6->da,
				  dst_ip, sizeof(dst_ip));

			tprintf("Src IP: %s, ", src_ip);
			tprintf("Dst IP: %s, ", dst_ip);
			tprintf("Src Port: %u, ", ntohs(type1_ip6->sp));
			tprintf("Dst Port: %u, ", ntohs(type1_ip6->dp));
			tprintf("Flow Label: 0x%x%x%x", type1_ip6->flow_label1,
				type1_ip6->flow_label2, type1_ip6->flow_label3);
		}
		else {
			tprintf("Version (%u) not supported", type1->version);
			return 0;
		}
		  
	}
	else if(frm_class->type == 2) {
		struct element_tclas_type2 *type2;

		type2 =	(struct element_tclas_type2 *)
				  pkt_pull(pkt, sizeof(*type2));
		if (type2 == NULL)
			return 0;

		tprintf("802.1Q VLAN TCI: 0x%x", ntohs(type2->vlan_tci));
	}
	else if(frm_class->type == 3) {
		struct element_tclas_type3 *type3;
		u8 len, i;
		u8 *val;

		type3 =	(struct element_tclas_type3 *)
				  pkt_pull(pkt, sizeof(*type3));
		if (type3 == NULL)
			return 0;

		len = (tclas->len - 5) / 2;

		tprintf("Filter Offset: %u, ", type3->offs);
		
		if((len & 1) || (len_lt_error(tclas->len, 5))) {
			tprintf("Length of TCLAS (%u) not correct", tclas->len);
			return 0;
		}
		else {
			val = pkt_pull(pkt, len);
			if (val == NULL)
				return 0;

			tprintf("Filter Value: 0x");
			for (i = 0; i < len / 2; i++)
				tprintf("%x ", val[i]);
			tprintf(", ");
			tprintf("Filter Mask: 0x");
			for (i = len / 2; i < len; i++)
				tprintf("%x ", val[i]);
		}
		
	}
	else if(frm_class->type == 4) {
		struct element_tclas_type4 *type4;

		type4 =	(struct element_tclas_type4 *)
				  pkt_pull(pkt, sizeof(*type4));
		if (type4 == NULL)
			return 0;

		tprintf("Version: %u, ", type4->version);
		/* big endian format follows */
		if(type4->version == 4) {
			struct element_tclas_type4_ip4 *type4_ip4;
			char src_ip[INET_ADDRSTRLEN];
			char dst_ip[INET_ADDRSTRLEN];

			type4_ip4 = (struct element_tclas_type4_ip4 *)
					  pkt_pull(pkt, sizeof(*type4_ip4));
			if (type4_ip4 == NULL)
				return 0;

			inet_ntop(AF_INET, &type4_ip4->sa, src_ip, sizeof(src_ip));
			inet_ntop(AF_INET, &type4_ip4->da, dst_ip, sizeof(dst_ip));

			tprintf("Src IP: %s, ", src_ip);
			tprintf("Dst IP: %s, ", dst_ip);
			tprintf("Src Port: %u, ", ntohs(type4_ip4->sp));
			tprintf("Dst Port: %u, ", ntohs(type4_ip4->dp));
			tprintf("DSCP: 0x%x, ", type4_ip4->dscp);
			tprintf("Proto: %u, ", type4_ip4->proto);
			tprintf("Res: 0x%x", type4_ip4->reserved);
		}
		else if(type4->version == 6) {
			struct element_tclas_type4_ip6 *type4_ip6;
			char src_ip[INET6_ADDRSTRLEN];
			char dst_ip[INET6_ADDRSTRLEN];

			type4_ip6 = (struct element_tclas_type4_ip6 *)
					  pkt_pull(pkt, sizeof(*type4_ip6));
			if (type4_ip6 == NULL)
				return 0;

			inet_ntop(AF_INET6, &type4_ip6->sa,
				  src_ip, sizeof(src_ip));
			inet_ntop(AF_INET6, &type4_ip6->da,
				  dst_ip, sizeof(dst_ip));

			tprintf("Src IP: %s, ", src_ip);
			tprintf("Dst IP: %s, ", dst_ip);
			tprintf("Src Port: %u, ", ntohs(type4_ip6->sp));
			tprintf("Dst Port: %u, ", ntohs(type4_ip6->dp));
			tprintf("DSCP: 0x%x, ", type4_ip6->dscp);
			tprintf("Nxt Hdr: %u, ", type4_ip6->nxt_hdr);
			tprintf("Flow Label: 0x%x%x%x", type4_ip6->flow_label1,
				type4_ip6->flow_label2, type4_ip6->flow_label3);
		}
		else {
			tprintf("Version (%u) not supported", type4->version);
			return 0;
		}
	}
	else if(frm_class->type == 5) {
		struct element_tclas_type5 *type5;

		type5 =	(struct element_tclas_type5 *)
				  pkt_pull(pkt, sizeof(*type5));
		if (type5 == NULL)
			return 0;

		tprintf("802.1Q PCP: 0x%x, ", type5->pcp);
		tprintf("802.1Q CFI: 0x%x, ", type5->cfi);
		tprintf("802.1Q VID: 0x%x", type5->vid);
	}
	else {
		tprintf("Classifier Type (%u) not supported", frm_class->type);
		return 0;
	}

	return 1;
}

static int8_t inf_sched(struct pkt_buff *pkt, u8 *id)
{
	struct element_schedule *schedule;
	u16 info;

	schedule = (struct element_schedule *) pkt_pull(pkt, sizeof(*schedule));
	if (schedule == NULL)
		return 0;

	info = le16_to_cpu(schedule->inf);

	tprintf(" Schedule (%u, Len(%u)): ", *id, schedule->len);
	if (len_neq_error(schedule->len, 12))
		return 0;
	
	tprintf("Aggregation: %u, ", info >> 15);
	tprintf("TSID: %u, ", (info >> 11) & 0xF);
	tprintf("Direction: %u, ", (info >> 9) & 0x3);
	tprintf("Res: %u, ", info & 0x1FF);
	tprintf("Serv Start Time: %uus, ", le32_to_cpu(schedule->start));
	tprintf("Serv Interval: %uus, ", le32_to_cpu(schedule->serv_intv));
	tprintf("Spec Interval: %fs", le32_to_cpu(schedule->spec_intv) * TU);

	return 1;
}

static int8_t inf_chall_txt(struct pkt_buff *pkt, u8 *id)
{
	struct element_chall_txt *chall_txt;
	u8 i;
	u8 *txt;

	chall_txt = (struct element_chall_txt *)
			pkt_pull(pkt, sizeof(*chall_txt));
	if (chall_txt == NULL)
		return 0;

	tprintf(" Challenge Text (%u, Len(%u)): ", *id, chall_txt->len);
	if ((chall_txt->len - sizeof(*chall_txt) + 1) > 0) {
		txt = pkt_pull(pkt, (chall_txt->len - sizeof(*chall_txt) + 1));
		if (txt == NULL)
			return 0;

		tprintf("0x");
		for (i = 0; i < (chall_txt->len - sizeof(*chall_txt) + 1); i++)
			tprintf("%x", txt[i]);
	}

	return 1;
}

static int8_t inf_pwr_constr(struct pkt_buff *pkt, u8 *id)
{
	struct element_pwr_constr *pwr_constr;

	pwr_constr = (struct element_pwr_constr *) pkt_pull(pkt, sizeof(*pwr_constr));
	if (pwr_constr == NULL)
		return 0;

	tprintf(" Power Constraint (%u, Len(%u)): ", *id, pwr_constr->len);
	if (len_neq_error(pwr_constr->len, 1))
		return 0;

	tprintf("Local Power Constraint: %udB", pwr_constr->local_pwr_constr);

	return 1;
}

static int8_t inf_pwr_cap(struct pkt_buff *pkt, u8 *id)
{
	struct element_pwr_cap *pwr_cap;

	pwr_cap = (struct element_pwr_cap *) pkt_pull(pkt, sizeof(*pwr_cap));
	if (pwr_cap == NULL)
		return 0;

	tprintf(" Power Capability (%u, Len(%u)): ", *id, pwr_cap->len);
	if (len_neq_error(pwr_cap->len, 2))
		return 0;

	tprintf("Min. Transm. Pwr Cap.: %ddBm, ", (int8_t)pwr_cap->min_pwr_cap);
	tprintf("Max. Transm. Pwr Cap.: %ddBm", (int8_t)pwr_cap->max_pwr_cap);

	return 1;
}

static int8_t inf_tpc_req(struct pkt_buff *pkt, u8 *id)
{
	struct element_tpc_req *tpc_req;

	tpc_req = (struct element_tpc_req *) pkt_pull(pkt, sizeof(*tpc_req));
	if (tpc_req == NULL)
		return 0;

	tprintf(" TPC Request (%u, Len(%u))", *id, tpc_req->len);
	if (len_neq_error(tpc_req->len, 0))
		return 0;

	return 1;
}

static int8_t inf_tpc_rep(struct pkt_buff *pkt, u8 *id)
{
	struct element_tpc_rep *tpc_rep;

	tpc_rep = (struct element_tpc_rep *) pkt_pull(pkt, sizeof(*tpc_rep));
	if (tpc_rep == NULL)
		return 0;

	tprintf(" TPC Report (%u, Len(%u)): ", *id, tpc_rep->len);
	if (len_neq_error(tpc_rep->len, 2))
		return 0;

	tprintf("Transmit Power: %udBm, ", (int8_t)tpc_rep->trans_pwr);
	tprintf("Link Margin: %udB", (int8_t)tpc_rep->trans_pwr);

	return 1;
}

static int8_t inf_supp_ch(struct pkt_buff *pkt, u8 *id)
{
	struct element_supp_ch *supp_ch;
	u8 i;

	supp_ch = (struct element_supp_ch *) pkt_pull(pkt, sizeof(*supp_ch));
	if (supp_ch == NULL)
		return 0;

	tprintf(" Supp Channels (%u, Len(%u)): ", *id, supp_ch->len);
	if (len_lt_error(supp_ch->len, 2))
		return 0;

	if(supp_ch->len & 1) {
		tprintf("Length should be even");
		return 0;
	}
  
	for (i = 0; i < supp_ch->len; i += 2) {
		struct element_supp_ch_tuple *supp_ch_tuple;

		supp_ch_tuple = (struct element_supp_ch_tuple *)
				    pkt_pull(pkt, sizeof(*supp_ch_tuple));
		if (supp_ch_tuple == NULL)
			return 0;

		tprintf("First Channel Nr: %u, ", supp_ch_tuple->first_ch_nr);
		tprintf("Nr of Channels: %u, ", supp_ch_tuple->nr_ch);
	}

	return 1;
}

static int8_t inf_ch_sw_ann(struct pkt_buff *pkt, u8 *id)
{
	struct element_ch_sw_ann *ch_sw_ann;

	ch_sw_ann = (struct element_ch_sw_ann *)
			pkt_pull(pkt, sizeof(*ch_sw_ann));
	if (ch_sw_ann == NULL)
		return 0;

	tprintf(" Channel Switch Announc (%u, Len(%u)): ", *id, ch_sw_ann->len);
	if (len_neq_error(ch_sw_ann->len, 3))
		return 0;

	tprintf("Switch Mode: %u, ", ch_sw_ann->switch_mode);
	tprintf("New Nr: %u, ", ch_sw_ann->new_nr);
	tprintf("Switch Count: %u", ch_sw_ann->switch_cnt);

	return 1;
}

static const char *meas_type(u8 type)
{
	switch (type) {
	case 0:  return "Basic";
	case 1:  return "Clear Channel assesment (CCA)";
	case 2:  return "Receive power indication (RPI) histogram";
	case 3:  return "Channel load";
	case 4:  return "Noise histogram";
	case 5:  return "Beacon";
	case 6:  return "Frame";
	case 7:  return "STA statistics";
	case 8:  return "LCI";
	case 9:  return "Transmit stream/category measurement";
	case 10: return "Multicast diagnostics";
	case 11: return "Location Civic";
	case 12: return "Location Identifier";
	default: return "Reserved";
	}
}

static int8_t inf_meas_req(struct pkt_buff *pkt, u8 *id)
{
	struct element_meas_req *meas_req;

	meas_req = (struct element_meas_req *) pkt_pull(pkt, sizeof(*meas_req));
	if (meas_req == NULL)
		return 0;

	tprintf(" Measurement Req (%u, Len(%u)): ", *id, meas_req->len);
	if (len_lt_error(meas_req->len, 3))
		return 0;

	tprintf("Token: %u, ", meas_req->token);
	tprintf("Req Mode: 0x%x (Parallel (%u), Enable(%u), Request(%u), "
	"Report(%u), Dur Mand(%u), Res(0x%x)),  ", meas_req->req_mode,
					meas_req->req_mode & 0x1,
					(meas_req->req_mode >> 1) & 0x1,
					(meas_req->req_mode >> 2) & 0x1,
					(meas_req->req_mode >> 3) & 0x1,
					(meas_req->req_mode >> 4) & 0x1,
					meas_req->req_mode >> 7);
	tprintf("Type: %s (%u), ", meas_type(meas_req->type), meas_req->type);

	if(meas_req->len > 3) {
		if(meas_req->type == 0) {
			struct element_meas_basic *basic;

			basic = (struct element_meas_basic *)
				    pkt_pull(pkt, sizeof(*basic));
			if (basic == NULL)
				return 0;

			if ((meas_req->len - 3 - sizeof(*basic)) != 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Ch Nr: %uus, ", basic->ch_nr);
			tprintf("Meas Start Time: %"PRIu64", ",
				    le64_to_cpu(basic->start));
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(basic->dur) * TU);
			
		}
		else if(meas_req->type == 1) {
			struct element_meas_cca *cca;

			cca = (struct element_meas_cca *)
				    pkt_pull(pkt, sizeof(*cca));
			if (cca == NULL)
				return 0;

			if ((meas_req->len - 3 - sizeof(*cca)) != 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Ch Nr: %uus, ", cca->ch_nr);
			tprintf("Meas Start Time: %"PRIu64", ",
				    le64_to_cpu(cca->start));
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(cca->dur) * TU);
		}
		else if(meas_req->type == 2) {
			struct element_meas_rpi *rpi;

			rpi = (struct element_meas_rpi *)
				    pkt_pull(pkt, sizeof(*rpi));
			if (rpi == NULL)
				return 0;

			if ((meas_req->len - 3 - sizeof(*rpi)) != 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Ch Nr: %uus, ", rpi->ch_nr);
			tprintf("Meas Start Time: %"PRIu64", ",
				    le64_to_cpu(rpi->start));
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(rpi->dur) * TU);
		}
		else if(meas_req->type == 3) {
			struct element_meas_ch_load *ch_load;

			ch_load = (struct element_meas_ch_load *)
				    pkt_pull(pkt, sizeof(*ch_load));
			if (ch_load == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*ch_load)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("OP Class: %u, ", ch_load->op_class);
			tprintf("Ch Nr: %u, ", ch_load->ch_nr);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(ch_load->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(ch_load->dur) * TU);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*ch_load)))
				return 0;
		}
		else if(meas_req->type == 4) {
			struct element_meas_noise *noise;

			noise = (struct element_meas_noise *)
				    pkt_pull(pkt, sizeof(*noise));
			if (noise == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*noise)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("OP Class: %u, ", noise->op_class);
			tprintf("Ch Nr: %u, ", noise->ch_nr);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(noise->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(noise->dur) * TU);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*noise)))
				return 0;
		}
		else if(meas_req->type == 5) {
			struct element_meas_beacon *beacon;

			beacon = (struct element_meas_beacon *)
				    pkt_pull(pkt, sizeof(*beacon));
			if (beacon == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*beacon)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("OP Class: %u, ", beacon->op_class);
			tprintf("Ch Nr: %u, ", beacon->ch_nr);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(beacon->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(beacon->dur) * TU);
			tprintf("Mode: %u, ", beacon->mode);
			tprintf("BSSID: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				    beacon->bssid[0], beacon->bssid[1],
				    beacon->bssid[2], beacon->bssid[3],
				    beacon->bssid[4], beacon->bssid[5]);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*beacon)))
				return 0;
		}
		else if(meas_req->type == 6) {
			struct element_meas_frame *frame;

			frame = (struct element_meas_frame *)
				    pkt_pull(pkt, sizeof(*frame));
			if (frame == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*frame)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("OP Class: %u, ", frame->op_class);
			tprintf("Ch Nr: %u, ", frame->ch_nr);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(frame->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(frame->dur) * TU);
			tprintf("Request Type: %u, ", frame->frame);
			tprintf("MAC Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				    frame->mac[0], frame->mac[1],
				    frame->mac[2], frame->mac[3],
				    frame->mac[4], frame->mac[5]);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*frame)))
				return 0;
		}
		else if(meas_req->type == 7) {
			struct element_meas_sta *sta;

			sta = (struct element_meas_sta *)
				    pkt_pull(pkt, sizeof(*sta));
			if (sta == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*sta)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Peer MAC Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				    sta->peer_mac[0], sta->peer_mac[1],
				    sta->peer_mac[2], sta->peer_mac[3],
				    sta->peer_mac[4], sta->peer_mac[5]);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(sta->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(sta->dur) * TU);
			tprintf("Group ID: %u, ", sta->group_id);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*sta)))
				return 0;
		}
		else if(meas_req->type == 8) {
			struct element_meas_lci *lci;

			lci = (struct element_meas_lci *)
				    pkt_pull(pkt, sizeof(*lci));
			if (lci == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*lci)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Location Subj: %u, ", lci->loc_subj);
			tprintf("Latitude Req Res: %udeg",
				    lci->latitude_req_res);
			tprintf("Longitude Req Res: %udeg",
				    lci->longitude_req_res);
			tprintf("Altitude Req Res: %udeg",
				    lci->altitude_req_res);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*lci)))
				return 0;
		}
		else if(meas_req->type == 9) {
			struct element_meas_trans_str_cat *trans;

			trans = (struct element_meas_trans_str_cat *)
				    pkt_pull(pkt, sizeof(*trans));
			if (trans == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*trans)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(trans->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(trans->dur) * TU);
			tprintf("MAC Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				trans->peer_sta_addr[0], trans->peer_sta_addr[1],
				trans->peer_sta_addr[2], trans->peer_sta_addr[3],
				trans->peer_sta_addr[4], trans->peer_sta_addr[5]);
			tprintf("Traffic ID: %u, ", trans->traffic_id);
			tprintf("Bin 0 Range: %u, ", trans->bin_0_range);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*trans)))
				return 0;
		}
		else if(meas_req->type == 10) {
			struct element_meas_mcast_diag *mcast;

			mcast = (struct element_meas_mcast_diag *)
				    pkt_pull(pkt, sizeof(*mcast));
			if (mcast == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*mcast)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(mcast->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(mcast->dur) * TU);
			tprintf("Group MAC Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				mcast->group_mac[0], mcast->group_mac[1],
				mcast->group_mac[2], mcast->group_mac[3],
				mcast->group_mac[4], mcast->group_mac[5]);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*mcast)))
				return 0;
		}
		else if(meas_req->type == 11) {
			struct element_meas_loc_civic *civic;

			civic = (struct element_meas_loc_civic *)
				    pkt_pull(pkt, sizeof(*civic));
			if (civic == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*civic)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Location Subj: %u, ", civic->loc_subj);
			tprintf("Type: %u, ", civic->civic_loc);
			tprintf("Srv Intv Units: %u, ",
				    le16_to_cpu(civic->loc_srv_intv_unit));
			tprintf("Srv Intv: %u, ", civic->loc_srv_intv);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*civic)))
				return 0;
		}
		else if(meas_req->type == 12) {
			struct element_meas_loc_id *id;

			id = (struct element_meas_loc_id *)
				    pkt_pull(pkt, sizeof(*id));
			if (id == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*id)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Location Subj: %u, ", id->loc_subj);
			tprintf("Srv Intv Units: %u, ",
				    le16_to_cpu(id->loc_srv_intv_unit));
			tprintf("Srv Intv: %u", id->loc_srv_intv);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*id)))
				return 0;
		}
		else if(meas_req->type == 255) {
			struct element_meas_pause *pause;

			pause = (struct element_meas_pause *)
				    pkt_pull(pkt, sizeof(*pause));
			if (pause == NULL)
				return 0;

			if ((ssize_t)(meas_req->len - 3 - sizeof(*pause)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_req->type);
				return 0;
			}

			tprintf("Pause Time: %fs, ", pause->time * 10 * TU);

			if(!subelements(pkt,
					  meas_req->len - 3 - sizeof(*pause)))
				return 0;
		}
		else {
			tprintf("Length field indicates data,"
			" but could not interpreted");
			return 0;
		}
	}

	return 1;
}

static int8_t inf_meas_rep(struct pkt_buff *pkt, u8 *id)
{
	struct element_meas_rep *meas_rep;

	meas_rep = (struct element_meas_rep *) pkt_pull(pkt, sizeof(*meas_rep));
	if (meas_rep == NULL)
		return 0;

	tprintf(" Measurement Rep (%u, Len(%u)): ", *id, meas_rep->len);
	if (len_lt_error(meas_rep->len, 3))
		return 0;

	tprintf("Token: %u, ", meas_rep->token);
	tprintf("Rep Mode: 0x%x (Late (%u), Incapable(%u), Refused(%u), ",
		meas_rep->rep_mode, meas_rep->rep_mode >> 7,
		(meas_rep->rep_mode >> 6) & 0x1,
		(meas_rep->rep_mode >> 5) & 0x1);
	tprintf("Type: %s (%u), ", meas_type(meas_rep->type), meas_rep->type);

	if(meas_rep->len > 3) {
		if(meas_rep->type == 0) {
			struct element_meas_basic *basic;

			basic = (struct element_meas_basic *)
				    pkt_pull(pkt, sizeof(*basic));
			if (basic == NULL)
				return 0;

			if ((meas_rep->len - 3 - sizeof(*basic)) != 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("Ch Nr: %uus, ", basic->ch_nr);
			tprintf("Meas Start Time: %"PRIu64", ",
				    le64_to_cpu(basic->start));
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(basic->dur) * TU);

		}
		else if(meas_rep->type == 1) {
			struct element_meas_cca *cca;

			cca = (struct element_meas_cca *)
				    pkt_pull(pkt, sizeof(*cca));
			if (cca == NULL)
				return 0;

			if ((meas_rep->len - 3 - sizeof(*cca)) != 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("Ch Nr: %uus, ", cca->ch_nr);
			tprintf("Meas Start Time: %"PRIu64", ",
				    le64_to_cpu(cca->start));
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(cca->dur) * TU);
		}
		else if(meas_rep->type == 2) {
			struct element_meas_rpi *rpi;

			rpi = (struct element_meas_rpi *)
				    pkt_pull(pkt, sizeof(*rpi));
			if (rpi == NULL)
				return 0;

			if ((meas_rep->len - 3 - sizeof(*rpi)) != 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("Ch Nr: %uus, ", rpi->ch_nr);
			tprintf("Meas Start Time: %"PRIu64", ",
				    le64_to_cpu(rpi->start));
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(rpi->dur) * TU);
		}
		else if(meas_rep->type == 3) {
			struct element_meas_ch_load *ch_load;

			ch_load = (struct element_meas_ch_load *)
				    pkt_pull(pkt, sizeof(*ch_load));
			if (ch_load == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*ch_load)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("OP Class: %u, ", ch_load->op_class);
			tprintf("Ch Nr: %u, ", ch_load->ch_nr);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(ch_load->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(ch_load->dur) * TU);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*ch_load)))
				return 0;
		}
		else if(meas_rep->type == 4) {
			struct element_meas_noise *noise;

			noise = (struct element_meas_noise *)
				    pkt_pull(pkt, sizeof(*noise));
			if (noise == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*noise)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("OP Class: %u, ", noise->op_class);
			tprintf("Ch Nr: %u, ", noise->ch_nr);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(noise->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(noise->dur) * TU);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*noise)))
				return 0;
		}
		else if(meas_rep->type == 5) {
			struct element_meas_beacon *beacon;

			beacon = (struct element_meas_beacon *)
				    pkt_pull(pkt, sizeof(*beacon));
			if (beacon == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*beacon)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("OP Class: %u, ", beacon->op_class);
			tprintf("Ch Nr: %u, ", beacon->ch_nr);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(beacon->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(beacon->dur) * TU);
			tprintf("Mode: %u, ", beacon->mode);
			tprintf("BSSID: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				    beacon->bssid[0], beacon->bssid[1],
				    beacon->bssid[2], beacon->bssid[3],
				    beacon->bssid[4], beacon->bssid[5]);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*beacon)))
				return 0;
		}
		else if(meas_rep->type == 6) {
			struct element_meas_frame *frame;

			frame = (struct element_meas_frame *)
				    pkt_pull(pkt, sizeof(*frame));
			if (frame == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*frame)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("OP Class: %u, ", frame->op_class);
			tprintf("Ch Nr: %u, ", frame->ch_nr);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(frame->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(frame->dur) * TU);
			tprintf("Request Type: %u, ", frame->frame);
			tprintf("MAC Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				    frame->mac[0], frame->mac[1],
				    frame->mac[2], frame->mac[3],
				    frame->mac[4], frame->mac[5]);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*frame)))
				return 0;
		}
		else if(meas_rep->type == 7) {
			struct element_meas_sta *sta;

			sta = (struct element_meas_sta *)
				    pkt_pull(pkt, sizeof(*sta));
			if (sta == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*sta)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("Peer MAC Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, ",
				    sta->peer_mac[0], sta->peer_mac[1],
				    sta->peer_mac[2], sta->peer_mac[3],
				    sta->peer_mac[4], sta->peer_mac[5]);
			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(sta->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(sta->dur) * TU);
			tprintf("Group ID: %u, ", sta->group_id);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*sta)))
				return 0;
		}
		else if(meas_rep->type == 8) {
			struct element_meas_lci *lci;

			lci = (struct element_meas_lci *)
				    pkt_pull(pkt, sizeof(*lci));
			if (lci == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*lci)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("Location Subj: %u, ", lci->loc_subj);
			tprintf("Latitude Req Res: %udeg",
				    lci->latitude_req_res);
			tprintf("Longitude Req Res: %udeg",
				    lci->longitude_req_res);
			tprintf("Altitude Req Res: %udeg",
				    lci->altitude_req_res);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*lci)))
				return 0;
		}
		else if(meas_rep->type == 9) {
			struct element_meas_trans_str_cat *trans;

			trans = (struct element_meas_trans_str_cat *)
				    pkt_pull(pkt, sizeof(*trans));
			if (trans == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*trans)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(trans->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(trans->dur) * TU);
			tprintf("MAC Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, ",
				trans->peer_sta_addr[0], trans->peer_sta_addr[1],
				trans->peer_sta_addr[2], trans->peer_sta_addr[3],
				trans->peer_sta_addr[4], trans->peer_sta_addr[5]);
			tprintf("Traffic ID: %u, ", trans->traffic_id);
			tprintf("Bin 0 Range: %u, ", trans->bin_0_range);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*trans)))
				return 0;
		}
		else if(meas_rep->type == 10) {
			struct element_meas_mcast_diag *mcast;

			mcast = (struct element_meas_mcast_diag *)
				    pkt_pull(pkt, sizeof(*mcast));
			if (mcast == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*mcast)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("Rand Intv: %fs, ",
				    le16_to_cpu(mcast->rand_intv) * TU);
			tprintf("Meas Duration: %fs",
				    le16_to_cpu(mcast->dur) * TU);
			tprintf("Group MAC Addr: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
				mcast->group_mac[0], mcast->group_mac[1],
				mcast->group_mac[2], mcast->group_mac[3],
				mcast->group_mac[4], mcast->group_mac[5]);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*mcast)))
				return 0;
		}
		else if(meas_rep->type == 11) {
			struct element_meas_loc_civic *civic;

			civic = (struct element_meas_loc_civic *)
				    pkt_pull(pkt, sizeof(*civic));
			if (civic == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*civic)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("Location Subj: %u, ", civic->loc_subj);
			tprintf("Type: %u, ", civic->civic_loc);
			tprintf("Srv Intv Units: %u, ",
				    le16_to_cpu(civic->loc_srv_intv_unit));
			tprintf("Srv Intv: %u, ", civic->loc_srv_intv);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*civic)))
				return 0;
		}
		else if(meas_rep->type == 12) {
			struct element_meas_loc_id *id;

			id = (struct element_meas_loc_id *)
				    pkt_pull(pkt, sizeof(*id));
			if (id == NULL)
				return 0;

			if ((ssize_t)(meas_rep->len - 3 - sizeof(*id)) < 0) {
				tprintf("Length of Req matchs not Type %u",
					    meas_rep->type);
				return 0;
			}

			tprintf("Location Subj: %u, ", id->loc_subj);
			tprintf("Srv Intv Units: %u, ",
				    le16_to_cpu(id->loc_srv_intv_unit));
			tprintf("Srv Intv: %u", id->loc_srv_intv);

			if(!subelements(pkt,
					  meas_rep->len - 3 - sizeof(*id)))
				return 0;
		}
		else {
			tprintf("Length field indicates data,"
			" but could not interpreted");
			return 0;
		}
	}

	return 1;
}

static int8_t inf_quiet(struct pkt_buff *pkt, u8 *id)
{
	struct element_quiet *quiet;

	quiet = (struct element_quiet *) pkt_pull(pkt, sizeof(*quiet));
	if (quiet == NULL)
		return 0;

	tprintf(" Quit (%u, Len(%u)): ", *id, quiet->len);
	if (len_neq_error(quiet->len, 6))
		return 0;

	tprintf("Count: %ud, ", quiet->cnt);
	tprintf("Period: %u, ", quiet->period);
	tprintf("Duration: %fs, ", le16_to_cpu(quiet->dur) * TU);
	tprintf("Offs: %fs", le16_to_cpu(quiet->offs) * TU);
	

	return 1;
}

static int8_t inf_ibss_dfs(struct pkt_buff *pkt, u8 *id)
{
	struct element_ibss_dfs *ibss_dfs;
	u8 i;

	ibss_dfs = (struct element_ibss_dfs *) pkt_pull(pkt, sizeof(*ibss_dfs));
	if (ibss_dfs == NULL)
		return 0;

	tprintf(" IBSS DFS (%u, Len(%u)): ", *id, ibss_dfs->len);
	if (len_lt_error(ibss_dfs->len, 7))
		return 0;

	tprintf("Owner: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, ",
		    ibss_dfs->owner[0], ibss_dfs->owner[1],
		    ibss_dfs->owner[2], ibss_dfs->owner[3],
		    ibss_dfs->owner[4], ibss_dfs->owner[5]);
	tprintf("Recovery Intv: %u, ", ibss_dfs->rec_intv);

	if((ibss_dfs->len - sizeof(*ibss_dfs) + 1) & 1) {
		tprintf("Length of Channel Map should be modulo 2");
		return 0;
	}

	for (i = 0; i < ibss_dfs->len; i += 2) {
		struct element_ibss_dfs_tuple *ibss_dfs_tuple;

		ibss_dfs_tuple = (struct element_ibss_dfs_tuple *)
				    pkt_pull(pkt, sizeof(*ibss_dfs_tuple));
		if (ibss_dfs_tuple == NULL)
			return 0;

		tprintf("Channel Nr: %u, ", ibss_dfs_tuple->ch_nr);
		tprintf("Map: %u, ", ibss_dfs_tuple->map);
	}

	return 1;
}

static int8_t inf_erp(struct pkt_buff *pkt, u8 *id)
{
	struct element_erp *erp;

	erp = (struct element_erp *) pkt_pull(pkt, sizeof(*erp));
	if (erp == NULL)
		return 0;

	tprintf(" ERP (%u, Len(%u)): ", *id, erp->len);
	if (len_neq_error(erp->len, 1))
		return 0;
	tprintf("Non ERP Present (%u), ", erp->param & 0x1);
	tprintf("Use Protection (%u), ", (erp->param >> 1) & 0x1);
	tprintf("Barker Preamble Mode (%u), ", (erp->param >> 2) & 0x1);
	tprintf("Reserved (0x%.5x)", erp->param >> 3);

	return 1;
}

static int8_t inf_ts_del(struct pkt_buff *pkt, u8 *id)
{
	struct element_ts_del *ts_del;

	ts_del = (struct element_ts_del *) pkt_pull(pkt, sizeof(*ts_del));
	if (ts_del == NULL)
		return 0;

	tprintf(" TS Delay (%u, Len(%u)): ", *id, ts_del->len);
	if (len_neq_error(ts_del->len, 4))
		return 0;
	tprintf("Delay (%fs)", le32_to_cpu(ts_del->delay) * TU);

	return 1;
}

static int8_t inf_tclas_proc(struct pkt_buff *pkt, u8 *id)
{
	struct element_tclas_proc *tclas_proc;

	tclas_proc = (struct element_tclas_proc *)
			  pkt_pull(pkt, sizeof(*tclas_proc));
	if (tclas_proc == NULL)
		return 0;

	tprintf(" TCLAS Procesing (%u, Len(%u)): ", *id, tclas_proc->len);
	if (len_neq_error(tclas_proc->len, 1))
		return 0;
	tprintf("Processing (%u)", tclas_proc->proc);

	return 1;
}

static int8_t inf_ht_cap(struct pkt_buff *pkt, u8 *id)
{
	struct element_ht_cap *ht_cap;
	u32 tx_param_res, beam_cap;
	u16 ext_cap;

	ht_cap = (struct element_ht_cap *)
			  pkt_pull(pkt, sizeof(*ht_cap));
	if (ht_cap == NULL)
		return 0;

	tx_param_res = le32_to_cpu(ht_cap->tx_param_res);
	beam_cap = le32_to_cpu(ht_cap->beam_cap);
	ext_cap = le16_to_cpu(ht_cap->ext_cap);

	tprintf(" HT Capabilities (%u, Len(%u)):\n", *id, ht_cap->len);
	if (len_neq_error(ht_cap->len, 26))
		return 0;

	tprintf("\t\t Info:\n");
	tprintf("\t\t\t LDCP Cod Cap (%u)\n", ht_cap->ldpc);
	tprintf("\t\t\t Supp Ch Width Set (%u)\n", ht_cap->supp_width);
	tprintf("\t\t\t SM Pwr Save(%u)\n", ht_cap->sm_pwr);
	tprintf("\t\t\t HT-Greenfield (%u)\n", ht_cap->ht_green);
	tprintf("\t\t\t Short GI for 20/40 MHz (%u/%u)\n", ht_cap->gi_20mhz,
			ht_cap->gi_40mhz);
	tprintf("\t\t\t Tx/Rx STBC (%u/%u)\n", ht_cap->tx_stbc,
			ht_cap->rx_stbc);
	tprintf("\t\t\t HT-Delayed Block Ack (%u)\n", ht_cap->ht_ack);
	tprintf("\t\t\t Max A-MSDU Len (%u)\n", ht_cap->max_msdu_length);
	tprintf("\t\t\t DSSS/CCK Mode in 40 MHz (%u)\n",
			ht_cap->dsss_ck_mode);
	tprintf("\t\t\t Res (0x%x)\n", ht_cap->res);
	tprintf("\t\t\t Forty MHz Intol (%u)\n", ht_cap->forty_int);
	tprintf("\t\t\t L-SIG TXOP Protection Supp (%u)\n",
			ht_cap->prot_supp);

	tprintf("\t\t A-MPDU Params:\n");
	tprintf("\t\t\t Max Len Exp (%u)\n", ht_cap->param >> 6);
	tprintf("\t\t\t Min Start Spacing (%u)\n",
			(ht_cap->param >> 3) & 0x7);
	tprintf("\t\t\t Res (0x%x)\n", ht_cap->param & 0x07);

	tprintf("\t\t Supp MCS Set:\n");
	tprintf("\t\t\t Rx MCS Bitmask (0x%x%x%x%x%x%x%x%x%x%x)\n",
			ht_cap->bitmask1, ht_cap->bitmask2, ht_cap->bitmask3,
			ht_cap->bitmask4, ht_cap->bitmask5, ht_cap->bitmask6,
			ht_cap->bitmask7, ht_cap->bitmask8, ht_cap->bitmask9,
			ht_cap->bitmask10_res >> 3);
	tprintf("\t\t\t Res (0x%x)\n", ht_cap->bitmask10_res & 0x7);
	tprintf("\t\t\t Rx High Supp Data Rate (%u)\n",
			le16_to_cpu(ht_cap->supp_rate_res) >> 6);
	tprintf("\t\t\t Res (0x%x)\n",
			le16_to_cpu(ht_cap->supp_rate_res) & 0x3F);
	tprintf("\t\t\t Tx MCS Set Def (%u)\n", tx_param_res >> 31);
	tprintf("\t\t\t Tx Rx MCS Set Not Eq (%u)\n",
			(tx_param_res >> 30) & 1);
	tprintf("\t\t\t Tx Max Number Spat Str Supp (%u)\n",
			(tx_param_res >> 28) & 3);
	tprintf("\t\t\t Tx Uneq Mod Supp (%u)\n", (tx_param_res >> 27) & 1);
	tprintf("\t\t\t Res (0x%x)\n", tx_param_res & 0x7FFFFFF);

	tprintf("\t\t Ext Cap:\n");
	tprintf("\t\t\t PCO (%u)\n", ext_cap >> 15);
	tprintf("\t\t\t PCO Trans Time (%u)\n", (ext_cap >> 13) & 3);
	tprintf("\t\t\t Res (0x%x)\n", (ext_cap >> 8) & 0x1F);
	tprintf("\t\t\t MCS Feedb (%u)\n", (ext_cap >> 6) & 3);
	tprintf("\t\t\t +HTC Supp (%u)\n", (ext_cap >> 5) & 1);
	tprintf("\t\t\t RD Resp (%u)\n", (ext_cap >> 4) & 1);
	tprintf("\t\t\t Res (0x%x)\n", ext_cap & 0xF);

	tprintf("\t\t Transm Beamf:\n");
	tprintf("\t\t\t Impl Transm Beamf Rec Cap (%u)\n", beam_cap >> 31);
	tprintf("\t\t\t Rec/Transm Stagg Sound Cap (%u/%u)\n",
			(beam_cap >> 30) & 1, (beam_cap >> 29) & 1);
	tprintf("\t\t\t Rec/Trans NDP Cap (%u/%u)\n",
			(beam_cap >> 28) & 1, (beam_cap >> 27) & 1);
	tprintf("\t\t\t Impl Transm Beamf Cap (%u)\n", (beam_cap >> 26) & 1);
	tprintf("\t\t\t Cal (%u)\n", (beam_cap >> 24) & 3);
	tprintf("\t\t\t Expl CSI Transm Beamf Cap (%u)\n",
			(beam_cap >> 23) & 1);
	tprintf("\t\t\t Expl Noncmpr/Compr Steering Cap (%u/%u)\n",
			(beam_cap >> 22) & 1, (beam_cap >> 21) & 1);
	tprintf("\t\t\t Expl Trans Beamf CSI Feedb (%u)\n",
			(beam_cap >> 19) & 3);
	tprintf("\t\t\t Expl Noncmpr/Cmpr Feedb Cap (%u/%u)\n",
			(beam_cap >> 17) & 3, (beam_cap >> 15) & 3);
	tprintf("\t\t\t Min Grpg (%u)\n", (beam_cap >> 13) & 3);
	tprintf("\t\t\t CSI Num Beamf Ant Supp (%u)\n", (beam_cap >> 11) & 3);
	tprintf("\t\t\t Noncmpr/Cmpr Steering Nr Beamf Ant Supp (%u/%u)\n",
			(beam_cap >> 9) & 3, (beam_cap >> 7) & 3);
	tprintf("\t\t\t CSI Max Nr Rows Beamf Supp (%u)\n",
			(beam_cap >> 5) & 3);
	tprintf("\t\t\t Ch Estim Cap (%u)\n", (beam_cap >> 3) & 3);
	tprintf("\t\t\t Res (0x%x)\n", beam_cap & 7);

	tprintf("\t\t ASEL:\n");
	tprintf("\t\t\t Ant Select Cap (%u)\n", ht_cap->asel_cap >> 7);
	tprintf("\t\t\t Expl CSI Feedb Based Transm ASEL Cap (%u)\n",
			(ht_cap->asel_cap >> 6) & 1);
	tprintf("\t\t\t Ant Indic Feedb Based Transm ASEL Cap (%u)\n",
			(ht_cap->asel_cap >> 5) & 1);
	tprintf("\t\t\t Expl CSI Feedb Cap (%u)\n",
			(ht_cap->asel_cap >> 4) & 1);
	tprintf("\t\t\t Ant Indic Feedb Cap (%u)\n",
			(ht_cap->asel_cap >> 3) & 1);
	tprintf("\t\t\t Rec ASEL Cap (%u)\n", (ht_cap->asel_cap >> 2) & 1);
	tprintf("\t\t\t Transm Sound PPDUs Cap (%u)\n",
			(ht_cap->asel_cap >> 1) & 1);
	tprintf("\t\t\t Res (0x%x)", ht_cap->asel_cap & 1);

	return 1;
}

static int8_t inf_qos_cap(struct pkt_buff *pkt, u8 *id)
{
	struct element_qos_cap *qos_cap;

	qos_cap = (struct element_qos_cap *)
			  pkt_pull(pkt, sizeof(*qos_cap));
	if (qos_cap == NULL)
		return 0;

	tprintf(" QoS Capabilities (%u, Len(%u)): ", *id, qos_cap->len);
	if (len_neq_error(qos_cap->len, 1))
		return 0;

	tprintf("Info (0x%x)", qos_cap->info);

	return 1;
}

static int8_t inf_ext_supp_rates(struct pkt_buff *pkt, u8 *id)
{
	u8 i;
	u8 *rates;
	struct element_ext_supp_rates *ext_supp_rates;

	ext_supp_rates = (struct element_ext_supp_rates *)
				pkt_pull(pkt, sizeof(*ext_supp_rates));
	if (ext_supp_rates == NULL)
		return 0;

	tprintf(" Ext Support Rates (%u, Len(%u)): ", *id, ext_supp_rates->len);

	if ((ext_supp_rates->len - sizeof(*ext_supp_rates) + 1) > 0) {
		rates = pkt_pull(pkt, ext_supp_rates->len);
		if (rates == NULL)
			return 0;

		for (i = 0; i < ext_supp_rates->len; i++)
			tprintf("%g ", (rates[i] & 0x80) ?
				((rates[i] & 0x3f) * 0.5) :
				data_rates(rates[i]));
		return 1;
	}

	return 0;
}

static int8_t inf_vend_spec(struct pkt_buff *pkt, u8 *id)
{
	u8 i;
	u8 *data;
	struct element_vend_spec *vend_spec;

	vend_spec = (struct element_vend_spec *)
			pkt_pull(pkt, sizeof(*vend_spec));
	if (vend_spec == NULL)
		return 0;

	tprintf(" Vendor Specific (%u, Len (%u)): ", *id, vend_spec->len);

	data = pkt_pull(pkt, vend_spec->len);
	if (data == NULL)
		return 0;

	tprintf("Data 0x");
	for (i = 0; i < vend_spec->len; i++)
		tprintf("%.2x", data[i]);

	return 1;
}

static int8_t inf_unimplemented(struct pkt_buff *pkt __maybe_unused,
				u8 *id __maybe_unused)
{
	return 0;
}

static int8_t inf_elements(struct pkt_buff *pkt)
{
	u8 *id = pkt_pull(pkt, 1);
	if (id == NULL)
		return 0;

	switch (*id) {
	case   0: return inf_ssid(pkt, id);
	case   1: return inf_supp_rates(pkt, id);
	case   2: return inf_fh_ps(pkt, id);
	case   3: return inf_dsss_ps(pkt, id);
	case   4: return inf_cf_ps(pkt, id);
	case   5: return inf_tim(pkt, id);
	case   6: return inf_ibss_ps(pkt, id);
	case   7: return inf_country(pkt, id);
	case   8: return inf_hop_pp(pkt, id);
	case   9: return inf_hop_pt(pkt, id);
	case  10: return inf_req(pkt, id);
	case  11: return inf_bss_load(pkt, id);
	case  12: return inf_edca_ps(pkt, id);
	case  13: return inf_tspec(pkt, id);
	case  14: return inf_tclas(pkt, id);
	case  15: return inf_sched(pkt, id);
	case  16: return inf_chall_txt(pkt, id);
	case  17 ... 31: return inf_reserved(pkt, id);
	case  32: return inf_pwr_constr(pkt, id);
	case  33: return inf_pwr_cap(pkt, id);
	case  34: return inf_tpc_req(pkt, id);
	case  35: return inf_tpc_rep(pkt, id);
	case  36: return inf_supp_ch(pkt, id);
	case  37: return inf_ch_sw_ann(pkt, id);
	case  38: return inf_meas_req(pkt, id);
	case  39: return inf_meas_rep(pkt, id);
	case  40: return inf_quiet(pkt, id);
	case  41: return inf_ibss_dfs(pkt, id);
	case  42: return inf_erp(pkt, id);
	case  43: return inf_ts_del(pkt, id);
	case  44: return inf_tclas_proc(pkt, id);
	case  45: return inf_ht_cap(pkt, id);
	case  46: return inf_qos_cap(pkt, id);
	case  47: return inf_reserved(pkt, id);
	case  48: return inf_unimplemented(pkt, id);
	case  49: return inf_unimplemented(pkt, id);
	case  50: return inf_ext_supp_rates(pkt, id);
	case  51: return inf_unimplemented(pkt, id);
	case  52: return inf_unimplemented(pkt, id);
	case  53: return inf_unimplemented(pkt, id);
	case  54: return inf_unimplemented(pkt, id);
	case  55: return inf_unimplemented(pkt, id);
	case  56: return inf_unimplemented(pkt, id);
	case  57: return inf_unimplemented(pkt, id);
	case  58: return inf_unimplemented(pkt, id);
	case  59: return inf_unimplemented(pkt, id);
	case  60: return inf_unimplemented(pkt, id);
	case  61: return inf_unimplemented(pkt, id);
	case  62: return inf_unimplemented(pkt, id);
	case  63: return inf_unimplemented(pkt, id);
	case  64: return inf_unimplemented(pkt, id);
	case  65: return inf_unimplemented(pkt, id);
	case  66: return inf_unimplemented(pkt, id);
	case  67: return inf_unimplemented(pkt, id);
	case  68: return inf_unimplemented(pkt, id);
	case  69: return inf_unimplemented(pkt, id);
	case  70: return inf_unimplemented(pkt, id);
	case  71: return inf_unimplemented(pkt, id);
	case  72: return inf_unimplemented(pkt, id);
	case  73: return inf_unimplemented(pkt, id);
	case  74: return inf_unimplemented(pkt, id);
	case  75: return inf_unimplemented(pkt, id);
	case  76: return inf_unimplemented(pkt, id);
	case  78: return inf_unimplemented(pkt, id);
	case  79: return inf_unimplemented(pkt, id);
	case  80: return inf_unimplemented(pkt, id);
	case  81: return inf_unimplemented(pkt, id);
	case  82: return inf_unimplemented(pkt, id);
	case  83: return inf_unimplemented(pkt, id);
	case  84: return inf_unimplemented(pkt, id);
	case  85: return inf_unimplemented(pkt, id);
	case  86: return inf_unimplemented(pkt, id);
	case  87: return inf_unimplemented(pkt, id);
	case  88: return inf_unimplemented(pkt, id);
	case  89: return inf_unimplemented(pkt, id);
	case  90: return inf_unimplemented(pkt, id);
	case  91: return inf_unimplemented(pkt, id);
	case  92: return inf_unimplemented(pkt, id);
	case  93: return inf_unimplemented(pkt, id);
	case  94: return inf_unimplemented(pkt, id);
	case  95: return inf_unimplemented(pkt, id);
	case  96: return inf_unimplemented(pkt, id);
	case  97: return inf_unimplemented(pkt, id);
	case  98: return inf_unimplemented(pkt, id);
	case  99: return inf_unimplemented(pkt, id);
	case 100: return inf_unimplemented(pkt, id);
	case 101: return inf_unimplemented(pkt, id);
	case 102: return inf_unimplemented(pkt, id);
	case 104: return inf_unimplemented(pkt, id);
	case 105: return inf_unimplemented(pkt, id);
	case 106: return inf_unimplemented(pkt, id);
	case 107: return inf_unimplemented(pkt, id);
	case 108: return inf_unimplemented(pkt, id);
	case 109: return inf_unimplemented(pkt, id);
	case 110: return inf_unimplemented(pkt, id);
	case 111: return inf_unimplemented(pkt, id);
	case 112: return inf_unimplemented(pkt, id);
	case 113: return inf_unimplemented(pkt, id);
	case 114: return inf_unimplemented(pkt, id);
	case 115: return inf_unimplemented(pkt, id);
	case 116: return inf_unimplemented(pkt, id);
	case 117: return inf_unimplemented(pkt, id);
	case 118: return inf_unimplemented(pkt, id);
	case 119: return inf_unimplemented(pkt, id);
	case 120: return inf_unimplemented(pkt, id);
	case 121: return inf_unimplemented(pkt, id);
	case 122: return inf_unimplemented(pkt, id);
	case 123: return inf_unimplemented(pkt, id);
	case 124: return inf_unimplemented(pkt, id);
	case 125: return inf_unimplemented(pkt, id);
	case 126: return inf_unimplemented(pkt, id);
	case 127: return inf_unimplemented(pkt, id);
	case 128: return inf_reserved(pkt, id);
	case 129: return inf_reserved(pkt, id);
	case 130: return inf_unimplemented(pkt, id);
	case 131: return inf_unimplemented(pkt, id);
	case 132: return inf_unimplemented(pkt, id);
	case 133: return inf_reserved(pkt, id);
	case 134: return inf_reserved(pkt, id);
	case 135: return inf_reserved(pkt, id);
	case 136: return inf_reserved(pkt, id);
	case 137: return inf_unimplemented(pkt, id);
	case 138: return inf_unimplemented(pkt, id);
	case 139: return inf_unimplemented(pkt, id);
	case 140: return inf_unimplemented(pkt, id);
	case 141: return inf_unimplemented(pkt, id);
	case 142: return inf_unimplemented(pkt, id);
	case 143 ... 173: return inf_reserved(pkt, id);
	case 174: return inf_unimplemented(pkt, id);
	case 221: return inf_vend_spec(pkt, id);
	}

	return 0;
}

#define	ESS		0x0001
#define	IBSS		0x0002
#define	CF_Pollable	0x0004
#define	CF_Poll_Req	0x0008
#define	Privacy		0x0010
#define	Short_Pre	0x0020
#define	PBCC		0x0040
#define	Ch_Agility	0x0080
#define	Spec_Mgmt	0x0100
#define	QoS		0x0200
#define	Short_Slot_t	0x0400
#define	APSD		0x0800
#define	Radio_Meas	0x1000
#define	DSSS_OFDM	0x2000
#define	Del_Block_ACK	0x4000
#define	Imm_Block_ACK	0x8000

static int8_t cap_field(u16 cap_inf)
{
	if (ESS & cap_inf)
		tprintf(" ESS;");
	if (IBSS & cap_inf)
		tprintf(" IBSS;");
	if (CF_Pollable & cap_inf)
		tprintf(" CF Pollable;");
	if (CF_Poll_Req & cap_inf)
		tprintf(" CF-Poll Request;");
	if (Privacy & cap_inf)
		tprintf(" Privacy;");
	if (Short_Pre & cap_inf)
		tprintf(" Short Preamble;");
	if (PBCC & cap_inf)
		tprintf(" PBCC;");
	if (Ch_Agility & cap_inf)
		tprintf(" Channel Agility;");
	if (Spec_Mgmt & cap_inf)
		tprintf(" Spectrum Management;");
	if (QoS & cap_inf)
		tprintf(" QoS;");
	if (Short_Slot_t & cap_inf)
		tprintf(" Short Slot Time;");
	if (APSD & cap_inf)
		tprintf(" APSD;");
	if (Radio_Meas & cap_inf)
		tprintf(" Radio Measurement;");
	if (DSSS_OFDM & cap_inf)
		tprintf(" DSSS-OFDM;");
	if (Del_Block_ACK & cap_inf)
		tprintf(" Delayed Block Ack;");
	if (Imm_Block_ACK & cap_inf)
		tprintf(" Immediate Block Ack;");
	
	return 1;
}

static void print_inf_elements(struct pkt_buff *pkt)
{
	if (pkt_len(pkt)) {
		do {
			if (pkt_len(pkt))
				tprintf("\n\tIE:");

		} while (inf_elements(pkt));
	}
}

/* Management Dissectors */
static int8_t mgmt_beacon_dissect(struct pkt_buff *pkt)
{
	struct ieee80211_mgmt_beacon *beacon;

	beacon = (struct ieee80211_mgmt_beacon *)
			pkt_pull(pkt, sizeof(*beacon));
	if (beacon == NULL)
		return 0;

	tprintf("Timestamp 0x%.16"PRIx64", ", le64_to_cpu(beacon->timestamp));
	tprintf("Beacon Interval (%fs), ", le16_to_cpu(beacon->beacon_int)*TU);
	tprintf("Capabilities (0x%x <->", le16_to_cpu(beacon->capab_info));
	cap_field(le16_to_cpu(beacon->capab_info));
	tprintf(")");

	print_inf_elements(pkt);

	if (pkt_len(pkt))
		return 0;

	return 1;
}

static int8_t mgmt_probe_request_dissect(struct pkt_buff *pkt)
{
	print_inf_elements(pkt);

	if (pkt_len(pkt))
		return 0;

	return 1;
}

static int8_t mgmt_unimplemented(struct pkt_buff *pkt __maybe_unused)
{
	return 0;
}
/* End Management Dissectors */

/* Control Dissectors */
static int8_t ctrl_unimplemented(struct pkt_buff *pkt __maybe_unused)
{
	return 0;
}
/* End Control Dissectors */

/* Data Dissectors */
static int8_t data_unimplemented(struct pkt_buff *pkt __maybe_unused)
{
	return 0;
}
/* End Data Dissectors */

static const char *mgt_sub(u8 subtype, struct pkt_buff *pkt,
			   int8_t (**get_content)(struct pkt_buff *pkt))
{
	u16 seq_ctrl;
	struct ieee80211_mgmt *mgmt;
	const char *dst, *src, *bssid;

	mgmt = (struct ieee80211_mgmt *) pkt_pull(pkt, sizeof(*mgmt));
	if (!mgmt)
		return NULL;

	dst = lookup_vendor((mgmt->da[0] << 16) |
			    (mgmt->da[1] <<  8) |
			     mgmt->da[2]);
	src = lookup_vendor((mgmt->sa[0] << 16) |
			    (mgmt->sa[1] <<  8) |
			     mgmt->sa[2]);

	bssid = lookup_vendor((mgmt->bssid[0] << 16) |
			      (mgmt->bssid[1] <<  8) |
			       mgmt->bssid[2]);
	seq_ctrl = le16_to_cpu(mgmt->seq_ctrl);

	tprintf("Duration (%u),", le16_to_cpu(mgmt->duration));
	tprintf("\n\tDestination (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x) ",
		mgmt->da[0], mgmt->da[1], mgmt->da[2],
		mgmt->da[3], mgmt->da[4], mgmt->da[5]);
	if (dst) {
		tprintf("=> (%s:%.2x:%.2x:%.2x)", dst,
			mgmt->da[3], mgmt->da[4], mgmt->da[5]);
	}

	tprintf("\n\tSource (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x) ",
		mgmt->sa[0], mgmt->sa[1], mgmt->sa[2],
		mgmt->sa[3], mgmt->sa[4], mgmt->sa[5]);
	if (src) {
		tprintf("=> (%s:%.2x:%.2x:%.2x)", src,
			mgmt->sa[3], mgmt->sa[4], mgmt->sa[5]);
	}

	tprintf("\n\tBSSID (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x) ",
		mgmt->bssid[0], mgmt->bssid[1], mgmt->bssid[2],
		mgmt->bssid[3], mgmt->bssid[4], mgmt->bssid[5]);
	if(bssid) {
		tprintf("=> (%s:%.2x:%.2x:%.2x)", bssid,
			mgmt->bssid[3], mgmt->bssid[4], mgmt->bssid[5]);
	}

	tprintf("\n\tFragmentnr. (%u), Seqnr. (%u). ",
		seq_ctrl & 0xf, seq_ctrl >> 4);

	switch (subtype) {
	case 0x0:
		*get_content = mgmt_unimplemented;
		return "Association Request";
	case 0x1:
		*get_content = mgmt_unimplemented;
		return "Association Response";
	case 0x2:
		*get_content = mgmt_unimplemented;
		return "Reassociation Request";
	case 0x3:
		*get_content = mgmt_unimplemented;
		return "Reassociation Response";
	case 0x4:
		*get_content = mgmt_probe_request_dissect;
		return "Probe Request";
	case 0x5:
		/* Probe Response is very similar to Beacon except some IEs */
		*get_content = mgmt_beacon_dissect;
		return "Probe Response";
	case 0x8:
		*get_content = mgmt_beacon_dissect;
		return "Beacon";
	case 0x9:
		*get_content = mgmt_unimplemented;
		return "ATIM";
	case 0xA:
		*get_content = mgmt_unimplemented;
		return "Disassociation";
	case 0xB:
		*get_content = mgmt_unimplemented;
		return "Authentication";
	case 0xC:
		*get_content = mgmt_unimplemented;
		return "Deauthentication";
	default:
		*get_content = NULL;
		return "Reserved";
	}
}

static const char *ctrl_sub(u8 subtype, struct pkt_buff *pkt __maybe_unused,
			    int8_t (**get_content)(struct pkt_buff *pkt))
{
	switch (subtype) {
	case 0xA:
		*get_content = ctrl_unimplemented;
		return "PS-Poll";
	case 0xB:
		*get_content = ctrl_unimplemented;
		return "RTS";
	case 0xC:
		*get_content = ctrl_unimplemented;
		return "CTS";
	case 0xD:
		*get_content = ctrl_unimplemented;
		return "ACK";
	case 0xE:
		*get_content = ctrl_unimplemented;
		return "CF End";
	case 0xF:
		*get_content = ctrl_unimplemented;
		return "CF End + CF-ACK";
	default:
		*get_content = NULL;
		return "Reserved";
	}
}

static const char *data_sub(u8 subtype, struct pkt_buff *pkt __maybe_unused,
		 	    int8_t (**get_content)(struct pkt_buff *pkt))
{
	switch (subtype) {
	case 0x0:
		*get_content = data_unimplemented;
		return "Data";
	case 0x1:
		*get_content = data_unimplemented;
		return "Data + CF-ACK";
	case 0x2:
		*get_content = data_unimplemented;
		return "Data + CF-Poll";
	case 0x3:
		*get_content = data_unimplemented;
		return "Data + CF-ACK + CF-Poll";
	case 0x4:
		*get_content = data_unimplemented;
		return "Null";
	case 0x5:
		*get_content = data_unimplemented;
		return "CF-ACK";
	case 0x6:
		*get_content = data_unimplemented;
		return "CF-Poll";
	case 0x7:
		*get_content = data_unimplemented;
		return "CF-ACK + CF-Poll";
	default:
		*get_content = NULL;
		return "Reserved";
	}
}

static const char *
frame_control_type(u8 type, const char *(**get_subtype)(u8 subtype,
		   struct pkt_buff *pkt, int8_t (**get_content)(struct pkt_buff *pkt)))
{
	switch (type) {
	case 0x0:
		*get_subtype = mgt_sub;
		return "Management";
	case 0x1:
		*get_subtype = ctrl_sub;
		return "Control";
	case 0x2:
		*get_subtype = data_sub;
		return "Data";
	case 0x3:
		*get_subtype = NULL;
		return "Reserved";
	default:
		*get_subtype = NULL;
		return "Control Type unknown";
	}
}

static void ieee80211(struct pkt_buff *pkt)
{
	int8_t (*get_content)(struct pkt_buff *pkt) = NULL;
	const char *(*get_subtype)(u8 subtype, struct pkt_buff *pkt,
		int8_t (**get_content)(struct pkt_buff *pkt)) = NULL;
	const char *subtype = NULL;
	struct ieee80211_frm_ctrl *frm_ctrl;

	if (pkt->link_type == LINKTYPE_IEEE802_11_RADIOTAP) {
		struct ieee80211_radiotap_header *rtap;

		rtap = (struct ieee80211_radiotap_header *)pkt_pull(pkt,
				sizeof(*rtap));
		if (rtap == NULL)
			return;

		tprintf(" [ Radiotap ");
		tprintf("Version (%u), ", rtap->version);
		tprintf("Length (%u), ", le16_to_cpu(rtap->len));
		tprintf("Flags (0x%08x) ]\n", le32_to_cpu(rtap->present));

		pkt_pull(pkt, le16_to_cpu(rtap->len) - sizeof(*rtap));
	}

	frm_ctrl = (struct ieee80211_frm_ctrl *)pkt_pull(pkt, sizeof(*frm_ctrl));
	if (frm_ctrl == NULL)
		return;

	tprintf(" [ 802.11 Frame Control (0x%04x)]\n",
		le16_to_cpu(frm_ctrl->frame_control));

	tprintf(" [ Proto Version (%u), ", frm_ctrl->proto_version);
	tprintf("Type (%u, %s), ", frm_ctrl->type,
		frame_control_type(frm_ctrl->type, &get_subtype));
	if (get_subtype) {
		subtype = (*get_subtype)(frm_ctrl->subtype, pkt, &get_content);
		tprintf("Subtype (%u, %s)", frm_ctrl->subtype, subtype);
	} else {
		tprintf("%s%s%s", colorize_start_full(black, red),
			"No SubType Data available", colorize_end());
	}

	tprintf("%s%s", frm_ctrl->to_ds ? ", Frame goes to DS" : "",
		frm_ctrl->from_ds ?  ", Frame comes from DS" : "");
	tprintf("%s", frm_ctrl->more_frags ? ", More Fragments" : "");
	tprintf("%s", frm_ctrl->retry ? ", Frame is retransmitted" : "");
	tprintf("%s", frm_ctrl->power_mgmt ? ", In Power Saving Mode" : "");
	tprintf("%s", frm_ctrl->more_data ? ", More Data" : "");
	tprintf("%s", frm_ctrl->wep ? ", Needs WEP" : "");
	tprintf("%s", frm_ctrl->order ? ", Order" : "");
	tprintf(" ]\n");

	if (get_content) {
		tprintf(" [ Subtype %s: ", subtype);
		if (!((*get_content) (pkt)))
			tprintf("%s%s%s", colorize_start_full(black, red),
				"Failed to dissect Subtype", colorize_end());
		tprintf(" ]");
	} else {
		tprintf("%s%s%s", colorize_start_full(black, red),
			"No SubType Data available", colorize_end());
	}

	tprintf("\n");

//	pkt_set_dissector(pkt, &ieee802_lay2, ntohs(eth->h_proto));
}

static void ieee80211_less(struct pkt_buff *pkt __maybe_unused)
{
	tprintf("802.11 frame (more on todo)");
}

struct protocol ieee80211_ops = {
	.key = 0,
	.print_full = ieee80211,
	.print_less = ieee80211_less,
};
