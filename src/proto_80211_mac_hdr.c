/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Daniel Borkmann <borkmann@iogearbox.net>
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <asm/byteorder.h>

#include "proto.h"
#include "protos.h"
#include "dissector_80211.h"
#include "built_in.h"
#include "pkt_buff.h"
#include "oui.h"

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


/* http://www.sss-mag.com/pdf/802_11tut.pdf
 * http://www.scribd.com/doc/78443651/111/Management-Frames
 * http://www.wildpackets.com/resources/compendium/wireless_lan/wlan_packets
 * http://www.rhyshaden.com/wireless.htm
*/

static int8_t inf_ssid(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_sup_rates(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_fh_ps(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_dsss_ps(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_cf_ps(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tim(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ibss_ps(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_country(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_hop_pp(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_hop_pt(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_bss_load(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_edca_ps(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tspec(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tclas(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_sched(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_chall_txt(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_pwr_constr(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_pwr_cap(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tpc_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tpc_rep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_supp_ch(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ch_sw_ann(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_meas_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_meas_rep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_quiet(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ibss_dfs(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_erp(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ts_del(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tclas_proc(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ht_cap(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_qos_cap(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_rsn(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ext_supp_rates(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ap_ch_exp(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_neighb_rep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_rcpi(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mde(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_fte(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_time_out_int(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_rde(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_dse_reg_loc(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_supp_op_class(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ext_ch_sw_ann(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ht_op(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_sec_ch_offs(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_bss_avg_acc_del(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ant(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_rsni(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_meas_pilot_trans(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_bss_avl_adm_cap(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_bss_ac_acc_del(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_time_adv(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_rm_ena_cap(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mult_bssid(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_20_40_bss_coex(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_20_40_bss_int_ch_rep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_overl_bss_scan_para(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ric_desc(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mgmt_mic(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ev_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ev_rep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_diagn_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_diagn_rep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_loc_para(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_nontr_bssid_cap(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ssid_list(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mult_bssid_index(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_fms_desc(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_fms_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_fms_resp(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_qos_tfc_cap(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_bss_max_idle_per(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tfs_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tfs_resp(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_wnm_sleep_mod(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tim_bcst_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tim_bcst_resp(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_coll_interf_rep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ch_usage(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_time_zone(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_dms_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_dms_resp(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_link_id(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_wakeup_sched(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ch_sw_timing(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_pti_ctrl(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_tpu_buff_status(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_interw(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_adv_proto(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_exp_bandw_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_qos_map_set(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_roam_cons(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_emer_alert_id(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mesh_conf(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mesh_id(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mesh_link_metr_rep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_cong_notif(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mesh_peer_mgmt(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mesh_ch_sw_para(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mesh_awake_win(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_beacon_timing(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mccaop_setup_req(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mccaop_setup_rep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mccaop_adv(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mccaop_teardwn(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_gann(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_rann(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_ext_cap(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_preq(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_prep(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_perr(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_pxu(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_pxuc(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_auth_mesh_peer_exch(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mic(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_dest_uri(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_u_apsd_coex(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_mccaop_adv_overv(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_vend_spec(struct pkt_buff *pkt) {
	return 1;
}

static int8_t inf_elements(u8 id, struct pkt_buff *pkt) {
	switch (id) {
	case 0:
		      return inf_ssid(pkt);
	case 1:
		      return inf_sup_rates(pkt);
	case 2:
		      return inf_fh_ps(pkt);
	case 3:
		      return inf_dsss_ps(pkt);
	case 4:
		      return inf_cf_ps(pkt);
	case 5:
		      return inf_tim(pkt);
	case 6:
		      return inf_ibss_ps(pkt);
	case 7:
		      return inf_country(pkt);
	case 8:
		      return inf_hop_pp(pkt);
	case 9:
		      return inf_hop_pt(pkt);
	case 10:
		      return inf_req(pkt);
	case 11:
		      return inf_bss_load(pkt);
	case 12:
		      return inf_edca_ps(pkt);
	case 13:
		      return inf_tspec(pkt);
	case 14:
		      return inf_tclas(pkt);
	case 15:
		      return inf_sched(pkt);
	case 16:
		      return inf_chall_txt(pkt);
	case 32:
		      return inf_pwr_constr(pkt);
	case 33:
		      return inf_pwr_cap(pkt);
	case 34:
		      return inf_tpc_req(pkt);
	case 35:
		      return inf_tpc_rep(pkt);
	case 36:
		      return inf_supp_ch(pkt);
	case 37:
		      return inf_ch_sw_ann(pkt);
	case 38:
		      return inf_meas_req(pkt);
	case 39:
		      return inf_meas_rep(pkt);
	case 40:
		      return inf_quiet(pkt);
	case 41:
		      return inf_ibss_dfs(pkt);
	case 42:
		      return inf_erp(pkt);
	case 43:
		      return inf_ts_del(pkt);
	case 44:
		      return inf_tclas_proc(pkt);
	case 45:
		      return inf_ht_cap(pkt);
	case 46:
		      return inf_qos_cap(pkt);
	case 48:
		      return inf_rsn(pkt);
	case 50:
		      return inf_ext_supp_rates(pkt);
	case 51:
		      return inf_ap_ch_exp(pkt);
	case 52:
		      return inf_neighb_rep(pkt);
	case 53:
		      return inf_rcpi(pkt);
	case 54:
		      return inf_mde(pkt);
	case 55:
		      return inf_fte(pkt);
	case 56:
		      return inf_time_out_int(pkt);
	case 57:
		      return inf_rde(pkt);
	case 58:
		      return inf_dse_reg_loc(pkt);
	case 59:
		      return inf_supp_op_class(pkt);
	case 60:
		      return inf_ext_ch_sw_ann(pkt);
	case 61:
		      return inf_ht_op(pkt);
	case 62:
		      return inf_sec_ch_offs(pkt);
	case 63:
		      return inf_bss_avg_acc_del(pkt);
	case 64:
		      return inf_ant(pkt);
	case 65:
		      return inf_rsni(pkt);
	case 66:
		      return inf_meas_pilot_trans(pkt);
	case 67:
		      return inf_bss_avl_adm_cap(pkt);
	case 68:
		      return inf_bss_ac_acc_del(pkt);
	case 69:
		      return inf_time_adv(pkt);
	case 70:
		      return inf_rm_ena_cap(pkt);
	case 71:
		      return inf_mult_bssid(pkt);
	case 72:
		      return inf_20_40_bss_coex(pkt);
	case 73:
		      return inf_20_40_bss_int_ch_rep(pkt);
	case 74:
		      return inf_overl_bss_scan_para(pkt);
	case 75:
		      return inf_ric_desc(pkt);
	case 76:
		      return inf_mgmt_mic(pkt);
	case 78:
		      return inf_ev_req(pkt);
	case 79:
		      return inf_ev_rep(pkt);
	case 80:
		      return inf_diagn_req(pkt);
	case 81:
		      return inf_diagn_rep(pkt);
	case 82:
		      return inf_loc_para(pkt);
	case 83:
		      return inf_nontr_bssid_cap(pkt);
	case 84:
		      return inf_ssid_list(pkt);
	case 85:
		      return inf_mult_bssid_index(pkt);
	case 86:
		      return inf_fms_desc(pkt);
	case 87:
		      return inf_fms_req(pkt);
	case 88:
		      return inf_fms_resp(pkt);
	case 89:
		      return inf_qos_tfc_cap(pkt);
	case 90:
		      return inf_bss_max_idle_per(pkt);
	case 91:
		      return inf_tfs_req(pkt);
	case 92:
		      return inf_tfs_resp(pkt);
	case 93:
		      return inf_wnm_sleep_mod(pkt);
	case 94:
		      return inf_tim_bcst_req(pkt);
	case 95:
		      return inf_tim_bcst_resp(pkt);
	case 96:
		      return inf_coll_interf_rep(pkt);
	case 97:
		      return inf_ch_usage(pkt);
	case 98:
		      return inf_time_zone(pkt);
	case 99:
		      return inf_dms_req(pkt);
	case 100:
		      return inf_dms_resp(pkt);
	case 101:
		      return inf_link_id(pkt);
	case 102:
		      return inf_wakeup_sched(pkt);
	case 104:
		      return inf_ch_sw_timing(pkt);
	case 105:
		      return inf_pti_ctrl(pkt);
	case 106:
		      return inf_tpu_buff_status(pkt);
	case 107:
		      return inf_interw(pkt);
	case 108:
		      return inf_adv_proto(pkt);
	case 109:
		      return inf_exp_bandw_req(pkt);
	case 110:
		      return inf_qos_map_set(pkt);
	case 111:
		      return inf_roam_cons(pkt);
	case 112:
		      return inf_emer_alert_id(pkt);
	case 113:
		      return inf_mesh_conf(pkt);
	case 114:
		      return inf_mesh_id(pkt);
	case 115:
		      return inf_mesh_link_metr_rep(pkt);
	case 116:
		      return inf_cong_notif(pkt);
	case 117:
		      return inf_mesh_peer_mgmt(pkt);
	case 118:
		      return inf_mesh_ch_sw_para(pkt);
	case 119:
		      return inf_mesh_awake_win(pkt);
	case 120:
		      return inf_beacon_timing(pkt);
	case 121:
		      return inf_mccaop_setup_req(pkt);
	case 122:
		      return inf_mccaop_setup_rep(pkt);
	case 123:
		      return inf_mccaop_adv(pkt);
	case 124:
		      return inf_mccaop_teardwn(pkt);
	case 125:
		      return inf_gann(pkt);
	case 126:
		      return inf_rann(pkt);
	case 127:
		      return inf_ext_cap(pkt);
	case 130:
		      return inf_preq(pkt);
	case 131:
		      return inf_prep(pkt);
	case 132:
		      return inf_perr(pkt);
	case 137:
		      return inf_pxu(pkt);
	case 138:
		      return inf_pxuc(pkt);
	case 139:
		      return inf_auth_mesh_peer_exch(pkt);
	case 140:
		      return inf_mic(pkt);
	case 141:
		      return inf_dest_uri(pkt);
	case 142:
		      return inf_u_apsd_coex(pkt);
	case 174:
		      return inf_mccaop_adv_overv(pkt);
	case 221:
		      return inf_vend_spec(pkt);
	}
	
	tprintf(" Reserved Info Element");
	return 1;
}

static int8_t cap_field(u16 cap_inf) {

#define	ESS		0b0000000000000001
#define	IBSS		0b0000000000000010
#define	CF_Pollable	0b0000000000000100
#define	CF_Poll_Req	0b0000000000001000
#define	Privacy		0b0000000000010000
#define	Short_Pre	0b0000000000100000
#define	PBCC		0b0000000001000000
#define	Ch_Agility	0b0000000010000000
#define	Spec_Mgmt	0b0000000100000000
#define	QoS		0b0000001000000000
#define	Short_Slot_t	0b0000010000000000
#define	APSD		0b0000100000000000
#define	Radio_Meas	0b0001000000000000
#define	DSSS_OFDM	0b0010000000000000
#define	Del_Block_ACK	0b0100000000000000
#define	Imm_Block_ACK	0b1000000000000000

	if(ESS & cap_inf)
	      tprintf(" ESS;");
	if(IBSS & cap_inf)
	      tprintf(" IBSS;");
	if(CF_Pollable & cap_inf)
	      tprintf(" CF Pollable;");
	if(CF_Poll_Req & cap_inf)
	      tprintf(" CF-Poll Request;");
	if(Privacy & cap_inf)
	      tprintf(" Privacy;");
	if(Short_Pre & cap_inf)
	      tprintf(" Short Preamble;");
	if(PBCC & cap_inf)
	      tprintf(" PBCC;");
	if(Ch_Agility & cap_inf)
	      tprintf(" Channel Agility;");
	if(Spec_Mgmt & cap_inf)
	      tprintf(" Spectrum Management;");
	if(QoS & cap_inf)
	      tprintf(" QoS;");
	if(Short_Slot_t & cap_inf)
	      tprintf(" Short Slot Time;");
	if(APSD & cap_inf)
	      tprintf(" APSD;");
	if(Radio_Meas & cap_inf)
	      tprintf(" Radio Measurement;");
	if(DSSS_OFDM & cap_inf)
	      tprintf(" DSSS-OFDM;");
	if(Del_Block_ACK & cap_inf)
	      tprintf(" Delayed Block Ack;");
	if(Imm_Block_ACK & cap_inf)
	      tprintf(" Immediate Block Ack;");
	
	return 1;
}

/* Management Dissectors */
static int8_t assoc_req(struct pkt_buff *pkt) {
	return 0;
}

static int8_t assoc_resp(struct pkt_buff *pkt) {
	return 0;
}

static int8_t reassoc_req(struct pkt_buff *pkt) {
	return 0;
}

static int8_t reassoc_resp(struct pkt_buff *pkt) {
	return 0;
}

static int8_t probe_req(struct pkt_buff *pkt) {
	return 0;
}

static int8_t probe_resp(struct pkt_buff *pkt) {
	return 0;
}

static int8_t beacon(struct pkt_buff *pkt) {
	struct ieee80211_mgmt_beacon *beacon =
		(struct ieee80211_mgmt_beacon *) pkt_pull(pkt, sizeof(*beacon));
	if (beacon == NULL)
		return 0;
	tprintf("Timestamp 0x%.16lx, ", le64_to_cpu(beacon->timestamp));
	tprintf("Beacon Interval (%fs), ",
				    le16_to_cpu(beacon->beacon_int) * 0.001024);
	tprintf("Capabilities (0x%x <->",
				    le16_to_cpu(beacon->capab_info));
	cap_field(le16_to_cpu(beacon->capab_info));
	tprintf(")");
	return 1;
}

static int8_t atim(struct pkt_buff *pkt) {
	return 0;
}

static int8_t disassoc(struct pkt_buff *pkt) {
	return 0;
}

static int8_t auth(struct pkt_buff *pkt) {
	return 0;
}

static int8_t deauth(struct pkt_buff *pkt) {
	return 0;
}
/* End Management Dissectors */

/* Control Dissectors */
static int8_t ps_poll(struct pkt_buff *pkt) {
	return 0;
}

static int8_t rts(struct pkt_buff *pkt) {
	return 0;
}

static int8_t cts(struct pkt_buff *pkt) {
	return 0;
}

static int8_t ack(struct pkt_buff *pkt) {
	return 0;
}

static int8_t cf_end(struct pkt_buff *pkt) {
	return 0;
}

static int8_t cf_end_ack(struct pkt_buff *pkt) {
	return 0;
}
/* End Control Dissectors */

/* Data Dissectors */
static int8_t data(struct pkt_buff *pkt) {
	return 0;
}

static int8_t data_cf_ack(struct pkt_buff *pkt) {
	return 0;
}

static int8_t data_cf_poll(struct pkt_buff *pkt) {
	return 0;
}

static int8_t data_cf_ack_poll(struct pkt_buff *pkt) {
	return 0;
}

static int8_t null(struct pkt_buff *pkt) {
	return 0;
}

static int8_t cf_ack(struct pkt_buff *pkt) {
	return 0;
}

static int8_t cf_poll(struct pkt_buff *pkt) {
	return 0;
}

static int8_t cf_ack_poll(struct pkt_buff *pkt) {
	return 0;
}
/* End Data Dissectors */

static char *mgt_sub(u8 subtype, struct pkt_buff *pkt, int8_t (**get_content)(struct pkt_buff *pkt)) {

	struct ieee80211_mgmt *mgmt =
		(struct ieee80211_mgmt *) pkt_pull(pkt, sizeof(*mgmt));
	if (mgmt == NULL)
		return 0;

	const char *dst = lookup_vendor((mgmt->da[0] << 16) | (mgmt->da[1] << 8) | mgmt->da[2]);
	const char *src = lookup_vendor((mgmt->sa[0] << 16) | (mgmt->sa[1] << 8) | mgmt->sa[2]);
	const char *bssid = lookup_vendor((mgmt->bssid[0] << 16) | (mgmt->bssid[1] << 8) | mgmt->bssid[2]);
	u16 seq_ctrl = le16_to_cpu(mgmt->seq_ctrl);

	tprintf("Duration (%u),", le16_to_cpu(mgmt->duration));
	tprintf("\n\tDestination (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x) ",
			      mgmt->da[0], mgmt->da[1], mgmt->da[2], mgmt->da[3], mgmt->da[4], mgmt->da[5]);
	if(dst)
		tprintf("=> (%s:%.2x:%.2x:%.2x)", dst, mgmt->da[3], mgmt->da[4], mgmt->da[5]);
	tprintf("\n\tSource (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x) ",
			      mgmt->sa[0], mgmt->sa[1], mgmt->sa[2], mgmt->sa[3], mgmt->sa[4], mgmt->sa[5]);
	if(src)
		tprintf("=> (%s:%.2x:%.2x:%.2x)", src, mgmt->sa[3], mgmt->sa[4], mgmt->sa[5]);
	tprintf("\n\tBSSID (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x) ",
			      mgmt->bssid[0], mgmt->bssid[1], mgmt->bssid[2], mgmt->bssid[3], mgmt->bssid[4], mgmt->bssid[5]);
	if(bssid)
		tprintf("=> (%s:%.2x:%.2x:%.2x)", bssid, mgmt->bssid[3], mgmt->bssid[4], mgmt->bssid[5]);
	tprintf("\n\tFragmentnr. (%u), Seqnr. (%u). ", seq_ctrl & 0xf, seq_ctrl >> 4);
  
	switch (subtype) {
	case 0b0000:
		      *get_content = assoc_req;
		      return "Association Request";
	case 0b0001:
		      *get_content = assoc_resp;
		      return "Association Response";
	case 0b0010:
		      *get_content = reassoc_req;
		      return "Reassociation Request";
	case 0b0011:
		      *get_content = reassoc_resp;
		      return "Reassociation Response";
	case 0b0100:
		      *get_content = probe_req;
		      return "Probe Request";
	case 0b0101:
		      *get_content = probe_resp;
		      return "Probe Response";
	case 0b1000:
		      *get_content = beacon;
		      return "Beacon";
	case 0b1001:
		      *get_content = atim;
		      return "ATIM";
	case 0b1010:
		      *get_content = disassoc;
		      return "Disassociation";
	case 0b1011:
		      *get_content = auth;
		      return "Authentication";
	case 0b1100:
		      *get_content = deauth;
		      return "Deauthentication";
	}

	if ((subtype >= 0b0110 && subtype <= 0b0111) || (subtype >= 0b1101 && subtype <= 0b1111))
		      return "Reserved";

	return "Management SubType not supported";
}

static char *ctrl_sub(u8 subtype, struct pkt_buff *pkt, int8_t (**get_content)(struct pkt_buff *pkt)) {

	switch (subtype) {
	case 0b1010:
		      *get_content = ps_poll;
		      return "PS-Poll";
	case 0b1011:
		      *get_content = rts;
		      return "RTS";
	case 0b1100:
		      *get_content = cts;
		      return "CTS";
	case 0b1101:
		      *get_content = ack;
		      return "ACK";
	case 0b1110:
		      *get_content = cf_end;
		      return "CF End";
	case 0b1111:
		      *get_content = cf_end_ack;
		      return "CF End + CF-ACK";
	}

	if (subtype <= 0b1001)
		      return "Reserved";
	
	return "Control SubType not supported";
}

static char *data_sub(u8 subtype, struct pkt_buff *pkt, int8_t (**get_content)(struct pkt_buff *pkt)) {

	switch (subtype) {
	case 0b0000:
		      *get_content = data;
		      return "Data";
	case 0b0001:
		      *get_content = data_cf_ack;
		      return "Data + CF-ACK";
	case 0b0010:
		      *get_content = data_cf_poll;
		      return "Data + CF-Poll";
	case 0b0011:
		      *get_content = data_cf_ack_poll;
		      return "Data + CF-ACK + CF-Poll";
	case 0b0100:
		      *get_content = null;
		      return "Null";
	case 0b0101:
		      *get_content = cf_ack;
		      return "CF-ACK";
	case 0b0110:
		      *get_content = cf_poll;
		      return "CF-Poll";
	case 0b0111:
		      *get_content = cf_ack_poll;
		      return "CF-ACK + CF-Poll";
	}

	if (subtype >= 0b1000 && subtype <= 0b1111)
		      return "Reserved";
	
	return "Data SubType not supported";
}

static char *frame_control_type(u8 type, char *(**get_subtype)(u8 subtype, struct pkt_buff *pkt, int8_t (**get_content)(struct pkt_buff *pkt))) {
	switch (type) {
	case 0b00:
		    *get_subtype = mgt_sub;
		    return "Management";
	case 0b01:
		    *get_subtype = ctrl_sub;
		    return "Control";
	case 0b10:
		    *get_subtype = data_sub;
		    return "Data";
	case 0b11: return "Reserved";
	}

	return "Control Type not supported";
	
}

static void ieee80211(struct pkt_buff *pkt)
{
	int8_t (*get_content)(struct pkt_buff *pkt) = NULL;
	char *(*get_subtype)(u8 subtype, struct pkt_buff *pkt, int8_t (**get_content)(struct pkt_buff *pkt)) = NULL;
	char *subtype = NULL;
	
	struct ieee80211_frm_ctrl *frm_ctrl =
		(struct ieee80211_frm_ctrl *) pkt_pull(pkt, sizeof(*frm_ctrl));
	if (frm_ctrl == NULL)
		return;

	tprintf(" [ 802.11 Frame Control (0x%04x)]\n",
		le16_to_cpu(frm_ctrl->frame_control));
	tprintf("\t [ Proto Version (%u), ", frm_ctrl->proto_version);
	tprintf("Type (%u, %s), ", frm_ctrl->type, frame_control_type(frm_ctrl->type, &get_subtype));
	if (get_subtype) {
		subtype = (*get_subtype)(frm_ctrl->subtype, pkt, &get_content);
		tprintf("Subtype (%u, %s)", frm_ctrl->subtype, subtype);
	}
	else
		tprintf("\n%s%s%s", colorize_start_full(black, red),
			    "No SubType Data available", colorize_end());
	tprintf("%s%s",
		frm_ctrl->to_ds ? ", Frame goes to DS" : "",
		frm_ctrl->from_ds ?  ", Frame comes from DS" : "");
	tprintf("%s", frm_ctrl->more_frags ? ", More Fragments" : "");
	tprintf("%s", frm_ctrl->retry ? ", Frame is retransmitted" : "");
	tprintf("%s", frm_ctrl->power_mgmt ? ", In Power Saving Mode" : "");
	tprintf("%s", frm_ctrl->more_data ? ", More Data" : "");
	tprintf("%s", frm_ctrl->wep ? ", Needs WEP" : "");
	tprintf("%s", frm_ctrl->order ? ", Order" : "");
	tprintf(" ]\n");

	if (get_content) {
		tprintf("[ %s ", subtype);
		if (!((*get_content) (pkt)))
		      tprintf("\n%s%s%s", colorize_start_full(black, red),
			    "Failed to dissect Subtype", colorize_end());
		tprintf(" ]");
	}
	else
		tprintf("\n%s%s%s", colorize_start_full(black, red),
			    "No SubType Data available", colorize_end());

//	pkt_set_proto(pkt, &ieee802_lay2, ntohs(eth->h_proto));
}

static void ieee80211_less(struct pkt_buff *pkt)
{
	tprintf("802.11 frame (more on todo)");
}

struct protocol ieee80211_ops = {
	.key = 0,
	.print_full = ieee80211,
	.print_less = ieee80211_less,
};

EXPORT_SYMBOL(ieee80211_ops);
