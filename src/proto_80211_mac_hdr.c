/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <daniel@netsniff-ng.org>
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

/* http://www.sss-mag.com/pdf/802_11tut.pdf
 * http://www.scribd.com/doc/78443651/111/Management-Frames
 * http://www.wildpackets.com/resources/compendium/wireless_lan/wlan_packets
 * http://www.rhyshaden.com/wireless.htm
*/

struct element_reserved {
	u8 len;
} __packed;

struct element_ssid {
	u8 len;
	u8 SSID[0];
} __packed;

struct element_supp_rates {
	u8 len;
	u8 SSID[0];
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
				  apsid:1,
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
				  apsid:1,
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

struct element_erp {
	u8 len;
	u8 param;
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

static int8_t len_error(u8 len, u8 intended)
{
	if(len != intended) {
		tprintf("Length should be %u Bytes", intended);
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

static int8_t inf_reserved(struct pkt_buff *pkt, u8 *id)
{
	u8 i;
	u8 *data;
	struct element_reserved *reserved;

	reserved = (struct element_reserved *) pkt_pull(pkt, sizeof(*reserved));
	if (reserved == NULL)
		return 0;

	tprintf("Reserved (%u, Len (%u)): ", *id, reserved->len);

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

	tprintf("Rates (%u, Len (%u)): ", *id, supp_rates->len);

	if ((supp_rates->len - sizeof(*supp_rates) + 1) > 0) {
		rates = pkt_pull(pkt, supp_rates->len);
		if (rates == NULL)
			return 0;

		for (i = 0; i < supp_rates->len; i++)
			tprintf("%g ", (rates[i] & 0x80) ?
				((rates[i] & 0x3f) * 0.5) :
				data_rates(rates[i]));
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

	tprintf("FH Param Set (%u, Len(%u)): ", *id, fh_ps->len);
	if (len_error(fh_ps->len, 5))
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

	tprintf("DSSS Param Set (%u, Len(%u)): ", *id, dsss_ps->len);
	if (len_error(dsss_ps->len, 1))
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

	tprintf("CF Param Set (%u, Len(%u)): ", *id, cf_ps->len);
	if (len_error(cf_ps->len, 6))
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

	tim = (struct element_tim *) pkt_pull(pkt, sizeof(*tim));
	if (tim == NULL)
		return 0;

	tprintf("TIM (%u, Len(%u)): ", *id, tim->len);
	tprintf("DTIM Count: %u, ", tim->dtim_cnt);
	tprintf("DTIM Period: %u, ", tim->dtim_period);
	tprintf("Bitmap Control: %u, ", tim->bmp_cntrl);
	if ((tim->len - sizeof(*tim) + 1) > 0) {
		u8 *bmp = pkt_pull(pkt, (tim->len - sizeof(*tim) + 1));
		if (bmp == NULL)
			return 0;

		tprintf("Partial Virtual Bitmap: 0x");
		for(u8 i=0; i < (tim->len - sizeof(*tim) + 1); i++)
			tprintf("%.2x ", bmp[i]);
	}

	return 1;
}

static int8_t inf_ibss_ps(struct pkt_buff *pkt, u8 *id)
{
	struct element_ibss_ps *ibss_ps;

	ibss_ps = (struct element_ibss_ps *) pkt_pull(pkt, sizeof(*ibss_ps));
	if (ibss_ps == NULL)
		return 0;

	tprintf("IBSS Param Set (%u, Len(%u)): ", *id, ibss_ps->len);
	if (len_error(ibss_ps->len, 2))
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

	tprintf("Country (%u, Len(%u)): ", *id, country->len);
	tprintf("Country String: %c%c%c", country->country_first,
		country->country_sec, country->country_third);

	for (i = 0; i < (country->len - 3); i += 3) {
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

	if(country->len % 2) {
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

	tprintf("Hopping Pattern Param (%u, Len(%u)): ", *id, hop_pp->len);
	if (len_error(hop_pp->len, 2))
		return 0;
	tprintf("Nr of Ch: %u", hop_pp->nr_ch);

	return 1;
}

static int8_t inf_hop_pt(struct pkt_buff *pkt, u8 *id)
{
	int i;
	u8 *rand_tabl;
	struct element_hop_pt *hop_pt;

	hop_pt = (struct element_hop_pt *) pkt_pull(pkt, sizeof(*hop_pt));
	if (hop_pt == NULL)
		return 0;

	tprintf("Hopping Pattern Table (%u, Len(%u)): ", *id, hop_pt->len);
	tprintf("Flag: %u, ", hop_pt->flag);
	tprintf("Nr of Sets: %u, ", hop_pt->nr_sets);
	tprintf("Modules: %u, ", hop_pt->modules);
	tprintf("Offs: %u", hop_pt->offs);

	if ((hop_pt->len - sizeof(*hop_pt) + 1) > 0) {
		rand_tabl = pkt_pull(pkt, (hop_pt->len - sizeof(*hop_pt) + 1));
		if (rand_tabl == NULL)
			return 0;

		tprintf(", Rand table: 0x");
		for (i = 0; i < (hop_pt->len - sizeof(*hop_pt) + 1); i++)
			tprintf("%.2x ", rand_tabl[i]);
	}

	return 1;
}

static int8_t inf_req(struct pkt_buff *pkt, u8 *id)
{
	int i;
	struct element_req *req;
	u8 *req_ids;

	req = (struct element_req *) pkt_pull(pkt, sizeof(*req));
	if (req == NULL)
		return 0;

	tprintf("Request Element (%u, Len(%u)): ", *id, req->len);
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

	tprintf("BSS Load element (%u, Len(%u)): ", *id, bss_load->len);
	if (len_error(bss_load->len, 5))
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

	tprintf("EDCA Param Set (%u, Len(%u)): ", *id, edca_ps->len);
	if (len_error(edca_ps->len, 18))
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
// 	u32 ac_be, ac_bk, ac_vi, ac_vo;
	struct element_tspec *tspec;

	tspec = (struct element_tspec *) pkt_pull(pkt, sizeof(*tspec));
	if (tspec == NULL)
		return 0;

	tprintf("TSPEC (%u, Len(%u)): ", *id, tspec->len);
	if (len_error(tspec->len, 55))
		return 0;
	tprintf("Traffic Type: %u, ", tspec->traffic_type);
	tprintf("TSID: %u, ", tspec->tsid);
	tprintf("Direction: %u, ", tspec->direction);
	tprintf("Access Policy: %u, ", tspec->access_policy);
	tprintf("Aggregation: %u, ", tspec->aggr);
	tprintf("User Priority: %u, ", tspec->user_prior);
	tprintf("TSinfo Ack Policy: %u, ", tspec->tsinfo_ack_pol);
	tprintf("Schedule: %u, ", tspec->schedule);
	tprintf("Reserved: 0x%x, ", tspec->res);
	tprintf("Nominal MSDU Size: %uB (Fixed (%u)), ",
		tspec->nom_msdu_size >> 1, tspec->nom_msdu_size & 1);
	tprintf("Maximum MSDU Size: %uB, ", tspec->max_msdu_size);
	tprintf("Minimum Service Interval: %uus, ", tspec->min_srv_intv);
	tprintf("Maximum Service Interval: %uus, ", tspec->max_srv_intv);
	tprintf("Inactivity Interval: %uus, ", tspec->inactive_intv);
	tprintf("Suspension Interval: %uus, ", tspec->susp_intv);
	tprintf("Service Start Time: %uus, ", tspec->srv_start_time);
	tprintf("Minimum Data Rate: %ub/s, ", tspec->min_data_rate);
	tprintf("Mean Data Rate: %ub/s, ", tspec->mean_data_rate);
	tprintf("Peak Data Rate: %ub/s, ", tspec->peak_data_rate);
	tprintf("Burst Size: %uB, ", tspec->burst_size);
	tprintf("Delay Bound: %uus, ", tspec->delay_bound);
	tprintf("Minimum PHY Rate: %ub/s, ", tspec->min_phy_rate);
	tprintf("Surplus Bandwidth: %u.%u, ", tspec->surplus_bandw_allow >> 13,
		tspec->surplus_bandw_allow & 0x1FFF);
	tprintf("Medium Time: %uus, ", tspec->med_time * 32);

	return 1;
}

static int8_t inf_tclas(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_sched(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_chall_txt(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_pwr_constr(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_pwr_cap(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_tpc_req(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_tpc_rep(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_supp_ch(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_ch_sw_ann(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_meas_req(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_meas_rep(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_quiet(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_ibss_dfs(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_erp(struct pkt_buff *pkt, u8 *id)
{
	struct element_erp *erp;

	erp = (struct element_erp *) pkt_pull(pkt, sizeof(*erp));
	if (erp == NULL)
		return 0;

	tprintf("ERP (%u, Len(%u)): ", *id, erp->len);
	if (len_error(erp->len, 1))
		return 0;
	tprintf("Non ERP Present (%u), ", erp->param & 0x1);
	tprintf("Use Protection (%u), ", (erp->param >> 1) & 0x1);
	tprintf("Barker Preamble Mode (%u), ", (erp->param >> 2) & 0x1);
	tprintf("Reserved (0x%.5x)", erp->param >> 3);

	return 1;
}

static int8_t inf_ts_del(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_tclas_proc(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_ht_cap(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_qos_cap(struct pkt_buff *pkt, u8 *id)
{
	return 0;
}

static int8_t inf_rsn(struct pkt_buff *pkt, u8 *id)
{
	return 0;
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

	tprintf("Ext Support Rates (%u, Len(%u)): ", *id, ext_supp_rates->len);

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

static int8_t inf_ap_ch_exp(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_neighb_rep(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_rcpi(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mde(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_fte(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_time_out_int(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_rde(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_dse_reg_loc(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_supp_op_class(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ext_ch_sw_ann(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ht_op(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_sec_ch_offs(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_bss_avg_acc_del(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ant(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_rsni(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_meas_pilot_trans(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_bss_avl_adm_cap(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_bss_ac_acc_del(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_time_adv(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_rm_ena_cap(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mult_bssid(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_20_40_bss_coex(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_20_40_bss_int_ch_rep(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_overl_bss_scan_para(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ric_desc(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mgmt_mic(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ev_req(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ev_rep(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_diagn_req(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_diagn_rep(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_loc_para(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_nontr_bssid_cap(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ssid_list(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mult_bssid_index(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_fms_desc(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_fms_req(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_fms_resp(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_qos_tfc_cap(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_bss_max_idle_per(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_tfs_req(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_tfs_resp(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_wnm_sleep_mod(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_tim_bcst_req(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_tim_bcst_resp(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_coll_interf_rep(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ch_usage(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_time_zone(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_dms_req(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_dms_resp(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_link_id(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_wakeup_sched(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ch_sw_timing(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_pti_ctrl(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_tpu_buff_status(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_interw(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_adv_proto(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_exp_bandw_req(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_qos_map_set(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_roam_cons(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_emer_alert_id(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mesh_conf(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mesh_id(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mesh_link_metr_rep(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_cong_notif(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mesh_peer_mgmt(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mesh_ch_sw_para(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mesh_awake_win(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_beacon_timing(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mccaop_setup_req(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mccaop_setup_rep(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mccaop_adv(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mccaop_teardwn(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_gann(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_rann(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_ext_cap(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_preq(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_prep(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_perr(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_pxu(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_pxuc(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_auth_mesh_peer_exch(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mic(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_dest_uri(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_u_apsd_coex(struct pkt_buff *pkt, u8 *id) {
	return 0;
}

static int8_t inf_mccaop_adv_overv(struct pkt_buff *pkt, u8 *id) {
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

	tprintf("Vendor Specific (%u, Len (%u)): ", *id, vend_spec->len);

	data = pkt_pull(pkt, vend_spec->len);
	if (data == NULL)
		return 0;

	tprintf("Data 0x");
	for (i = 0; i < vend_spec->len; i++)
		tprintf("%.2x", data[i]);

	return 1;
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
	case  48: return inf_rsn(pkt, id);
	case  49: return inf_rsn(pkt, id);
	case  50: return inf_ext_supp_rates(pkt, id);
	case  51: return inf_ap_ch_exp(pkt, id);
	case  52: return inf_neighb_rep(pkt, id);
	case  53: return inf_rcpi(pkt, id);
	case  54: return inf_mde(pkt, id);
	case  55: return inf_fte(pkt, id);
	case  56: return inf_time_out_int(pkt, id);
	case  57: return inf_rde(pkt, id);
	case  58: return inf_dse_reg_loc(pkt, id);
	case  59: return inf_supp_op_class(pkt, id);
	case  60: return inf_ext_ch_sw_ann(pkt, id);
	case  61: return inf_ht_op(pkt, id);
	case  62: return inf_sec_ch_offs(pkt, id);
	case  63: return inf_bss_avg_acc_del(pkt, id);
	case  64: return inf_ant(pkt, id);
	case  65: return inf_rsni(pkt, id);
	case  66: return inf_meas_pilot_trans(pkt, id);
	case  67: return inf_bss_avl_adm_cap(pkt, id);
	case  68: return inf_bss_ac_acc_del(pkt, id);
	case  69: return inf_time_adv(pkt, id);
	case  70: return inf_rm_ena_cap(pkt, id);
	case  71: return inf_mult_bssid(pkt, id);
	case  72: return inf_20_40_bss_coex(pkt, id);
	case  73: return inf_20_40_bss_int_ch_rep(pkt, id);
	case  74: return inf_overl_bss_scan_para(pkt, id);
	case  75: return inf_ric_desc(pkt, id);
	case  76: return inf_mgmt_mic(pkt, id);
	case  78: return inf_ev_req(pkt, id);
	case  79: return inf_ev_rep(pkt, id);
	case  80: return inf_diagn_req(pkt, id);
	case  81: return inf_diagn_rep(pkt, id);
	case  82: return inf_loc_para(pkt, id);
	case  83: return inf_nontr_bssid_cap(pkt, id);
	case  84: return inf_ssid_list(pkt, id);
	case  85: return inf_mult_bssid_index(pkt, id);
	case  86: return inf_fms_desc(pkt, id);
	case  87: return inf_fms_req(pkt, id);
	case  88: return inf_fms_resp(pkt, id);
	case  89: return inf_qos_tfc_cap(pkt, id);
	case  90: return inf_bss_max_idle_per(pkt, id);
	case  91: return inf_tfs_req(pkt, id);
	case  92: return inf_tfs_resp(pkt, id);
	case  93: return inf_wnm_sleep_mod(pkt, id);
	case  94: return inf_tim_bcst_req(pkt, id);
	case  95: return inf_tim_bcst_resp(pkt, id);
	case  96: return inf_coll_interf_rep(pkt, id);
	case  97: return inf_ch_usage(pkt, id);
	case  98: return inf_time_zone(pkt, id);
	case  99: return inf_dms_req(pkt, id);
	case 100: return inf_dms_resp(pkt, id);
	case 101: return inf_link_id(pkt, id);
	case 102: return inf_wakeup_sched(pkt, id);
	case 104: return inf_ch_sw_timing(pkt, id);
	case 105: return inf_pti_ctrl(pkt, id);
	case 106: return inf_tpu_buff_status(pkt, id);
	case 107: return inf_interw(pkt, id);
	case 108: return inf_adv_proto(pkt, id);
	case 109: return inf_exp_bandw_req(pkt, id);
	case 110: return inf_qos_map_set(pkt, id);
	case 111: return inf_roam_cons(pkt, id);
	case 112: return inf_emer_alert_id(pkt, id);
	case 113: return inf_mesh_conf(pkt, id);
	case 114: return inf_mesh_id(pkt, id);
	case 115: return inf_mesh_link_metr_rep(pkt, id);
	case 116: return inf_cong_notif(pkt, id);
	case 117: return inf_mesh_peer_mgmt(pkt, id);
	case 118: return inf_mesh_ch_sw_para(pkt, id);
	case 119: return inf_mesh_awake_win(pkt, id);
	case 120: return inf_beacon_timing(pkt, id);
	case 121: return inf_mccaop_setup_req(pkt, id);
	case 122: return inf_mccaop_setup_rep(pkt, id);
	case 123: return inf_mccaop_adv(pkt, id);
	case 124: return inf_mccaop_teardwn(pkt, id);
	case 125: return inf_gann(pkt, id);
	case 126: return inf_rann(pkt, id);
	case 127: return inf_ext_cap(pkt, id);
	case 128: return inf_reserved(pkt, id);
	case 129: return inf_reserved(pkt, id);
	case 130: return inf_preq(pkt, id);
	case 131: return inf_prep(pkt, id);
	case 132: return inf_perr(pkt, id);
	case 133: return inf_reserved(pkt, id);
	case 134: return inf_reserved(pkt, id);
	case 135: return inf_reserved(pkt, id);
	case 136: return inf_reserved(pkt, id);
	case 137: return inf_pxu(pkt, id);
	case 138: return inf_pxuc(pkt, id);
	case 139: return inf_auth_mesh_peer_exch(pkt, id);
	case 140: return inf_mic(pkt, id);
	case 141: return inf_dest_uri(pkt, id);
	case 142: return inf_u_apsd_coex(pkt, id);
	case 143 ... 173: return inf_reserved(pkt, id);
	case 174: return inf_mccaop_adv_overv(pkt, id);
	case 221: return inf_vend_spec(pkt, id);
	}

	return 0;
}

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

static int8_t beacon(struct pkt_buff *pkt)
{
	struct ieee80211_mgmt_beacon *beacon;

	beacon = (struct ieee80211_mgmt_beacon *)
			pkt_pull(pkt, sizeof(*beacon));
	if (beacon == NULL)
		return 0;

	tprintf("Timestamp 0x%.16lx, ", le64_to_cpu(beacon->timestamp));
	tprintf("Beacon Interval (%fs), ", le16_to_cpu(beacon->beacon_int)*TU);
	tprintf("Capabilities (0x%x <->", le16_to_cpu(beacon->capab_info));
	cap_field(le16_to_cpu(beacon->capab_info));
	tprintf(")");

	if(pkt_len(pkt)) {
		tprintf("\n\tParameters:");
		while (inf_elements(pkt)) {
			tprintf("\n\t");
		}
	}

	if(pkt_len(pkt))
		return 0;
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

static const char *mgt_sub(u8 subtype, struct pkt_buff *pkt,
			   int8_t (**get_content)(struct pkt_buff *pkt))
{
	u16 seq_ctrl;
	struct ieee80211_mgmt *mgmt;
	const char *dst, *src, *bssid;

	mgmt = (struct ieee80211_mgmt *) pkt_pull(pkt, sizeof(*mgmt));
	if (mgmt == NULL)
		return 0;

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
	case 0b0110 ... 0b0111:
	case 0b1101 ... 0b1111:
		*get_content = NULL;
		return "Reserved";
	default:
		*get_content = NULL;
		return "Management SubType unknown";
	}
}

static const char *ctrl_sub(u8 subtype, struct pkt_buff *pkt,
			    int8_t (**get_content)(struct pkt_buff *pkt))
{
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
	case 0b0000 ... 0b1001:
		*get_content = NULL;
		return "Reserved";
	default:
		return "Control SubType unkown";
	}
}

static const char *data_sub(u8 subtype, struct pkt_buff *pkt,
		 	    int8_t (**get_content)(struct pkt_buff *pkt))
{
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
	case 0b1000 ... 0b1111:
		*get_content = NULL;
		return "Reserved";
	default:
		*get_content = NULL;
		return "Data SubType unkown";
	}
}

static const char *
frame_control_type(u8 type, const char *(**get_subtype)(u8 subtype,
		   struct pkt_buff *pkt, int8_t (**get_content)(struct pkt_buff *pkt)))
{
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
	case 0b11:
		*get_subtype = NULL;
		return "Reserved";
	default:
		*get_subtype = NULL;
		return "Control Type unkown";
	}
}

static void ieee80211(struct pkt_buff *pkt)
{
	int8_t (*get_content)(struct pkt_buff *pkt) = NULL;
	const char *(*get_subtype)(u8 subtype, struct pkt_buff *pkt,
		int8_t (**get_content)(struct pkt_buff *pkt)) = NULL;
	const char *subtype = NULL;
	struct ieee80211_frm_ctrl *frm_ctrl;

	frm_ctrl = (struct ieee80211_frm_ctrl *)
			pkt_pull(pkt, sizeof(*frm_ctrl));
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
