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

static int8_t inf_ssid() {
	return 1;
}

static int8_t inf_elements(u8 id) {
	switch (id) {
	case 1:
		      return inf_ssid();


	return 0;
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
