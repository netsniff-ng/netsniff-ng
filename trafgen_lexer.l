/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

/* lex-func-prefix: yy */

%{

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "trafgen_parser.tab.h"
#include "xmalloc.h"
#include "built_in.h"
#include "str.h"

extern void yyerror(const char *);

static char *try_convert_shellcode(char *sstr)
{
	bool found_any = false;
	char *bstr, *ostr = sstr, *hay, *orig = sstr;
	size_t j = 0, blen, slen = strlen(sstr), tot = 0;
	const char *needle = "\\x";

	sstr++;
	slen -= 2;

	if (slen % 4 != 0)
		return orig;

	blen = slen / 4;
	hay = sstr;
	while ((hay = strstr(hay, needle)) != NULL ) {
		hay += strlen(needle) + 2;
		found_any = true;
		tot++;
	}

	if (blen != tot || !found_any)
		return orig;

	blen += 2;
	bstr = xzmalloc(blen);

	bstr[j++] = '\"';
	while (j < blen - 1)
		bstr[j++] = (uint8_t) strtoul(sstr + 2, &sstr, 16);
	bstr[j++] = '\"';

	xfree(ostr);
	return bstr;
}

%}

%option align
%option nounput
%option noyywrap
%option noreject
%option 8bit
%option caseless
%option noinput
%option nodefault

number_oct	([0][0-9]+)
number_hex	([0]?[x][a-fA-F0-9]+)
number_bin	([0]?[b][0-1]+)
number_dec	(([0])|([1-9][0-9]*))
number_ascii	([a-zA-Z])

/* rules taken from nftables scanner.l */
hex4		([[:xdigit:]]{1,4})
v680		(({hex4}:){7}{hex4})
v670		((:)((:{hex4}){7}))
v671		((({hex4}:){1})((:{hex4}){6}))
v672		((({hex4}:){2})((:{hex4}){5}))
v673		((({hex4}:){3})((:{hex4}){4}))
v674		((({hex4}:){4})((:{hex4}){3}))
v675		((({hex4}:){5})((:{hex4}){2}))
v676		((({hex4}:){6})(:{hex4}{1}))
v677		((({hex4}:){7})(:))
v67		({v670}|{v671}|{v672}|{v673}|{v674}|{v675}|{v676}|{v677})
v660		((:)((:{hex4}){6}))
v661		((({hex4}:){1})((:{hex4}){5}))
v662		((({hex4}:){2})((:{hex4}){4}))
v663		((({hex4}:){3})((:{hex4}){3}))
v664		((({hex4}:){4})((:{hex4}){2}))
v665		((({hex4}:){5})((:{hex4}){1}))
v666		((({hex4}:){6})(:))
v66		({v660}|{v661}|{v662}|{v663}|{v664}|{v665}|{v666})
v650		((:)((:{hex4}){5}))
v651		((({hex4}:){1})((:{hex4}){4}))
v652		((({hex4}:){2})((:{hex4}){3}))
v653		((({hex4}:){3})((:{hex4}){2}))
v654		((({hex4}:){4})(:{hex4}{1}))
v655		((({hex4}:){5})(:))
v65		({v650}|{v651}|{v652}|{v653}|{v654}|{v655})
v640		((:)((:{hex4}){4}))
v641		((({hex4}:){1})((:{hex4}){3}))
v642		((({hex4}:){2})((:{hex4}){2}))
v643		((({hex4}:){3})((:{hex4}){1}))
v644		((({hex4}:){4})(:))
v64		({v640}|{v641}|{v642}|{v643}|{v644})
v630		((:)((:{hex4}){3}))
v631		((({hex4}:){1})((:{hex4}){2}))
v632		((({hex4}:){2})((:{hex4}){1}))
v633		((({hex4}:){3})(:))
v63		({v630}|{v631}|{v632}|{v633})
v620		((:)((:{hex4}){2}))
v621		((({hex4}:){1})((:{hex4}){1}))
v622		((({hex4}:){2})(:))
v62		({v620}|{v621}|{v622})
v610		((:)(:{hex4}{1}))
v611		((({hex4}:){1})(:))
v61		({v610}|{v611})
v60		(::)

a_hex		([a-fA-F0-9]+)
mac		({a_hex}:{a_hex}:{a_hex}:{a_hex}:{a_hex}:{a_hex})
ip4_addr	([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)
ip6_addr	({v680}|{v67}|{v66}|{v65}|{v64}|{v63}|{v62}|{v61}|{v60})

%%

"cpu"		{ return K_CPU; }
"fill"		{ return K_FILL; }
"rnd"		{ return K_RND; }
"csum16"	{ return K_CSUMIP; }
"csumip"	{ return K_CSUMIP; }
"csumip4"	{ return K_CSUMIP; }
"csumicmp"	{ return K_CSUMIP; }
"csumicmp4"	{ return K_CSUMIP; }
"csumudp"	{ return K_CSUMUDP; }
"csumtcp"	{ return K_CSUMTCP; }
"csumudp6"	{ return K_CSUMUDP6; }
"csumtcp6"	{ return K_CSUMTCP6; }
"csumicmp6"	{ return K_CSUMICMP6; }
"drnd"		{ return K_DRND; }
"dinc"		{ return K_DINC; }
"ddec"		{ return K_DDEC; }
"seqinc"	{ return K_SEQINC; }
"seqdec"	{ return K_SEQDEC; }
"const8"|"c8"	{ return K_CONST8; }
"const16"|"c16"	{ return K_CONST16; }
"const32"|"c32"	{ return K_CONST32; }
"const64"|"c64"	{ return K_CONST64; }

"prot"[o]?	{ return K_PROT; }
"tc"|"tclass"	{ return K_TC; }

	/* Ethernet */
"daddr"|"da"	{ return K_DADDR; }
"saddr"|"sa"	{ return K_SADDR; }
"etype"	        { return K_ETYPE; }
"type"	        { return K_TYPE; }

	/* PFC/IEEE 802.3X PAUSE */
"time"		{ return K_TIME; }
"pri"|"prio"	{ return K_PRIO; }

	/* VLAN (802.1Q & 802.1ad) */
"tpid"		{ return K_TPID; }
"tci"		{ return K_TCI; }
"pcp"		{ return K_PCP; }
"dei"|"cfi"	{ return K_DEI; }
"1ad"		{ return K_1AD; }
"1q"		{ return K_1Q; }

	/* MPLS (Multi Protocol Label Switching) */
"lbl"|"label"	{ return K_LABEL; }
"last"		{ return K_LAST; }
"exp"		{ return K_EXP; }

	/* ARP */
"sha"|"smac"	{ return K_SHA; }
"spa"|"sip"	{ return K_SPA; }
"tha"|"tmac"	{ return K_THA; }
"tpa"|"tip"	{ return K_TPA; }
"req"|"request"	{ return K_REQUEST; }
"reply"		{ return K_REPLY; }
"op"|"oper"	{ return K_OPER; }
"htype"		{ return K_HTYPE; }
"ptype"		{ return K_PTYPE; }

	/* IPv4 */
"ihl"		{ return K_IHL; }
"ver"|"version"	{ return K_VER; }
"ttl"		{ return K_TTL; }
"dscp"		{ return K_DSCP; }
"ecn"		{ return K_ECN; }
"tos"		{ return K_TOS; }
"len"|"length"	{ return K_LEN; }
"id"		{ return K_ID; }
"flags"		{ return K_FLAGS; }
"frag"		{ return K_FRAG; }
"csum"		{ return K_CSUM; }
"df"		{ return K_DF; }
"mf"		{ return K_MF; }

	/* IPv6 */
"fl"|"flow"	{ return K_FLOW; }
"nh"|"nexthdr"	{ return K_NEXT_HDR; }
"hl"|"hoplimit"	{ return K_HOP_LIMIT; }


	/* ICMPv4 */
"addr"		{ return K_ADDR; }
"mtu"		{ return K_MTU; }

	/* ICMPv6 */
"code"		{ return K_CODE; }
"echorequest"	{ return K_ECHO_REQUEST; }
"echoreply"	{ return K_ECHO_REPLY; }

	/* UDP */
"sp"|"sport"	{ return K_SPORT; }
"dp"|"dport"	{ return K_DPORT; }

	/* TCP */
"seq"		{ return K_SEQ; }
"ackseq"|"aseq"	{ return K_ACK_SEQ; }
"doff"|hlen	{ return K_DOFF; }
"cwr"		{ return K_CWR; }
"ece"|"ecn"	{ return K_ECE; }
"urg"		{ return K_URG; }
"ack"		{ return K_ACK; }
"psh"		{ return K_PSH; }
"rst"		{ return K_RST; }
"syn"		{ return K_SYN; }
"fin"		{ return K_FIN; }
"win"|"window"	{ return K_WINDOW; }
"urgptr"	{ return K_URG_PTR; }

	/* DNS */
"qr"		{ return K_QR; }
"aa"|"aanswer"	{ return K_AANSWER; }
"trunc"		{ return K_TRUNC; }
"ravail"	{ return K_RAVAIL; }
"rdesired"	{ return K_RDESIRED; }
"zero"		{ return K_ZERO; }
"rc"|"rcode"	{ return K_RCODE; }
"qdcount"	{ return K_QDCOUNT; }
"ancount"	{ return K_ANCOUNT; }
"nscount"	{ return K_NSCOUNT; }
"arcount"	{ return K_ARCOUNT; }
"name"		{ return K_NAME; }
"class"		{ return K_CLASS; }
"data"		{ return K_DATA; }
"qry"|"query"	{ return K_QUERY; }
"ans"|"answer"	{ return K_ANSWER; }
"auth"		{ return K_AUTH; }
"add"		{ return K_ADD; }
"ns"		{ return K_NS; }
"cname"		{ return K_CNAME; }
"ptr"		{ return K_PTR; }

"eth"		{ return K_ETH; }
"pause"         { return K_PAUSE; }
"pfc"		{ return K_PFC; }
"vlan"		{ return K_VLAN; }
"mpls"		{ return K_MPLS; }
"arp"		{ return K_ARP; }
"ip4"|"ipv4"	{ return K_IP4; }
"ip6"|"ipv6"	{ return K_IP6; }
"icmp4"|"icmpv4" { return K_ICMP4; }
"icmp6"|"icmpv6"	{ return K_ICMP6; }
"udp"		{ return K_UDP; }
"tcp"		{ return K_TCP; }
"dns"		{ return K_DNS; }

[ ]*"-"[ ]*	{ return '-'; }
[ ]*"+"[ ]*	{ return '+'; }
[ ]*"*"[ ]*	{ return '*'; }
[ ]*"/"[ ]*	{ return '/'; }
[ ]*"%"[ ]*	{ return '%'; }
[ ]*"&"[ ]*	{ return '&'; }
[ ]*"|"[ ]*	{ return '|'; }
[ ]*"<"[ ]*	{ return '<'; }
[ ]*">"[ ]*	{ return '>'; }
[ ]*"^"[ ]*	{ return '^'; }
"{"		{ return '{'; }
"}"		{ return '}'; }
"("		{ return '('; }
")"		{ return ')'; }
"["		{ return '['; }
"]"		{ return ']'; }
","		{ return ','; }
":"		{ return ':'; }
"="		{ return '='; }

"\n"		{ yylineno++; }

"\""[^\"]+"\""	{ yylval.str = try_convert_shellcode(xstrdup(yytext));
		  return string; }

([ \t\n]+)?	{ return K_WHITE; }

"/*"([^\*]|\*[^/])*"*/" { return K_COMMENT; }

"#"[^\n]*	{ return K_COMMENT; }

{number_hex}	{ yylval.number = strtoul(yytext + (yytext[0] == 'x' ? 1 : 0),
					  NULL, 16);
		  return number; }

{number_dec}	{ yylval.number = strtol(yytext, NULL, 10);
		  return number; }

{number_oct}	{ yylval.number = strtol(yytext + 1, NULL, 8);
		  return number; }

{number_bin}	{ yylval.number = strtol(yytext + (yytext[0] == 'b' ? 1 : 2),
					 NULL, 2);
		  return number; }

{number_ascii}	{ yylval.number = (uint8_t) (*yytext);
		  return number; }

{mac}	        { if (str2mac(yytext, yylval.mac, 6))
			panic("Failed to parse MAC address %s\n", yytext);
		  return mac; }

{ip4_addr}	{ if (inet_pton(AF_INET, yytext, &yylval.ip4_addr) != 1)
			panic("Failed to parse IPv4 address %s\n", yytext);
		  return ip4_addr; };

{ip6_addr}	{ if (inet_pton(AF_INET6, yytext, &yylval.ip6_addr) != 1)
			panic("Failed to parse IPv6 address %s\n", yytext);
		  return ip6_addr; };

"'\\x"[a-fA-F0-9]{2}"'" { yylval.number = strtol(yytext + 3, NULL, 16);
		  return number; }

"'"."'"		{ yylval.number = (uint8_t) (*(yytext + 1));
		  return number; }

";"[^\n]*	{/* NOP */}
.		{ printf("Unknown character '%s'", yytext);
		  yyerror("lex Unknown character"); }

%%
