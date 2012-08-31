/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2008-2010 Herbert Haas
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the 
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more 
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with 
 * this program; if not, see http://www.gnu.org/licenses/gpl-2.0.html
 * 
*/

#include "mz.h"
#include "mops.h"


// Creates first element, aka "head" element
// This element can also be used! See automops_alloc_protocol!
// 
struct automops * automops_init()
{
	// Create initial automops element:
	struct automops *new_automops = (struct automops*) malloc(sizeof(struct automops));
	new_automops->next = new_automops;
	new_automops->prev = new_automops;
	automops_set_defaults (new_automops);
	new_automops->used = -1; // freshly created, no valid data in it
	return new_automops;
}



// (Re-)sets anything within the specified automops element
void automops_set_defaults(struct automops * cur)
{
	int i;
	
	mz_strncpy(cur->name, "user_proto", 16);
	mz_strncpy(cur->desc, "undefined", 16);
	cur->layers_on  = 0;
	cur->layers_off = 0;

	cur->etype = 0;
	cur->proto = 0;
	for (i=0; i<6; i++) {
		cur->sa[i] = 0x00;
		cur->da[i] = 0xff; // bcast (silly?)
	}
	cur->SA = cur->DA = 0;
	cur->sp = cur->dp = 0;
	
	cur->payload_type = 0; // both ascii or hex
	cur->payload = NULL;
	cur->payload_s = 0;
	cur->defined_externally = -1; // undefined
	if (cur->field != NULL) automops_delete_fields (cur);
	cur->field = NULL;
}


// Returns pointer to new automops element:
//   1) either insert a new automops element in list
//   2) or returns same pointer again if current automops element is empty
// Note that new element N is always PREPENDED to cur:
//   ... = N-2 = N-1 = N = cur = 1 = 2 = ...
// Therefore, cur should be typically a pointer to the head element
// 
struct automops * automops_alloc_protocol(struct automops *cur)
{
	struct automops *new_automops;
	
	if (cur->used == -1) // allows to use head element in list
	{
		new_automops = cur; // current automops was unused => no need to insert a new one!
	}
	else // create new automops element
	{
		new_automops = (struct automops *) malloc(sizeof(struct automops));
		if (new_automops==NULL) 
		{
			fprintf(stderr, "MZ alert: cannot create new automops entry - memory full?\n");
			return NULL; // memory full?
		}
		new_automops->field=NULL; // don't remove this! See automops_set_defaults() to understand.
		automops_set_defaults(new_automops);
	}

	new_automops->used=0;
	
	// append to doubly linked list 
	new_automops->prev = cur->prev;
	new_automops->next = cur;
	cur->prev = new_automops;
	new_automops->prev->next = new_automops;
	
	return new_automops;
}


// Delete particular protocol (remove it from list or mops).
//
// If amp_head is deleted, makes previous element amp_head.
// Note that the global amp_head must exist but within MOPS this
// is always the case.
// 
// RETURN VALUE:
// 
//   - pointer to previous element in the list
//   - NULL if current automops is used by some mops(es)
//         (in this case, we may still need it, maybe the user wants
//         to modify data or wants other information...?)
//    
//   - NULL if current element is a single element attached to a mops
//        
struct automops * automops_delete_protocol(struct automops *cur)
{
	struct automops *last;

	// Maybe the following is not really practical? /////
	if (cur->used>0) {
		return NULL;
	}
	/////////////////////////////////////////////////////
	
	// delete fields list:
	automops_delete_fields (cur);

	if (cur->payload_s) free (cur->payload);
	
	if ((cur!=amp_head) && (cur->prev==NULL) && (cur->next==NULL)) {
		// this one is attached to a mops
		if (cur!=NULL) free (cur);
		return NULL;
	} 
	
	// part of linked list
	last = cur->prev;
	cur->next->prev = cur->prev;
	cur->prev->next = cur->next;
	if (cur==amp_head) {
		amp_head = last;
	}
	if (cur!=NULL) free (cur);
	
   return last;	
}



// Search automops element for a given protocol name
// 
// Returns pointer to that automops element 
//         or NULL if not found
// 
struct automops * automops_search_protocol(struct automops *list, char *name)
{
	struct automops *head = list;
	struct automops *cur = list;
	
	do {
		if ( (strncasecmp(name, cur->name, 
				  AUTOMOPS_MAX_NAME_LEN) == 0)) {
			return cur; // FOUND!    
		}
		cur = cur->next;
	} while (head != cur);
	
	return NULL; // NOT FOUND!
}



// Runs through all automops entries and dumps some basic info 
// Returns the number of used protocols
// 
int  automops_dump_all(struct automops* list)
{
	struct automops *head = list;
	struct automops *cur = list;
	struct fields *f=NULL;
	int anzmops=0, used=0;
	char str[64], ft[32];
	uint32_t SA=0, DA=0;
	uint8_t *x, *y;
	char bits_on[18], bits_off[18];
	int i=0, j=0;
		
	do {
		if (cur->used==-1) {
			fprintf(stderr, "AUTOMOPS: Initial element\n");
			if ((cur->next==cur)&&(cur->prev==cur))
				fprintf(stderr, "  No other elements found.\n");
			break;
		}
		if (cur->used>0) used++;
		anzmops++;
		SA=ntohl(cur->SA); x = (uint8_t*) &SA;
		DA=ntohl(cur->DA); y = (uint8_t*) &DA;
		char2bits(cur->layers_on, bits_on);
		char2bits(cur->layers_off, bits_off);
		fprintf(stderr, "Protocol %i: %s -- %s\n"
			" Layercodes:  X T U I M Q S E\n"
			"    requires  %s (0x%02x)\n" 
			"   conflicts  %s (0x%02x)\n"
			" L2: EtherType=%04x, sa=%02x:%02x:%02x:%02x:%02x:%02x, da=%02x:%02x:%02x:%02x:%02x:%02x\n"
			,
			anzmops, cur->name, cur->desc, 
			bits_on, cur->layers_on, bits_off, cur->layers_off,
			cur->etype, cur->sa[0], cur->sa[1], cur->sa[2], cur->sa[3], cur->sa[4], cur->sa[5],
			cur->da[0], cur->da[1], cur->da[2], cur->da[3], cur->da[4], cur->da[5]);
		if (cur->layers_on&MOPS_IP) {
			fprintf(stderr, " IP: proto=%i, SA=%u.%u.%u.%u, DA=%u.%u.%u.%u\n",
				cur->proto, *x, *(x+1), *(x+2), *(x+3), *y, *(y+1), *(y+2), *(y+3));
		} else {
			fprintf(stderr, " IP: ---\n");
		}
		// Walk through field data:
		f=cur->field; j=0;
		while (f!=NULL) {
			j++; // count number of fields
			if (verbose) {
				i=0;
				if (f->longdesc!=NULL) { 
					mz_strncpy(str, f->longdesc, 60);
					if (strnlen(str,60)>=59) i=1;
				}
				else {
					mz_strncpy(str, "-- no long description specified --", 60);
				}
				amp_type2str(f->type, ft);
				fprintf(stderr, "    %02i  Field [%i] '%s' -- %s\n"
					"        Description: %s%s\n"
					"        Type: %s %s %s (%lu/%lu) {%lu..%lu..%lu} shift: %i; %i chars\n"
					,f->i, f->index, f->name, f->shortdesc,
					str, (i) ? "..." : "", 
					ft, (f->constant) ? "FIXED" : "",
					(f->valname!=NULL) ? f->valname : "(no value name)" ,
					(long unsigned int) f->tlv_type, 
					(long unsigned int) f->tlv_len, 
					(long unsigned int) f->min, 
					(long unsigned int) f->val, 
					(long unsigned int) f->max,
					f->leftshift, f->str_s);
			}
			f=f->next;
		}
		if (verbose==0) fprintf(stderr, " %i fields defined.\n", j);
		//---------------------------------
		cur = cur->next;
	}  while (head != cur);
   
	return used;
}



// Creates an independent automops element for mops
// (it will be not part of any linked list so, next=prev=NULL)
// 
// RETURN VALUE: - Pointer to the cloned automops 
//               - NULL upon failure
//               
struct automops * automops_clone_automops(struct automops * amp)
{
	struct automops *new_automops;
	struct fields *f, *g, *h=NULL;
	int i;
	
	// Allocate memory 
	new_automops = (struct automops *) malloc(sizeof(struct automops));
	if (new_automops==NULL)	{
		fprintf(stderr, "MZ alert: cannot create new automops element - memory full?\n");
		return NULL; // memory full?
	}
	
	// Copy the automops items
	new_automops->next = NULL;
	new_automops->prev = NULL;

	strncpy(new_automops->name, amp->name, AUTOMOPS_MAX_NAME_LEN);
	strncpy(new_automops->desc, amp->desc, AUTOMOPS_MAX_SHORTDESC_LEN);
	new_automops->layers_on = amp->layers_on;
	new_automops->layers_off = amp->layers_off;
	new_automops->etype = amp->etype;
	new_automops->proto = amp->proto;
	for (i=0; i<6; i++) {
		new_automops->da[i] = amp->da[i]; // dst mac
		new_automops->sa[i] = amp->sa[i]; // src mac
	}
	new_automops->DA = amp->DA; // dst IP
	new_automops->SA = amp->SA; // src IP
	new_automops->dp = amp->dp; // dst port
	new_automops->sp = amp->sp; // src port
	new_automops->defined_externally = amp->defined_externally;
	new_automops->payload_type = amp->payload_type;
	if (amp->payload_s) {
		new_automops->payload = (char*) malloc(amp->payload_s);
		if (new_automops->payload==NULL)	{
			fprintf(stderr, "MZ alert: cannot create new automops payload element - memory full?\n");
			return NULL; // memory full?
		}
		memcpy((void*) new_automops->payload, amp->payload, amp->payload_s);
	}

	new_automops->used = amp->used;
         
        ////////////////////////////////////////////////////////////////////////////////////////////////
	//
	//  Copy the fields list
	// 
	new_automops->field = NULL; 
	for (f=amp->field; f!=NULL; f=f->next) {
		g = (struct fields *) malloc(sizeof(struct fields));
		if (g==NULL) {
			fprintf(stderr, "MZ alert: cannot create new field element - memory full?\n");
			return NULL; // memory full?
		}
		if (new_automops->field==NULL) { // first element
			new_automops->field = g;
			h = g;
		} else {                         // next elements
			h->next = g;
			h = g;
		}
		// copy all data. From here on 'h' is the new one, 'f' is the existing one
		mz_strncpy(h->name, f->name, AUTOMOPS_MAX_NAME_LEN);
		mz_strncpy(h->shortdesc, f->shortdesc, AUTOMOPS_MAX_SHORTDESC_LEN);
		mz_strncpy(h->valname, f->valname, AUTOMOPS_MAX_NAME_LEN);
		if (f->longdesc!=NULL) {
			h->longdesc = (char*)
				malloc(strnlen(f->longdesc, 1600)); // 80 chars x 20 lines should be enough
			if (h->longdesc == NULL) {
				fprintf(stderr, "MZ alert: cannot allocate memory!\n");
				return NULL; // memory full?
			}
			strncpy(h->longdesc, f->longdesc, 1600);
		}
		if (f->str_s) {
			h->str_s = f->str_s;
			h->str = (u_int8_t *) malloc(f->str_s);
			if (h->str == NULL) {
				fprintf(stderr, "MZ alert: cannot allocate memory!\n");
				return NULL; // memory full?
			}
			memcpy((void*) h->str, (void*) f->str, f->str_s);
		}
		h->constant  = f->constant;
		h->type      = f->type;
		h->tlv_type  = f->tlv_type;
		h->tlv_len   = f->tlv_len;
		h->val       = f->val;
		h->min       = f->min;
		h->max       = f->max;
		h->leftshift = f->leftshift;
		h->index         = f->index;   
	}
	return new_automops;
}


// Add a new field object 
struct fields * automops_add_field (struct automops *amp)
{
	struct fields *f, *f_prev=NULL, *g;
	int i=0;
	
	// jump to the end of the fields list
	f=amp->field;
	while (f!=NULL) {
		f_prev=f;
		++i;
		f=f->next;
	}
	
	g = (struct fields *) malloc(sizeof(struct fields));
	if (g==NULL) {
		if (verbose) fprintf(stderr, "MZ alert: cannot create new field element - memory full?\n");
		return NULL; // memory full?
	}
	
	if (amp->field==NULL) { // is is first element in amp 
		amp->field = g;
	} else {                // it is just another element in the fields list
		f_prev->next = g;
	}
	g->next=NULL; // 'pointing to NULL' identifies the last element
	g->i=i;       // each field element has a unique internal number
	g->index=0;   // indicates 'empty' field
	automops_field_set_defaults(g);
	return g;
}


// Typically only used by automops_add_field() 
// Only call this function after creating a new field element
void automops_field_set_defaults(struct fields *f)
{
	f->name[0]=0x00;
	f->shortdesc[0]=0x00;
	f->longdesc=NULL;
	f->constant=0;
	
	//NOTE: f->i MUST NOT be reset!
	f->index=0;
	f->valname[0]=0x00;
	f->tlv_type=0;
	f->tlv_len=0;
	f->val=0;
	f->min=0;
	f->max=0;
	f->leftshift=0;
	f->str=NULL;
	f->str_s=0;
	f->next=NULL;
}


// Returns integer equivalent for a string of basic protocols.
// For example returns MOPS_ETH | MOPS_IP for d="eth ip".
// See the definitions in mops.h.
// 
// NOTE: Does (and must) NOT verify whether items are conflicting
// such as "udp tcp". This task MUST be done by callee, otherwise
// this function's purpose would be not generic enough.
// 
// RETURN VALUE: 
//     The sum of basic protocols
//     or -1 upon failure.
int mops_str2layers(char *d)
{
	int ret=0;
	char *tok;
	
	// dissalow too long strings.
	if (strlen(d)>50) return -1; // TODO: replace 100 to a more reasonable value
	
	tok=strtok(d, " ");
	while (tok!=NULL) {
		if (strncasecmp("eth", d, 10)==0) ret |= MOPS_ETH;
		else
		if (strncasecmp("snap", d, 10)==0) ret |= MOPS_SNAP;
		else
		if (strncasecmp("dot1q", d, 10)==0) ret |= MOPS_dot1Q;
		else
	        if (strncasecmp("mpls", d, 10)==0) ret |= MOPS_MPLS;
		else
		if (strncasecmp("ip", d, 10)==0) ret |= MOPS_IP;
		else
		if (strncasecmp("udp", d, 10)==0) ret |= MOPS_UDP;
		else
		if (strncasecmp("tcp", d, 10)==0) ret |= MOPS_TCP;
		else 
		return -1; // unknown
		tok=strtok(NULL, " ");
	}
	return ret;
}

// Returns one of 'enum fieldtypes' for a given ascii string
// or -1 if unknown field type given.
int amp_str2type(char *d)
{
	if (strncasecmp("byte8", d, 10)==0) return Byte8;
	if (strncasecmp("byte16", d, 10)==0) return Byte16;
	if (strncasecmp("byte32", d, 10)==0) return Byte32;
	if (strncasecmp("flaginbyte", d, 16)==0) return Flag_in_Byte;
	if (strncasecmp("multibytes", d, 16)==0) return MultiBytes;
	if (strncasecmp("multibyteshex", d, 16)==0) return MultiBytesHex;
	if (strncasecmp("tlv", d, 10)==0) return TLV;
	return -1;
}

// Converts integer field types into ascii string s[32].
// Returns 0 upon success, 1 if unknown type
int amp_type2str(int t, char *s)
{
	switch (t) {
	 case Byte8:
		mz_strncpy(s, "Byte8", 32);
		break;
	 case Byte16:
		mz_strncpy(s, "Byte16", 32);
		break;
	 case Byte32:
		mz_strncpy(s, "Byte32", 32);
		break;
	 case Flag_in_Byte:
		mz_strncpy(s, "FlagInByte", 32);
		break;
	 case MultiBytes:
		mz_strncpy(s, "MultiBytes", 32);
		break;
	 case MultiBytesHex:
		mz_strncpy(s, "MultiBytesHex", 32);
		break;
	 case TLV:
		mz_strncpy(s, "TLV", 32);
		break;
	 default:
		mz_strncpy(s, "[unknown/same]", 32);
		return 1;
	}
	return 0;
}


// Searches the automops object with specified name 'd'.
// NOTE: The names are case insensitive!
// 
// RETURN VALUE: pointer to that object 
//               or NULL if not found
//   
struct automops * amp_getamp_byname(struct automops *head, char *d)
{
	struct automops *a;
	a = head;
	do {
		if (strncasecmp(a->name, d, AUTOMOPS_MAX_NAME_LEN)==0) return a;
		a=a->next;
	} while (a!=head);
	return NULL; // not found
}


// Add data 'd' identified by tag 'xntag' to the automops entry 'amp'.
// 
// RETURN VALUE: 0 upon success, 1 upon failure
// 
int amp_add_pentry (struct automops *amp, int xntag, char *d)
{
	int i=0;
	char *tok;
	u_int8_t x[MAX_MOPS_MSG_SIZE];
	struct automops *g;
	
	switch (xntag) {
	 case xml_name:
		if (strpbrk(d," \t")!=NULL) return ampInvalidName; // name must not consist of multiple words!
		g = amp_getamp_byname(amp_head, d);
		if (g!=NULL) return ampDuplicateName; // name already exists!
		mz_strncpy(amp->name, d, AUTOMOPS_MAX_NAME_LEN);
		if (verbose==2) {
			fprintf(stderr, "Adding protocol '%s'\n", amp->name);
		}
		break;
		
	 case xml_desc:
		mz_strncpy(amp->desc, d, AUTOMOPS_MAX_SHORTDESC_LEN);
		break;
		
	 case xml_requires:
		i = mops_str2layers(d);
		if (i==-1) return ampInvalidLayer;
		if ((i&MOPS_UDP) && (i&MOPS_TCP)) return ampTCPandUDP; // cannot require both!
		amp->layers_on |= i; // must be ORed because several same-tags allowed
		break;
		
	 case xml_conflicts:
		i = mops_str2layers(d);
		if (i==-1) return ampInvalidLayer;
		amp->layers_off |= i; // must be ORed because several same-tags allowed
		break;
		
	 case xml_payloadtype: // 0=none, 1=ascii, 2=hex, 3=any
		tok = strtok (d," ");
		while (tok!=NULL) {
			if (strncasecmp("allowed", d, 10)==0) { 
				// only change if payload_type is still zero
				if (amp->payload_type==0) amp->payload_type=3; 
			} else
			if (strncasecmp("ascii", d, 10)==0) amp->payload_type|=1;
			else
			if (strncasecmp("hex", d, 10)==0) amp->payload_type|=2;
			else
			if (strncasecmp("any", d, 10)==0) amp->payload_type=3;
			else
			if (strncasecmp("none", d, 10)==0) amp->payload_type=0;
			else return ampPayloadType; // unknown
			tok=strtok(NULL, " ");
		}
		break;
		
	 case xml_payload:
		i=strnlen(d,MAX_MOPS_MSG_SIZE);
		if (i==MAX_MOPS_MSG_SIZE) return ampPayloadLen;
		amp->payload = (char*) malloc (i+1);
		mz_strncpy(amp->payload, d, i+1);
		amp->payload_s = i;
		break;

	 case xml_payloadhex:
		i=str2hex(d,x,MAX_MOPS_MSG_SIZE);
		if (i==MAX_MOPS_MSG_SIZE) return ampPayloadLen;
		if (i==-1) return 1;
		amp->payload = (char*) malloc (i+1);
		memcpy((void*)amp->payload, (void*) x, i);
		amp->payload_s = i;
		break;
		
	 default:
		return ampUnknownTag; 
		
	}
	return 0;
}

// Checks if given index value would be valid for the specified amp.
// (Index values must increase monotonic, successive same-values are
// allowed, step size is 0 or 1 but not greater. First index value
// must be 1. Example: 1,2,2,2,3,4,5,5,5,5,5,6,7,7,7.)
// 
// RETURN VALUE: 0 if ok, 1 if wrong
// 
int amp_checkindex(struct automops *amp, int i)
{
	int last_i=0;
	struct fields *g, *h=NULL;
	
	g=amp->field;
	while (g!=NULL) { // jump to last field object  P->F1->F2->NULL
		if (g->index==0) break; // stop if empty field object found
		h=g;
		g=g->next;
	} // now h is the penultimate object
//	printf("CHECKINDEX: try for %i, amp='%s' -- field '%s', index %i, [%i]\n", 
//		       i, amp->name, h->name, h->index, h->i);
	if (h==NULL) return 0; // first element, so any i is ok
	last_i=h->index;
	if (i<last_i) return 1; // index is decreasing!
	if ((i-last_i)>1) return 1; // index increase step larger 1!
	return 0;
}



// Searches the field object with specified name 'd'.
// NOTE: The names ar case insensitive!
// 
// RETURN VALUE: pointer to that object 
//               or NULL if not found
//   
struct fields * amp_getfield_byname(struct automops *amp, char *d)
{
	struct fields *f;
	
	f = amp->field;
	
	while (f!=NULL) {
		if (strncasecmp(f->name, d, AUTOMOPS_MAX_NAME_LEN)==0) return f;
		f=f->next;
	}
	return NULL; // not found
}



// This strange function ensures that 'w' consists of a single word.
// If 'w' consists of multiple words, it removes all but the first 
// word. Additionally surrounding spaces are removed.
// 
// RETURN VALUE: number of words found
// 
// EXAMPLE: "Hello world" => "Hello" 
//                           (return value = 2)
// 
int ensure_single_word(char *w)
{
	char *t, *t0;
	int i=0;
	
	t=strtok(w," ");
	t0=t;
	while (t!=NULL) {
		i++;
		t=strtok(NULL, " ");
	}
	mz_strncpy(w, t0, AUTOMOPS_MAX_NAME_LEN);
	return i;
}




// Add data 'd' identified by tag 'xntag' to the field entry 'f'
int amp_add_fentry (struct automops *amp, struct fields *f, int xntag, char *d)
{
	int i=0; 
	unsigned long long int ulli=0;
	struct fields *g=NULL;
	
	switch(xntag) {
	 case xml_index:
		i = (int) str2int(d); 
		if (amp_checkindex(amp, i)) return ampInvalidIndex; // invalid index
		f->index = (int) i;
		break;

	 case xml_name:
		if (ensure_single_word(d)>1) return ampInvalidName; // name must be single word
		g = amp_getfield_byname(amp, d);
		if (g!=NULL) return 1; // name already exists
		mz_strncpy(f->name, d, AUTOMOPS_MAX_NAME_LEN);		
		break;

	 case xml_desc:
		mz_strncpy(f->shortdesc, d, AUTOMOPS_MAX_SHORTDESC_LEN);
		break;

	 case xml_longdesc:
		i = strnlen(d, 400);
		if (i==400) return ampDescTooLong;
		f->longdesc = (char*) malloc(i+1);
		mz_strncpy(f->longdesc, d, i+1);
		break;
		
	 case xml_type:
		i = amp_str2type(d);
		if (i==-1) return ampInvalidType;
		f->type = i;
		break;
		
	 case xml_constant:
		if (strncasecmp(d, "yes", 6)==0) f->constant=1;
		else
		if (strncasecmp(d, "no", 6)==0)  f->constant=0;
		else return ampUnknownKeyword; // unknown keyword
		break;
		
	 case xml_valname:
		if (ensure_single_word(d)>1) return ampSingleWordRequired; // name must be single word
		i = strnlen(d, AUTOMOPS_MAX_NAME_LEN);
		if (i==AUTOMOPS_MAX_NAME_LEN) return 1; // too long
		mz_strncpy(f->valname, d, AUTOMOPS_MAX_NAME_LEN);
		break;
		
	 case xml_value:
		ulli = str2lint(d);
		if (ulli>0xffffffff) return ampRangeError;
		f->val = (u_int32_t) ulli;
		break;

	 case xml_min:
		ulli = str2lint(d);
		if (ulli>0xffffffff) return ampRangeError;
		f->min = (u_int32_t) ulli;
		break;

	 case xml_max:
		ulli = str2lint(d);
		if (ulli>0xffffffff) return ampRangeError;
		if (ulli<f->min) return 1; // max must be greater or equal min
		f->max = (u_int32_t) ulli;
		break;

	 case xml_tlvt:
		ulli = str2lint(d);
		if (ulli>0xffffffff) return ampRangeError;
		f->tlv_type = (u_int32_t) ulli;
		break;

	 case xml_tlvl:
		ulli = str2lint(d);
		if (ulli>0xffffffff) return ampRangeError;
		f->tlv_len = (u_int32_t) ulli;
		break;

	 case xml_lshift:
		i = (int) str2int(d);
		if (i>7) return ampRangeError;
		f->leftshift=i;
		break;
		
	 default:
		return ampUnknownTag; // unknown tag
	}
	return 0;
}


// Delete linked list of field elements for a given automops
// Returns the number of deleted elements
int automops_delete_fields (struct automops *amp)
{
	struct fields * cur = amp->field;
	struct fields * tmp;
	int i=0;
	
	if (cur==NULL) return 0;
	
	do {
		tmp = cur;
		cur = cur->next;
		if (tmp->str_s) {
			if (tmp->str!=NULL) {
				free (tmp->str);
				tmp->str=NULL;
			}
		}
		if (tmp->longdesc!=NULL) {
			free(tmp->longdesc);
			tmp->longdesc=NULL;
		}
		if (tmp!=NULL) {
			free(tmp);
			tmp=NULL;
		}
		i++;
	} while (cur!=NULL);
	
	return i;
}



// Deletes all elements except the specified element which us usually 
// the head element. Also 'used' elements will be removed!
//
void automops_delete_all (struct automops *list)
{
	struct automops *head = list;
	struct automops *cur = list->next; 
	struct automops *tmp;

	// Delete all but head element:
	while (head != cur)
	{
		tmp = cur->next;
		if (verbose) {
			fprintf(stderr, "   Deleting '%s'\n",cur->name);
		}
		automops_delete_protocol(cur);
		cur = tmp;
	}
	head->next = head;
	head->prev = head;

	if (verbose) {
		fprintf(stderr, "   Deleting '%s'\n",head->name);
	}

	if (head->payload_s) {
		if (head->payload!=NULL) {
			free (head->payload);
			head->payload=NULL;
		}
	}
	automops_set_defaults(head);
}


// Completely clean up. 
// After that, there is no automops list anymore.
// You only need this function when stopping mausezahn.
// 
void automops_cleanup (struct automops *list)
{
	// 1) delete all elements except head:
	automops_delete_all(list);

	// 2) delete head:
	automops_delete_fields (list);
	if (list->payload_s) {
		if (list->payload!=NULL) {
			free (list->payload);
			list->payload=NULL;
		}
	}
	if (list!=NULL) {
		free(list);
		list=NULL;
	}
}

// Converts amperr error values in 'e' to string messages 's'
// which must be at least 64 bytes in size.
// 
// RETURN VALUE: 0 if convertable, 1 else
// 
int amperr2str (int e, char *s)
{
	switch (e) {
		
	 case ampSuccess:
		break;
	 case ampInvalidIndex:
		mz_strncpy(s, "invalid index", 64);
		break;
	 case ampInvalidName:
		mz_strncpy(s, "invalid name", 64);
		break;

	 case ampDuplicateName:
		mz_strncpy(s, "duplicate name", 64);
		break;

	 case ampDescTooLong:
		mz_strncpy(s, "description too long", 64);
		break;

	 case ampInvalidLayer:
		mz_strncpy(s, "invalid layer", 64);
		break;

	 case ampTCPandUDP:
		mz_strncpy(s, "either TCP or UDP", 64);
		break;

		
	 case ampInvalidType:
		mz_strncpy(s, "invalid type", 64);
		break;

	 case ampUnknownKeyword:
		mz_strncpy(s, "unknown keyword", 64);
		break;

	 case ampSingleWordRequired:
		mz_strncpy(s, "single word required", 64);
		break;

	 case ampRangeError:
		mz_strncpy(s, "invalid range", 64);
		break;

	 case ampPayloadType:
		mz_strncpy(s, "invalid payload type", 64);
		break;

	 case ampPayloadLen:
		mz_strncpy(s, "payload length exceeded", 64);
		break;

		
	 case ampUnknownTag:
		mz_strncpy(s, "unknown tag (check mausezahn version?)", 64);
		break;
		
	 default:
		mz_strncpy(s, "completely unknown cause", 64);
		return 1;
	}
	return 0;
}




// Open amp file (containing XML data describing one or more protocols for automops) 
// and copy the data into a char array. 
// 
// NOTE that the char array must be free'd by the caller.
// 
// RETURN VALUE: - pointer to char array with the XML data 
//               - NULL upon failure
//               
char * mapfile (char *fn)
{
	int i, c;
	long fn_s;
	FILE *fd;
	char *blob;
	
	fd = fopen (fn, "r");
	if (fd==NULL) return NULL;
	
	// Determine length of file
	(void) fseek(fd, 0L, SEEK_END);
	fn_s = ftell(fd);
	if (fn_s > AUTOMOPS_MAX_FILE_SIZE) {
	        fprintf(stderr, " File '%s' exceeds max allowed length (%lu>%i)\n",
			fn, fn_s, AUTOMOPS_MAX_FILE_SIZE);
		fclose(fd);
		return NULL;
	}
	if (verbose) fprintf(stderr, " Parsing %lu bytes from '%s'...\n", fn_s, fn);
	rewind(fd);
	
	blob = (char*) malloc(fn_s+1);
	if (blob==NULL) {
		fclose(fd);
		return NULL;
	}
	
	i=0;
	while ((c=fgetc(fd)) != EOF) {
		blob[i]=(char) c;
		i++;
		if (i>fn_s) {
			fprintf(stderr, " WARNING: parsing '%s' exceeded EOF\n", fn);
			break; // should not reach here
		}
	}
	fclose(fd);
	blob[i]='\0';
	return blob;
}



// Create automops PDU within *mp based on data in *amp
// 
int automops_update (struct mops *mp, struct automops *amp)
{

	return 0;
}

