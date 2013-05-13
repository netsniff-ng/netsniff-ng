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
#include "cli.h"



// Returns integer number for given tag string
// For example xml_tag2int("field") => xml_field == 1
// 
// Returns -1 when tag not known
int xml_tag2int (char *t)
{
	if (!strncasecmp(t, "protocol", XML_MAX_TAG_LEN)) 
		return xml_protocol;

	if (!strncasecmp(t, "field", XML_MAX_TAG_LEN)) 
		return xml_field;

	if (!strncasecmp(t, "name", XML_MAX_TAG_LEN)) 
		return xml_name;

	if (!strncasecmp(t, "desc", XML_MAX_TAG_LEN)) 
		return xml_desc;
	
	if (!strncasecmp(t, "requires", XML_MAX_TAG_LEN)) 
		return xml_requires;
	
	if (!strncasecmp(t, "conflicts", XML_MAX_TAG_LEN)) 
		return xml_conflicts;

	if (!strncasecmp(t, "payloadtype", XML_MAX_TAG_LEN)) 
		return xml_payloadtype;

	if (!strncasecmp(t, "payload", XML_MAX_TAG_LEN)) 
		return xml_payload;

	if (!strncasecmp(t, "payloadhex", XML_MAX_TAG_LEN)) 
		return xml_payloadhex;
	
	if (!strncasecmp(t, "index", XML_MAX_TAG_LEN)) 
		return xml_index;
	
	if (!strncasecmp(t, "longdesc", XML_MAX_TAG_LEN)) 
		return xml_longdesc;

	if (!strncasecmp(t, "type", XML_MAX_TAG_LEN)) 
		return xml_type;
	
	if (!strncasecmp(t, "constant", XML_MAX_TAG_LEN)) 
		return xml_constant;

	if (!strncasecmp(t, "value", XML_MAX_TAG_LEN)) 
		return xml_value;

	if (!strncasecmp(t, "valname", XML_MAX_TAG_LEN)) 
		return xml_valname;
	
	if (!strncasecmp(t, "min", XML_MAX_TAG_LEN)) 
		return xml_min;
	
	if (!strncasecmp(t, "max", XML_MAX_TAG_LEN)) 
		return xml_max;
	
	if (!strncasecmp(t, "tlvt", XML_MAX_TAG_LEN)) 
		return xml_tlvt;

	if (!strncasecmp(t, "tlvl", XML_MAX_TAG_LEN)) 
		return xml_tlvl;

	if (!strncasecmp(t, "lshift", XML_MAX_TAG_LEN)) 
		return xml_lshift;

	return -1;
}


// For a given pair of tag t and parent p check 
// if t is really an allowed child of p.
// RETURN VALUE: 0 if correct, -1 otherwise
// 
int xml_check_parent(int t, int p)
{
	// For given tag t specify allowed parent p
	switch (t) {
		
 	 // no parent allowed
	 case xml_protocol:
		if (p==-1) return 0; 
		break;
	 
	 // has protocol as parent
	 case xml_field:
	 case xml_requires:
	 case xml_conflicts:
	 case xml_payloadtype:
	 case xml_payload:
	 case xml_payloadhex:
		if (p==xml_protocol) return 0;
		break;
		
	 // has field OR protocol as parent
	 case xml_name:
	 case xml_desc:
		if ((p==xml_protocol)||(p==xml_field)) return 0;
		break;
		
         // has field as parent
	 case xml_longdesc:
	 case xml_type:
	 case xml_constant:
	 case xml_valname:
	 case xml_value:
	 case xml_min:
	 case xml_max:
	 case xml_index:
	 case xml_lshift:
	 case xml_tlvt:
	 case xml_tlvl:
		if (p==xml_field) return 0;
	
	}
	return -1;
}


// Parse a single protocol definition. 
// The string 'p' must start with '<protocol>' and end with </protocol>
// 
// RETURN VALUE: 0 upon success, >0 otherwise.
// 
int parse_protocol (char *p)
{
	int i;
	char p_clone[AUTOMOPS_MAX_FILE_SIZE+1];
	struct automops *new_amp;
	
	// Make a local copy of the protocol definition
	strncpy(p_clone, p, AUTOMOPS_MAX_FILE_SIZE);
	p_clone[AUTOMOPS_MAX_FILE_SIZE]='\0';
	
	// Check if XML form is correct.
	//   I thought that this check should be done separately (and not during
	//   the xml_readin() function) for safety reasons. If read-in plus 
	//   validation would be combined, we would have more to clean-up at in
	//   case the XML data is corrupt.
	i = xml_canonic (p_clone);
	
	// If incorrect, tell where error is:
	if ((!quiet) && (i)) { 
		p_clone[i+1]='\0';
		fprintf(stderr, "(EE) Mausezahn automops xml parse error:\n"
			        "========================================\n"
			        "%s <<ERROR>>\n", p_clone);
		fprintf(stderr, "(EE) Error occured at character number %i\n", i);
		fprintf(stderr," --- (printed all valid data until error position) ---\n");
	}

	if (verbose) {
		fprintf(stderr, "...XML verification finished.\n");
	}

	// XML is correct, now create automops entry
	
	if (i==0) { 
		strncpy(p_clone, p, AUTOMOPS_MAX_FILE_SIZE);
		p_clone[AUTOMOPS_MAX_FILE_SIZE]='\0';
		new_amp = automops_alloc_protocol(amp_head);
		i = xml_readin(new_amp, p_clone);

		if ((!quiet) && (i)) {
			if (verbose) {
				p_clone[i+1]='\0';
				fprintf(stderr, "(EE) Invalid XML data at position %i: %s <<ERROR>>\n",
					i, p_clone);
				fprintf(stderr," --- (printed all valid data until error position) ---\n");
			}
			automops_delete_protocol(new_amp);
		}
	}
	return i;
}



// Scans p until the next tag is found and stores
// tag name in t which must be a string of size
// XML_STRLEN (at least).
// 
// Returns  
//     >0   if opening tag is found
//      0   if no tag is found or other problem
//     <0   if closing tag is found
//     
//     If any tag is found the absolut return value
//     indicates the position AFTER the tag, e. g.
//     ...<tag>...     or    ...</tag>...
//             ^here                  ^here
//          
//     Upon problem, the errorness char number is 
//     stored as string within t along with the
//     error reason as string. 
//     
int xml_getnext_tag (char *p, char *t)
{
	int 	i=0,j=0,k=0, 
		sign=1,
		len;

	// are there non-white characters left?
	len = strnlen(p, AUTOMOPS_MAX_FILE_SIZE);
	for (i=0; i<len; i++) if (!isspace(p[i])) j=1; // flag for first non-space character found
	if (!j) { // no more characters found
		t[0]=0x00;
		return 0;  
	}

	// basic length checks
	i=0; j=0;
	if ((len<3)||(len==AUTOMOPS_MAX_FILE_SIZE)) { // 3 is minimum tag length
		snprintf(t, XML_STRLEN, "invalid length (%u)",len);
		return 0;
	}
		
	
	// find first opening ('<') bracket
	do {
		if (p[i]=='<') break;
		i++;
	} while (i<len);

	// tag too close to end
	if (i>(len-3)) {
		snprintf(t, XML_STRLEN, "%4i - no end", i);
		return 0; // no tag found (smallest tag is '<x>')
	}

	j=++i;
	
	// closing tag?
	if (p[i]=='/') {
		i++;
		j++;
		sign=-1;
	}
	
	// find closing bracket 
	//     and get tag name
	do {
		if (p[i]=='>') {
			k=i; // =found
			break;
		}
		i++;
		if (i==len) {
			snprintf(t, XML_STRLEN, "%4i - no end?", i);
			return 0;
		}
	} while (i<(j+XML_MAX_TAG_LEN+1));
	
	// closing '>' really found?
	if (!k) {
		sprintf(t, "%4i - closing bracket missing", i);
		return 0;
	}
	
	// now the tag name is from p[j]..p[k-1]
	
	memcpy((void*) t, (void*) &p[j], k-j);
	t[k-j]='\0';
	
	return sign*(k+1);
}


// Copies data between opening and closing XML tags
// into 't' and returns the length of the data in bytes
//  or zero if nothing found
//  or -1 if protocol or data length is too long
// Note: Assumes that *p points to first byte after opening tag!
int xml_get_data (char *p, char *t)
{
	int i=0, len;
	
	// basic length checks
	len = strnlen(p, AUTOMOPS_MAX_FILE_SIZE);
	if (len==0) return 0;
	
	if (len>AUTOMOPS_MAX_FILE_SIZE) {
		snprintf(t, XML_STRLEN, "invalid length (%u)",len);
		return -1;
	}
	
	// find closing tag 
	// i. e. next opening ('<') bracket
	do {
		if (p[i]=='<') break;
		i++;
	} while (i<len);

	// Set limit on data length
	if (i>1500) return -1; // TODO: consider more reasonable limit
	
	// copy data 
	memcpy((void*) t, (void*) &p[0], i);
	t[i]='\0';
	return i;
}



// Make some simple checks whether XML data correct
// Currently only checks if 
//   - every opening tag has an ending tag (only via verbose now)
//   - tags are properly nested (only 1st order tests now)
//   
// RETURN VALUE: 0 upon success
//               or position of mistake  
//               
int xml_canonic (char *p)
{
	int i=0, l, dlen=0, plen, xntag=-1;
	char t[XML_STRLEN];
	char d[1500];

	struct xnstack stack, *s;
	
	s=&stack;
	xnstack_init(s);
	
	if (verbose==2) {
		fprintf(stderr, "Parsing {%s}\n\n", p);
	}
	
	plen = strnlen(p, AUTOMOPS_MAX_FILE_SIZE);
	
	do {
		l = xml_getnext_tag (p, t); // Now t contains next tag name and l tells whether open or closing
		if (l==0) { 
			if (t[0]==0x00) // no more tag found
				return 0;
			else {  // general failure 
				fprintf(stderr, "%s\n", t);
				return i;
			}
				
		}
		i += abs(l); 
		if (verbose==2) {
			fprintf(stderr, "%4i %4i stack=%i %s%s>\n",i,l,xnstack_size(s),
				(l>0) ? "<" : "</", t);
		}
		if (i>=plen) { // break condition (regular, not an error!)
			i=plen-1;
		}
		p+=abs(l); // now p points to first byte after tag
		
		if (xml_tag2int(t)<0) {
			fprintf(stderr, "mz/xml_canonic: UNKNOWN TAG at position %i\n", i);
			return i;
		}
		
		// Closing tag found: does it match last opening tag?
		if (l<0) {
			if (xml_tag2int(t)!=xnstack_pop(s)) {
				if (verbose) {
					fprintf(stderr, "mz/xml_canonic: Incoherent nesting at position %i\n", i);
				}
				return i;
			}
		}
		
		// Opening tag found: store it in last_tag!
		if (l>0) { 
			xntag=xml_tag2int(t);
			// Check if this tag has proper parent
			if (xml_check_parent(xntag, xnstack_get_top(s))) {
				fprintf(stderr, "mz/xml_canonic: Wrong parent tag\n");
				return i;
			}
			if (xnstack_push(s, xntag)==-1) {
				if (verbose) {
					fprintf(stderr, "mz/xml_canonic: max nesting depth exceeded\n");
				}
				return i;
			}
			// also print data:
			dlen = xml_get_data (p, d);
			if (dlen==-1) {
				if (verbose) {
					fprintf(stderr, "mz/xml_canonic: %s\n", d);
				}
				return i;
			}
			if ((dlen>0) && (verbose==2)) {
				fprintf(stderr, "            %s\n", d); // the data
			}

		}

		if (i==plen-1) return 0;
	} while (l!=0);

	if (xnstack_size(s)!=0) {
		fprintf(stderr,"mz/xml_canonic: number of opening and closing tags does not match!\n");
		return i;
	}
	
	return 0;
}



// Copy data elements of *p into struct *amp 
// =============================================================
// NOTE: THE XML STRUCTURE MUST BE CORRECT                   !!!
//       NO XML CHECKS ARE DONE TO KEEP THIS FUNCTION SMALL  !!!
//       THEREFORE ALWAYS RUN xml_canonic() FIRST            !!!
// =============================================================
// 
// However, this function checks if the *data* is valid.
// 
// RETURN VALUE: 0 upon success, 
//               otherwise character position of wrong data
// 
int xml_readin (struct automops *amp, char *p)
{		
	int i=0, l, dlen=0, plen, xntag=-1, parent=-1, err=0;
	char t[XML_STRLEN];
	char d[1500], errmsg[64];

	struct xnstack stack, *s;
	struct fields *f=NULL;
	
	s=&stack;
	xnstack_init(s);
	
	plen = strnlen(p, AUTOMOPS_MAX_FILE_SIZE);
	
	do {
		l = xml_getnext_tag (p, t); // Now t contains next tag name and l tells whether open or closing
		if (l==0) { 
			if (t[0]==0x00) return 0;
			else
			return i;
		}
		i += abs(l); 
		if (i>=plen) { // break condition (regular, not an error!)
			i=plen-1;
		}
		p+=abs(l); // now p points to first byte after tag
		
		
		// Closing tag found: does it match last opening tag?
		if (l<0) xnstack_pop(s);
		
		// Opening tag found: store it in last_tag!
		if (l>0) { 
			xntag=xml_tag2int(t);
			parent=xnstack_get_top(s); // get parent tag;
			xnstack_push(s, xntag);
			dlen = xml_get_data (p, d);

			if (xntag==xml_field) { // Create new field
				f=automops_add_field(amp);
			} else 
			// Now copy the data 'd' into (the header & fields of) 'amp'
			if (dlen>0) {
				if (parent==xml_protocol) {
					err = amp_add_pentry(amp, xntag, d);
				} else
				if (parent==xml_field) {
					err = amp_add_fentry(amp, f, xntag, d);
				}
				if (err) {
					if (!quiet) {
						amperr2str(err, errmsg);
						fprintf(stderr, "WARNING: Automops found '%s' at XML position %i\n", errmsg, i);
					}
					return i;
				}
			}
		}
		if (i==(plen-1)) return 0;

	} while (l!=0);
	return 0;
}
















///////////////////////////////////////////////////////////////////////////////
//                                                                           //
////////////// ONLY XML NESTING STACK FUNCTIONS BELOW THIS LINE ///////////////
//                  
//

void xnstack_init(struct xnstack *s)
{ 
	s->cursize=0;
}

// Returns top data element or -1 if stack empty
// Does NOT remove data elements!
int xnstack_get_top(struct xnstack *s)
{
	if (s->cursize==0) return -1;
	return s->data[s->cursize-1];
}

// Push data onto stack
// Returns -1 if max stack depth exceeded
int xnstack_push(struct xnstack *s, int d)
{
	if (s->cursize<XN_MAX_STACK)
		s->data[s->cursize++]=d;
	else
		return -1;
	return 0;
}


// Returns top data element and ALSO REMOVES it from stack
// Returns -1 if stack is empty
int xnstack_pop(struct xnstack *s)
{
	int d;
	d=xnstack_get_top(s);
	if (d>=0) s->cursize--;
	return d;
}

int xnstack_size(struct xnstack *s)
{
	return s->cursize;
}

