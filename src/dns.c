/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2008 Herbert Haas
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



////////////////////////////////////////////////////////////////////
//
// DNS: Only UDP-based here 
// 
////////////////////////////////////////////////////////////////////

#include "mz.h"
#include "cli.h"


#define MZ_DNS_HELP \
   		"| DNS type: Send Domain Name System Messages.\n" \
		"|\n" \
		"| Generally there are two interesting general DNS messages: queries and answers. The easiest\n" \
		"| way is to use the following syntax:\n" \
		"|\n" \
		"|   query|q = <name>[:<type>]  ............. where type is per default \"A\"\n" \
		"|                                            (and class is always \"IN\")\n" \
		"|\n" \
		"|   answer|a = [<type>:<ttl>:]<rdata> ...... ttl is per default 0.\n" \
		"|            = [<type>:<ttl>:]<rdata>/[<type>:<ttl>:]<rdata>/...\n" \
		"|\n" \
		"| Note: If you only use the 'query' option then a query is sent. If you additonally add\n" \
		"|       an 'answer' option then an answer is sent.\n" \
		"|\n" \
		"| Examples: \n" \
		"|\n" \
		"|   q = www.xyz.com\n" \
		"|   q = www.xyz.com, a=192.168.1.10\n" \
		"|   q = www.xyz.com, a=A:3600:192.168.1.10\n" \
		"|   q = www.xyz.com, a=CNAME:3600:abc.com/A:3600:192.168.1.10\n" \
		"|\n" \
		"| Note: <type> can be: A, CNAME, or any integer\n" \
		"|\n" \
		"|\n" \
		"| OPTIONAL parameter hacks: (if you don't know what you do this might cause invalid packets)\n" \
		"|\n" \
		"|   Parameter                    Description                               query / reply)\n" \
		"|   -------------------------------------------------------------------------------------\n" \
		"|\n" \
		"|   request/response|reply ..... flag only                               request / n.a.  \n" \
		"|   id ......................... packet id (0-65535)                     random  / random\n" \
		"|   opcode (or op) ............. accepts values 0..15 or one of             std  / 0     \n" \
	        "|                                these keywords: \n" \
		"|         = std ................... Standard Query\n" \
		"|         = inv ................... Inverse Query\n" \
		"|         = sts ................... Server Status Request\n" \
		"|   aa or !aa .................. Authoritative Answer                     UNSET  / SET\n" \
		"|   tc or !tc .................. Truncation                               UNSET  / UNSET\n" \
		"|   rd or !rd .................. Recursion Desired                          SET  / SET\n" \
		"|   ra or !ra .................. Recursion Available                      UNSET  / SET\n" \
		"|   z .......................... Reserved (takes values 0..7)                 0  / 0 \n" \
		"|                                (z=2...authenticated)\n" \
		"|   rcode ...................... Response Code (0..15); interesting           0  / 0 \n" \
		"|                                values are:\n" \
		"|        = 0 ...................... No Error Condition\n" \
		"|        = 1 ...................... Unable to interprete query due to format error\n" \
		"|        = 2 ...................... Unable to process due to server failure\n" \
		"|        = 3 ...................... Name in query does not exist\n" \
		"|        = 4 ...................... Type of query not supported\n" \
		"|        = 5 ...................... Query refused\n" \
		"|\n" \
		"| Count values (values 0..65535) will be set automatically! You should not set these\n" \
		"| values manually except you are interested in invalid packets.\n" \
		"|   qdcount (or qdc) ........... Number of entries in question section        1  / 1\n" \
		"|   ancount (or anc) ........... Number of RRs in answer records section      0  / 1\n" \
		"|   nscount (or nsc) ........... Number of name server RRs in authority       0  / 0\n" \
		"|                                records section\n" \
		"|   arcount (or arc) ........... Number of RRs in additional records section  0  / 0\n" \
		"\n"


int dns_get_query (char* argval);
int dns_get_answer (char* argval);



// Note: I do NOT use libnet here (had problems with bugs there...)
int create_dns_packet ()
{
   
   char  *token, *tokenptr, argval[MAX_PAYLOAD_SIZE];

   int i=0,j=0;
   
   unsigned char *x;
   u_int16_t    tmp;

   
   // 16 bit values:
   u_int8_t 
     dns_id0        =0,                    // DNS packet ID
     dns_id1        =0,
     dns_flags0     =0,                    // consists of the flags below
     dns_flags1     =0,
     dns_num_q0     =0,                    // number of questions
     dns_num_q1     =0,
     dns_num_ans0   =0,                    // number of answer resource records
     dns_num_ans1   =0,
     dns_num_aut0   =0,                    // number of authority resource records
     dns_num_aut1   =0,
     dns_num_add0   =0,                    // number of additional resource records
     dns_num_add1   =0,
     dns_type0      =0,
     dns_type1      =0;
   
   
   // bit fields for dns_flags1: Q/R(1), OPCODE(4), AA(1), TC(1), RD(1)
   // bit fields for dns_flags0: RA(1), Z(3), RCODE(4)
   u_int8_t
     dns_flags_qr,                  // 1 bit
     dns_flags_opcode,              // 4 bits
     dns_flags_aa,                  // 1 bit
     dns_flags_tc,                  // 1 bit
     dns_flags_rd,                  // 1 bit
     // ---- next byte -----
     dns_flags_ra,                  // 1 bit
     dns_flags_z,                   // 3 bits
     dns_flags_rcode;               // 4 bits
   
   
   u_int8_t
     dns_packet[MAX_PAYLOAD_SIZE],  // finally the whole packet with all sections
     section[MAX_PAYLOAD_SIZE];     // contains only a section (intermediately)
   u_int32_t
     dns_packet_s;
   
   
   
   if ( (getarg(tx.arg_string,"help", NULL)==1) && (mode==DNS) )
     {
	if (mz_port)
	  {
	     cli_print(gcli, "%s", MZ_DNS_HELP);
	     return -1;
	  }
	else
	  {
	     fprintf(stderr,"\n" 
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_DNS_HELP);
	     exit(0);
	  }
     }
 

   // general defaults: 
   // TODO: define globals in case dns is called by external functions!)
   //       MOST SAFEST AND EASIEST METHOD: define tx.dns_xxxx for default-initialization
   // 
   dns_id0           = 0x42;    // dns_id0 = (u_int8_t) ( ((float) rand()/RAND_MAX)*255);
   dns_id1           = 0x42; 
   
   dns_flags_qr      = 0;        // request
   dns_flags_opcode  = 0;        // 'standard query' (also for response!)
   
   dns_type0         = 1;        // A record
   dns_type1         = 0;


   i=0; 
   
   
   /////////////////////////////////////////////////////////////////////////////////
   // Evaluate CLI parameters:

   
   //  Handle the query //

   if ( (getarg(tx.arg_string,"query", argval)==1) ||
	(getarg(tx.arg_string,"q", argval)==1) )
     {

	(void) dns_get_query (argval); // returns the length in byte	dns_num_q0=1;
	
	// copy the result from gbuf to our local buffer 'section':
	for (j=0;j<gbuf_s;j++)
	  {
	     section[j]=gbuf[j];
	  }

	i = gbuf_s;
	
	// Set defaults if not already set by callee. 
	// !! But ONLY set these if there is no additional answer section
	// !! because then the answer section should set the defaults !!!
	if ( (getarg(tx.arg_string,"answer", NULL)==0) && // no answer
	     (getarg(tx.arg_string,"a", NULL)==0) )
	  {
	     if (!tx.dp)     tx.dp = 53;
	     if (!tx.sp)     tx.sp = 42000;
	  }
	

	// These are the defaults for a query:
	dns_flags_aa           = 1; // authoritative answer
	dns_flags_tc           = 0; // not truncated
	dns_flags_rd           = 1; // recursion desired
	dns_flags_ra           = 0; // recursion available
	dns_flags_z            = 0; // FYI: if 010 = 2 = authenticated
	dns_flags_rcode        = 0; // no errors
	dns_num_q0             = 1; // number of questions
     }


   
   // Handle the answer:
   // 
   // answer|a = <name>[:<type>[:<class>]]/[<ttl>:]<rdata>\n"
    if ( (getarg(tx.arg_string,"answer", argval)==1) ||
	     (getarg(tx.arg_string,"a", argval)==1) )
     {

	// In case there are multiple answer sections seperate them with / or |
	token = strtok_r(argval,"/|",&tokenptr);
	do
	  {
	     //then the corresponding answer section:
	     //first create a pointer to the <name>:
	     section[i]=0xc0; // a pointer always starts with MSB=11xxxxxx xxxxxxx = 0xc0
	     i++;
	     section[i]=0x0c; // this number always points to the first query entry
	     i++;
	     //then add rdata
	     dns_num_ans0 += dns_get_answer (token);
	     //NOTE: 'i' points to the next free byte in section[] (see the query handling above)
	     for (j=0;j<gbuf_s;j++)
	       {
		  section[j+i]=gbuf[j];
	       }
	     i=i+gbuf_s; // so 'i' again points to the next free byte in section[] 
	  } while ( (token = strtok_r(NULL,"/|",&tokenptr))!=NULL);

	if (!tx.sp) tx.sp = 53;
	if (!tx.dp) tx.dp = 42000;  // should be set by user
	dns_flags_qr           = 1; // response
	dns_flags_aa           = 0; // no authoritative answer
	dns_flags_tc           = 0; // not truncated
	dns_flags_rd           = 1; // recursion desired
	dns_flags_ra           = 0; // recursion not available
	dns_flags_z            = 0; // FYI: if 010 = 2 = authenticated
	dns_flags_rcode        = 0; // no errors
     }
   
   
   
   // *** NOTE ***
   // Now 'i' contains the number of DNS payload bytes = valid bytes in section[]
   //
   
  
   ///////////////////////////////////////////////////////////////////////////////////////////////
   // Now let's handle the optional other commands, if some user really changed them...
   //
   //
   
   if (getarg(tx.arg_string,"id",argval)==1)
     {
	tmp = (u_int16_t) str2int (argval);
	x = (unsigned char*) &tmp;
	
	dns_id1 = *x;
	x++;
	dns_id0 = *x;
     }
   
   
   if ( (getarg(tx.arg_string,"opcode", argval)==1) || (getarg(tx.arg_string,"op", argval)==1))
     {
	if (strncmp(argval,"std",3)==0)      // standard query
	  {
	     dns_flags_opcode = 0;
	  }
	else if (strncmp(argval,"inv",3)==0) // inverse query
	  {
	     dns_flags_opcode = 1;
	  }
	else if (strncmp(argval,"sts",3)==0) // status server request
	  {
	     dns_flags_opcode = 2;
	  }
	else // specified as integer
	  {
	     dns_flags_opcode = (u_int8_t) str2int (argval);
	     if (dns_flags_opcode > 15)
	       {
		  if (!quiet) 
		    { 
		       fprintf(stderr, "mz/dns: [Warning] Opcode cannot exceed 15 =>  will reduce to 15!\n");
		    }
		  dns_flags_opcode = 15;
	       }
	  }
     }


   
   
   if (getarg(tx.arg_string,"aa",NULL)==1)
     {
	dns_flags_aa = 1;
     }
   
   if (getarg(tx.arg_string,"!aa",NULL)==1)
     {
	dns_flags_aa = 0;
     }
   
   if (getarg(tx.arg_string,"tc",NULL)==1)
     {
	dns_flags_tc = 1;
     }
   
   if (getarg(tx.arg_string,"!tc",NULL)==1)
     {
	dns_flags_tc = 0;
     }
   
   if (getarg(tx.arg_string,"rd",NULL)==1)
     {
	dns_flags_rd = 1;
     }
   
   if (getarg(tx.arg_string,"!rd",NULL)==1)
     {
	dns_flags_rd = 0;
     }
   
   if (getarg(tx.arg_string,"ra",NULL)==1)
     {
	dns_flags_ra = 1;
     }
   
   if (getarg(tx.arg_string,"!ra",NULL)==1)
     {
	dns_flags_ra = 0;
     }
   
   if (getarg(tx.arg_string,"z", argval)==1)
     {
	dns_flags_z = (u_int8_t) str2int (argval);
	if (dns_flags_z > 7)
	  {
	     if (!quiet) 
	       { 
		  fprintf(stderr, "mz/dns: [Warning] z cannot exceed 7 =>  will reduce to 7!\n");
	       }
	     dns_flags_z = 7;
	  }
     }


   
   if (getarg(tx.arg_string,"rcode", argval)==1)
     {
	dns_flags_rcode = (u_int8_t) str2int (argval);
	if (dns_flags_rcode > 15)
	  {
	     if (!quiet) 
	       { 
		  fprintf(stderr, "mz/dns: [Warning] rcode cannot exceed 15 =>  will reduce to 15!\n");
	       }
	     dns_flags_rcode = 7;
	  }
     }
   
   
   if ( (getarg(tx.arg_string,"qdcount", argval)==1) ||
	(getarg(tx.arg_string,"qdc", argval)==1) ||
	(getarg(tx.arg_string,"qc", argval)==1) )
	
     {
	tmp = (u_int16_t) str2int (argval);
	x = (unsigned char*) &tmp;
	dns_num_q1 = *x;
	x++;
	dns_num_q0 = *x;
     }
   
   if ( (getarg(tx.arg_string,"ancount", argval)==1) ||
	(getarg(tx.arg_string,"anc", argval)==1) )
     {
	tmp = (u_int16_t) str2int (argval);
	x = (unsigned char*) &tmp;
	dns_num_ans1 = *x;
	x++;
	dns_num_ans0 = *x;
     }
   
   if ( (getarg(tx.arg_string,"nscount", argval)==1) ||
	(getarg(tx.arg_string,"nsc", argval)==1) )
     {
	tmp = (u_int16_t) str2int (argval);
	x = (unsigned char*) &tmp;
	dns_num_aut1 = *x;
	x++;
	dns_num_aut0 = *x;
     }

   if ( (getarg(tx.arg_string,"arcount", argval)==1) ||
	(getarg(tx.arg_string,"arc", argval)==1) )
     {
	tmp = (u_int16_t) str2int (argval);
	x = (unsigned char*) &tmp;
	dns_num_add1 = *x;
	x++;
	dns_num_add0 = *x;
     }
   
   //
   //  End of optional parameter handling
   //
   ///////////////////////////////////////////////////////////////////////////////////////////////
 


   
   ///////////////////////////////////////////////////////// 
   //  Now put all together i. e.  create the UDP payload 
   //
   // bit fields for dns_flags1: Q/R(1), OPCODE(4), AA(1), TC(1), RD(1)
   // bit fields for dns_flags0: RA(1), Z(3), RCODE(4)
   // 
   //   7  6  5  4  3  2  1  0   
   // +--+--+--+--+--+--+--+--+
   // |QR|  OPCODE   |AA|TC|RD|
   // +--+--+--+--+--+--+--+--+
   // 
   // 
   //   7  6  5  4  3  2  1  0   
   // +--+--+--+--+--+--+--+--+
   // |RA|    Z   |   RCODE   |
   // +--+--+--+--+--+--+--+--+
   //

   //// Flags: MSB
   dns_flags_qr <<= 7;
   dns_flags1 |= dns_flags_qr;

   dns_flags_opcode <<= 3;
   dns_flags1 |= dns_flags_opcode;
   
   dns_flags_aa <<= 2;
   dns_flags1 |= dns_flags_aa;
   
   dns_flags_tc <<= 1;
   dns_flags1 |= dns_flags_tc;
   
   dns_flags1 |= dns_flags_rd;
   
   //// Flags: LSB
   
   dns_flags_ra <<= 7;
   dns_flags0 |= dns_flags_ra;
   
   dns_flags_z <<= 4;
   dns_flags0 |= dns_flags_z;
   
   dns_flags0 |= dns_flags_rcode;
   
   //// Add header bytes to dns_packet:
   
   dns_packet[0]=dns_id1;
   dns_packet[1]=dns_id0;
   
   dns_packet[2]=dns_flags1;
   dns_packet[3]=dns_flags0;
   
   dns_packet[4]=dns_num_q1;
   dns_packet[5]=dns_num_q0;
   
   dns_packet[6]=dns_num_ans1;
   dns_packet[7]=dns_num_ans0;
   
   dns_packet[8]=dns_num_aut1;
   dns_packet[9]=dns_num_aut0;
   
   dns_packet[10]=dns_num_add1;
   dns_packet[11]=dns_num_add0;
   
   //// Add sections to dns_packet:

   
   for (j=0; j<i; j++)
     {
	dns_packet[12+j] = section[j];
     }

   //
   //////////////////////////////////////////////////////////

   dns_packet_s = i+12;
   tx.udp_payload_s = dns_packet_s;
      
   // copy the dns_paylod to the udp_payload

   for (j=0; j<tx.udp_payload_s; j++)
     {
	tx.udp_payload[j] = dns_packet[j];
     }
     
   tx.udp_len = 8 + tx.udp_payload_s;
   
   return dns_packet_s;
}



////////////////////////////////////////////////////////////////////////////////////////////
// Accepts a string like "www.perihel.at:A" or "www.perihel.at"
// and creates a valid query section using the global gbuf[] and gbuf_s 
// 
// query|q = <name>[:<type>]\n"
// Return value: 
//   number of queries (currently only 1 query accepted, 
//   hence return value is 1 on success or 0 upon failure
//   
int dns_get_query(char* argval)
{
   char *token, *field, *saveptr1=NULL, *saveptr2=NULL;
   int i,j, cnt;
   u_int16_t tmp;
   unsigned char *x;
   
   i=0;
   
   // now get first field: <name>
   field = strtok_r(argval, ":", &saveptr1);
   
   // decompose <name> into labels:
   token = strtok_r(field, ".", &saveptr2);

   do   // loop through all labels 
     {
	cnt = strlen(token);
	gbuf[i] = cnt; 
	i++;
	for (j=i; j<(i+cnt);j++)
	  {
	     gbuf[j] = *token;
	     token++;
	  }
	i+=cnt;
	
     } while ( (token = strtok_r(NULL, ".", &saveptr2)) != NULL);

   gbuf[i]=0x00;
   i++; // (always point to next empty byte)

   
   // lets see if <type> has also been specified:
   if ( (field = strtok_r(NULL, ":", &saveptr1)) !=NULL)
     {
	if ( (strncmp(field, "A",1)==0) || (strncmp(field, "a",1)==0) )
	  {
	     tmp = 1;
	  }
	else
	  {
	     tmp = (u_int16_t) str2int (field);
	  }

	x = (unsigned char*) &tmp;

	gbuf[i] = *(x+1);
	i++;
	gbuf[i] = *x;
	i++;
     }
   else // use default type=A
     {
	gbuf[i] =  0x00; i++;
	gbuf[i] =  0x01; i++;
     }

   // finally add the class=IN:
   gbuf[i] =  0x00; i++; 
   gbuf[i] =  0x01; i++;

   // this is the number of used bytes:
   gbuf_s = i;

   //////// TEST
   /*
   for (j=0; j<i; j++) 
     {
	printf("%02x \n",gbuf[j]);
     }
   printf("i=%u\n",i);
   */
   
   return 1;
}






//
// Given a label (e. g. www.google.com) creates correct bytes in *buf
// and returns number of bytes created.
// NOTE: Label MUST NOT be longer than 512 characters.
// 
int dns_process_label(char* label, u_int8_t *buf)
{
   char *saveptr=NULL, *token;
   int i=0, j=0, cnt=0, avoid_buffer_overflow=0;
   
   token = strtok_r(label, ".", &saveptr);
   
   do   // loop through all labels 
     {
	cnt = strlen(token);
	i++;
	*buf = cnt;
	buf++;
	avoid_buffer_overflow++;	
	for (j=0; j<cnt ;j++)
	  {	     
	     *buf = *token;
	     buf++;
	     avoid_buffer_overflow++;
	     if (avoid_buffer_overflow == 512) return 512;
	     token++;
	  }
	i+=cnt;
	
     } while ( (token = strtok_r(NULL, ".", &saveptr)) != NULL);
   *buf=0x00;
   i++; // number of total bytes written
   return i;
}





// Accepts a valid triple of type:ttl:rdata and writes anything in gbuf[] and gbuf_s.
// 
// Syntax examples:
// 
//    CNAME:3600:abc.com      => Depending on type the rdata must be handled differently
//    A:86400:192.168.1.33    => Up to 3 parameters
//    A:192.168.1.33          => TTL may be omitted, then TTL=0
//    192.168.1.44            => Single parameter can only be an A record
// 
// Other TYPES than A and CNAME are currently not supported and therefore the user must 
// specify RDATA in hex.
//

int dns_get_answer(char* argval)
{
   char *field, *saveptr1=NULL;
   char field1[512], field2[512], field3[512];
   int i, len, num_params;
   u_int16_t TYPE=1; // A
   u_int8_t *ptrTYPE;
   u_int32_t TTL=0;
   u_int8_t *ptrTTL;
   u_int16_t RDLEN;
   u_int8_t *ptrRDLEN;
   u_int8_t rdata[512];
   
   field1[0]='\0';
   field2[0]='\0';
   field3[0]='\0';

   len = strlen (argval);

   // determine number of occurences of ':'
   num_params=1;
   for (i=0; i<len; i++)
     {
	if (argval[i]==':') num_params++;
     }
   if (num_params>3) return 0; // Error!
   
   // now get the fields (type, ttl, rdata)
   field = strtok_r(argval, ":", &saveptr1);
   strncpy(field1, field, 512);
   if (num_params>1)  // 2 or 3
     {
	field = strtok_r(NULL, ":", &saveptr1);
	strncpy(field2, field, 512);
	if (num_params==3)
	  {
	     field = strtok_r(NULL, ":", &saveptr1);
	     strncpy(field3, field, 512);
	  }
     }
   
   
   // Now we have all parameters in field1, field2, and field3.
   // But field2 and/or field3 might be empty.
   
   switch (num_params)
     {
      case 1: // only RDATA specified
	strncpy(field3, field1, 512); 
	strcpy(field1, "A");
	strcpy(field2, "0");
	break;
      case 2: // TYPE and RDATA
	strncpy(field3, field2, 512);
	strcpy(field2, "0");
	break;
     }

   //CHECK:
   //printf("fields: [%s] [%s] [%s]\n",field1,field2,field3);
   
   //////////////////////////////////////////////////////////////////////
   // Now create the whole answer section: Type, Class, TTL, RDLEN, RDATA
     
   //// TYPE
   if ( (strcmp(field1,"CNAME")==0) ||
	(strcmp(field1,"cname")==0) )
     {
	TYPE=5;
	gbuf[0]=0x00;
	gbuf[1]=0x05;
     }
   else if ( (strcmp(field1,"A")==0) ||
	     (strcmp(field1,"a")==0) )
     {
	TYPE=1;
	gbuf[0]=0x00;
	gbuf[1]=0x01;
     }
   else // type must be given as number
     {
	TYPE = (u_int16_t) str2int(field1);
	ptrTYPE = (u_int8_t*) &TYPE;
	gbuf[0]=*(ptrTYPE+1);
	gbuf[1]=*(ptrTYPE);
     }
   
   
   //// CLASS = IN = 0x00 01
   gbuf[2]= 0x00; gbuf[3]=0x01;
   
   //// TTL
   TTL = (u_int32_t) str2int(field2);
   ptrTTL = (u_int8_t*) &TTL; 
   gbuf[4]= *(ptrTTL+3);
   gbuf[5]= *(ptrTTL+2); 
   gbuf[6]= *(ptrTTL+1); 
   gbuf[7]= *(ptrTTL+0); 

   
   //// RDLEN and RDATA
   if (TYPE==1)      // A
     {
	RDLEN = num2hex(field3, rdata); // should be 4 if IP address
	if (RDLEN!=4)
	  {
	     fprintf(stderr," mz/dns_get_answer: [WARNING] RDATA of A record should contain an IPv4 address (4 bytes).\n");
	  }  
     }
   else if (TYPE==5) // CNAME 
     {
	RDLEN = dns_process_label (field3, rdata);
	if (RDLEN==0)
	  {
	     fprintf(stderr," mz/dns_get_answer: [WARNING] RDATA must contain a domain name.\n");
	  }
     }
   else              // Any other type 
     {
	RDLEN = str2hex(field3, rdata, 512); // should be 4 if IP address
     }
   
   ptrRDLEN = (u_int8_t*) &RDLEN;
   gbuf[8] = *(ptrRDLEN+1);
   gbuf[9] = *(ptrRDLEN+0);

   
   // finally write rdata
   for (i=0; i<RDLEN; i++) 
     {
	gbuf[10+i] = rdata[i];
     }
   gbuf_s = 10+RDLEN;

   //////// TEST
   /*
   for (i=0; i<gbuf_s; i++) 
     {
	printf("%02x \n",gbuf[i]);
     }
   printf("i=%u\n",i);
   */

   return 1;
   
}
