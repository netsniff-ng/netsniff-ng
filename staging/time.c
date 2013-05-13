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


// Check if current system supports the nanosecond timer functions.
// Additionally, measure the precision.
// This function should be called upon program start.
// 
int check_timer()
{
	struct timespec res;
	int r;
   
// Check if the glibc is recent enough:
#ifdef _POSIX_C_SOURCE

	if (_POSIX_C_SOURCE >= 199309L) {
		r = clock_getres(CLOCK_MONOTONIC, &res);
		if (r!=0)  perror(" mz/check_timer:");
		if (verbose) {
			fprintf(stderr, " This system supports a high resolution clock.\n");
			fprintf(stderr, "  The clock resolution is %li nanoseconds.\n",
				res.tv_nsec);
		}
	}
	else {
		fprintf(stderr, 
			" WARNING: Your system does NOT support the newer high resolution clock\n"
		        "          Please inform the author: herbert@perihel.at\n");
		exit(1);
	}
#endif
	return 0;
}




// This is the replacement for gettimeofday() which would result in 'jumps' if
// the system clock is adjusted (e. g. via a NTP process) and finally the jitter
// measurement would include wrong datapoints.
// 
// Furthermore the function below utilizes the newer hi-res nanosecond timers.
inline void getcurtime (struct mz_timestamp *t)
{
	struct timespec ct;
	clock_gettime(CLOCK_MONOTONIC, &ct);
	t->sec  = ct.tv_sec;
	t->nsec = ct.tv_nsec;
}




//////////////////////////////////////////////////////////////////////////////////////
// Purpose: Calculate time deltas of two timestamps stored in struct timeval.
// 
// Subtract the "struct timeval" values X and Y, storing the result in RESULT,
// i. e. X-Y=RESULT. 
// 
// RETURN VALUES:
// 
//    Sign: 1 = negative, 0 = positive
//    Error: -1 due to a wrong timestamp (i. e. nsec > 999999999L)
// 
inline int timestamp_subtract (struct mz_timestamp *x, struct mz_timestamp *y, struct mz_timestamp *result)
{
	int32_t ndiff;
	int sign=0, carry=0;
		
	// Check for wrong timestamps
	if ((x->nsec>999999999L) || (y->nsec>999999999L)) return -1;
	
	if (y->sec > x->sec) sign=1;
	else if ((y->sec == x->sec) && (y->nsec > x->nsec)) sign=1;

	ndiff = x->nsec - y->nsec;
	if ((ndiff>0) && (sign)) carry=1;
	if ((ndiff<0) && (sign)) ndiff = y->nsec - x->nsec;
	if ((ndiff<0) && (!sign)) {
		ndiff = 1000000000L + ndiff;
		carry=1;
	}
	
	if (sign)
		result->sec = y->sec - x->sec - carry;
	else 
		result->sec = x->sec - y->sec - carry;
	
	result->nsec = ndiff;
	return sign;
}


// Add two variables of type struct mz_timestamp: x+y=result.
// 
inline void timestamp_add (struct mz_timestamp *x, struct mz_timestamp *y, struct mz_timestamp *result)
{
	int carry=0;
	u_int32_t c;
	
	c = x->nsec + y->nsec;
	if (c>999999999L) {
		carry=1;
		result->nsec =c-1000000000;
	} else  result->nsec =c;
	
	result->sec  = x->sec + y->sec + carry;
}



// Returns a human readable timestamp in the string result.
// Optionally a prefix can be specified, for example if the
// timestamp is part of a filename.
// 
// Example: 
//    char myTimeStamp[128];
//    
//    timestamp_human(myTimeStamp, NULL);
//    
//    => "20080718_155521"
//    
//    /* or with prefix */
//    
//    timestamp_human(myTimeStamp, "MZ_RTP_jitter_");
// 
//    => "MZ_RTP_jitter_20080718_155521"
// 
int timestamp_human(char* result, const char* prefix)
{
   time_t curtime;
   struct tm curtime_broken;
   char curtime_str[32];
   
   time(&curtime);
   localtime_r (&curtime, &curtime_broken);

   sprintf(curtime_str, "%4i%02i%02i-%02i%02i%02i",
	   curtime_broken.tm_year+1900,
	   curtime_broken.tm_mon+1,
	   curtime_broken.tm_mday,
	   curtime_broken.tm_hour,
	   curtime_broken.tm_min,
	   curtime_broken.tm_sec);
   
   if (prefix==NULL)
     {
	strncpy(result, curtime_str, 32);
     }
   else
     {
	strncpy(result, prefix, 32);
	strncat(result, curtime_str, 32);
     }
   
   return 0;
}


// Creates a human readable timestamp in the string result.
// Optionally a prefix can be specified, for example if the
// timestamp is part of a filename.
// 
// Example: 
//    char myTimeStamp[9];
//    
//    timestamp_hms (myTimeStamp);
//    
//    => "15:55:21"
int timestamp_hms(char* result)
{
   time_t curtime;
   struct tm curtime_broken;
   char curtime_str[32];
   
   time(&curtime);
   localtime_r (&curtime, &curtime_broken);

   sprintf(curtime_str, "%02i:%02i:%02i",
	   curtime_broken.tm_hour,
	   curtime_broken.tm_min,
	   curtime_broken.tm_sec);
   
   strncpy(result, curtime_str, 9);
   
   return 0;
}





