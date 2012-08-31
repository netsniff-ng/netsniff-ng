/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2010 Herbert Haas
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
#include "cli.h"
#include "mops.h"
#include "llist.h"

/* PURPOSE: 
 *   General doubly linked list with management functions.
 * 
 * NOTE:
 *   There is no dummy head element. Every element may contain data!
 *   Therefore there is only one general "create_new_element" function.
 * 
 *   You cannot delete the head element except you want to delete the whole list.
 *   Usually you delete the head element at last. 
 * 
 *   head->refcount always contains the number of elements.
 *   
 *   Each element has a unique index number.
 * 
 *   The user must assign her/his data to (void*) elem->data.
 * 
 */ 


// Create new list element - may be the first one (list==NULL)
//
struct mz_ll * mz_ll_create_new_element(struct mz_ll *list)
{
	struct mz_ll *new_element;
	new_element = (struct mz_ll*) malloc (sizeof(struct mz_ll));
	if (new_element==NULL) return NULL;
	_mz_ll_set_default(new_element);
	if (list==NULL) {
		new_element->next=new_element;
		new_element->prev=new_element;
		new_element->head=new_element;
		new_element->refcount=1;
		new_element->index=0;
		new_element->index_last=0;
	} else {
		new_element->prev=list->prev;
		new_element->next=list;
		new_element->prev->next=new_element;
		list->prev = new_element;
		new_element->head=list;
		list->refcount++;
		list->index_last++;
		new_element->index=list->index_last;
	}

	return new_element;
}

// Delete ONE list element.
int  mz_ll_delete_element (struct mz_ll *cur)
{
	if ((cur==NULL)||(cur==cur->head)) return -1; // don't delete head!
	if (cur->data!=NULL)  { free(cur->data); cur->data=NULL; }
	
	if ((cur->next!=cur)&&(cur->prev!=cur)) {
		cur->prev->next=cur->next;
		cur->next->prev=cur->prev;
	}
	cur->head->refcount--;
	if (cur!=NULL) { free(cur); cur=NULL; }
	return 0;
}


int mz_ll_delete_list (struct mz_ll *list)
{
	struct mz_ll *cur=list, 
		     *tmp;
	
	if (cur==NULL) return 1;
	while (cur!=cur->next) {
		tmp=cur->next;
		mz_ll_delete_element(cur);
		cur=tmp;
	}
	// Finally free list head:
	if (list->data!=NULL) { free(list->data); list->data=NULL; }
	free(list);
	list=NULL;
	return 0;
}
	
struct mz_ll * mz_ll_search_name (struct mz_ll *list, char *str)
{
	struct mz_ll *cur=list;
	do {
		if (strncmp(cur->name, str, MZ_LL_NAME_LEN)==0) return cur;
		cur=cur->next;
	}
	while (cur!=list);
	return NULL;
}

struct mz_ll * mz_ll_search_index (struct mz_ll *list, int i)
{
	struct mz_ll *cur=list;
	do {
		if (cur->index==i) return cur;
		cur=cur->next;
	}
	while (cur!=list);
	return NULL;
}

int mz_ll_size(struct mz_ll *list)
{
	int i=0;
	struct mz_ll *cur=list;

	if (list==NULL) return 0;
	
	do {
		i++;
		cur=cur->next;
	}
	while (cur!=list);
	if (i!=list->refcount) fprintf(stderr, "MZ_LL_SIZE: Anomalous situation. Report this.\n");
        return i;
}


int mz_ll_dump_all(struct mz_ll *list)
{
	int i=0;
	struct mz_ll *cur=list;

	if (list==NULL) return 0;
	
	do {
		i++;
		fprintf(stdout, "Element %i: '%s', index=%i\n",i,cur->name, cur->index);
		cur=cur->next;
	}
	while (cur!=list);
        return i;
}



// ------ PRIVATE: initialize list-element 
void _mz_ll_set_default (struct mz_ll *cur)
{
	cur->refcount = 0;
	cur->data = NULL;
	cur->name[0]='\0';
	cur->index=0;
	cur->state=0;
}




