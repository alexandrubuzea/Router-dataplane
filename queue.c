// Copyright Communication Protocols Team 2022

#include "queue.h"
#include "list.h"
#include <stdlib.h>
#include <assert.h>

struct queue
{
	list head;
	list tail;
};

queue queue_create(void)
{
	queue q = malloc(sizeof(struct queue));
	q->head = q->tail = NULL;
	return q;
}

int queue_empty(queue q)
{
	return q->head == NULL;
}

void queue_enq(queue q, void *element)
{
	if(queue_empty(q)) {
		q->head = q->tail = cons(element, NULL);
	} else {
		q->tail->next = cons(element, NULL);
		q->tail = q->tail->next;
	}
}

void *queue_deq(queue q)
{
	assert(!queue_empty(q));
	{
		void *temp = q->head->element;
		q->head = cdr_and_free(q->head);
		return temp;
	}
}

/** Copyright Buzea Alexandru-Mihai-Iulian 2022 (just this function)
 * This function acts just like STL std::queue<T>::front() method
 */
void *queue_peak(queue q)
{
	if (queue_empty(q))
		return NULL;
	
	return q->head->element;
}
