#ifndef MINITOR_PORT_TYPES
#define MINITOR_PORT_TYPES

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

// DEFINE TYPES
typedef pthread_mutex_t* MinitorMutex;

typedef struct port_timer_t
{
  pthread_t thread;
  int ms;
  bool repeat;
  void* data;
  void ( *function )( struct port_timer_t* );
  volatile bool quit;
  volatile int  generation;    /* incremented on restart; old thread exits autonomously */
  volatile bool thread_done;   /* set by exiting thread; port_timer_stop() waits on it */
  pthread_mutex_t quit_mutex;
  pthread_cond_t  quit_cond;
} port_timer_t;

typedef port_timer_t* MinitorTimer;

typedef struct port_queue_t
{
  void** buffer;
  int capacity;
  int size;
  int in;
  int out;
	pthread_mutex_t mutex;
	pthread_cond_t cond_full;
	pthread_cond_t cond_empty;
  volatile bool closing;      /* set by port_queue_delete; dequeue returns false */
  volatile int  waiter_count; /* threads blocked in dequeue; delete waits for 0 */
} port_queue_t;

typedef port_queue_t* MinitorQueue;
typedef pthread_t MinitorTask;

#endif
