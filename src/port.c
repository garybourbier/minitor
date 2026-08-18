#include "../h/port.h"

#include "../h/core.h"
#include "../h/connections.h"
#include "../h/consensus.h"

#include <esp_system.h>
#include <esp_pthread.h>
#include <esp_heap_caps.h>

const char* PORT_TAG = "PORT";

// ESP-IDF default pthread stack is 3KB — way too small for wolfSSL TLS (needs ~16KB+).
// Helper to create a pthread with explicit stack size.
static int _pthread_create_with_stack( pthread_t *thread, void *(*func)(void*),
                                       void *arg, size_t stack_bytes )
{
  pthread_attr_t attr;
  int ret;

  // Route stack allocation to PSRAM — internal SRAM largest free block (~31KB)
  // is too small for our 16-32KB pthread stacks after WiFi driver claims ~50KB.
  // esp_pthread_set_cfg applies to the next pthread_create() call only.
  esp_pthread_cfg_t pcfg = esp_pthread_get_default_config();
  pcfg.stack_alloc_caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
  esp_pthread_set_cfg( &pcfg );

  pthread_attr_init( &attr );
  pthread_attr_setstacksize( &attr, stack_bytes );
  ret = pthread_create( thread, &attr, func, arg );
  pthread_attr_destroy( &attr );
  return ret;
}

MinitorMutex port_mutex_create()
{
  int ret;
  MinitorMutex mutex = malloc( sizeof( pthread_mutex_t ) );

  ret = pthread_mutex_init( mutex, NULL );

  if ( ret != 0 )
  {
    MINITOR_LOG( PORT_TAG, "pthread_mutex err: %d", ret );

    free( mutex );
  }

  return mutex;
}

/* Timer threads are DETACHED with PSRAM stacks.  When port_timer_set_ms()
   increments the generation the old thread exits autonomously — no join needed.
   thread_done is set on exit so port_timer_stop() can wait without pthread_join. */
static void* port_timer_task( void* arg )
{
  MinitorTimer timer  = (MinitorTimer)arg;
  int          my_gen = timer->generation;

  while ( !timer->quit && timer->generation == my_gen )
  {
    struct timespec deadline;
    clock_gettime( CLOCK_REALTIME, &deadline );
    deadline.tv_sec  += timer->ms / 1000;
    deadline.tv_nsec += ( timer->ms % 1000 ) * 1000000L;
    if ( deadline.tv_nsec >= 1000000000L )
    {
      deadline.tv_sec++;
      deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock( &timer->quit_mutex );
    while ( !timer->quit && timer->generation == my_gen )
    {
      int rc = pthread_cond_timedwait( &timer->quit_cond, &timer->quit_mutex, &deadline );
      if ( rc != 0 ) break; /* ETIMEDOUT → deadline passed, fire the callback */
    }
    bool should_fire = ( !timer->quit && timer->generation == my_gen );
    pthread_mutex_unlock( &timer->quit_mutex );

    if ( !should_fire ) break;

    timer->function( timer );

    if ( !timer->repeat ) break;
    /* outer while re-checks generation before next sleep */
  }

  /* Signal completion.  Always signal so port_timer_stop() is never left
     waiting — even if we are a superseded (old-generation) thread. */
  pthread_mutex_lock( &timer->quit_mutex );
  timer->thread_done = true;
  pthread_cond_broadcast( &timer->quit_cond );
  pthread_mutex_unlock( &timer->quit_mutex );

  return NULL;
}

/* Helper: create a DETACHED timer thread with an 8 KB PSRAM stack.
   DETACHED: stack freed immediately on exit — no pthread_join() needed.
   PSRAM: saves internal SRAM (only ~25 KB free after consensus download). */
static int _timer_thread_create( MinitorTimer timer )
{
  esp_pthread_cfg_t pcfg = esp_pthread_get_default_config();
  pcfg.stack_alloc_caps  = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
  esp_pthread_set_cfg( &pcfg );

  pthread_attr_t attr;
  pthread_attr_init( &attr );
  pthread_attr_setstacksize( &attr, 8192 );
  pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );
  int ret = pthread_create( &timer->thread, &attr, port_timer_task, timer );
  pthread_attr_destroy( &attr );
  return ret;
}

MinitorTimer port_timer_create( int ms, bool repeat, void* timer_p, void* function )
{
  int ret;
  MinitorTimer timer = malloc( sizeof( port_timer_t ) );

  timer->ms          = ms;
  timer->repeat      = repeat;
  timer->function    = function;
  timer->data        = timer_p;
  timer->quit        = false;
  timer->generation  = 0;
  timer->thread_done = false;
  pthread_mutex_init( &timer->quit_mutex, NULL );
  pthread_cond_init( &timer->quit_cond, NULL );

  ret = _timer_thread_create( timer );

  if ( ret != 0 )
  {
    pthread_mutex_destroy( &timer->quit_mutex );
    pthread_cond_destroy( &timer->quit_cond );
    free( timer );
    timer = NULL;
  }

  return timer;
}

void port_timer_set_ms( MinitorTimer timer, int ms )
{
  /* Bump generation under the lock + broadcast to wake the sleeping thread.
     The old thread detects generation != my_gen and exits autonomously.
     Reset thread_done=false before creating the new thread so port_timer_stop()
     cannot return before the new thread finishes. */
  pthread_mutex_lock( &timer->quit_mutex );
  timer->generation++;
  timer->ms          = ms;
  timer->thread_done = false;
  pthread_cond_broadcast( &timer->quit_cond );
  pthread_mutex_unlock( &timer->quit_mutex );

  _timer_thread_create( timer );
}

void port_timer_stop( MinitorTimer timer )
{
  pthread_mutex_lock( &timer->quit_mutex );
  timer->quit = true;
  timer->generation++;
  pthread_cond_broadcast( &timer->quit_cond );

  /* Wait for the current timer thread to signal thread_done.
     Cannot use pthread_join() — thread is DETACHED.
     thread_done may already be true if timer fired and exited earlier. */
  while ( !timer->thread_done )
  {
    pthread_cond_wait( &timer->quit_cond, &timer->quit_mutex );
  }
  pthread_mutex_unlock( &timer->quit_mutex );
}

MinitorQueue port_queue_create( int length, int size )
{
  int ret;
  MinitorQueue queue = malloc( sizeof( port_queue_t ) );

  queue->buffer = malloc( size * length );
  queue->capacity = length;
  queue->size = 0;
  queue->in = 0;
  queue->out = 0;
  queue->closing = false;
  queue->waiter_count = 0;

  ret = pthread_mutex_init( &( queue->mutex ), NULL );

  if ( ret != 0 )
  {
    free( queue );
    return NULL;
  }

  ret = pthread_cond_init( &( queue->cond_full ), NULL );

  if ( ret != 0 )
  {
    free( queue );
    return NULL;
  }

  ret = pthread_cond_init( &( queue->cond_empty ), NULL );

  if ( ret != 0 )
  {
    free( queue );
    return NULL;
  }

  return queue;
}

bool port_queue_enqueue( MinitorQueue queue, void** pointer )
{
  // MUTEX TAKE
  pthread_mutex_lock( &( queue->mutex ) );

  if ( queue->closing )
  {
    pthread_mutex_unlock( &( queue->mutex ) );
    return false;
  }

  while ( queue->size == queue->capacity && !queue->closing )
  {
    pthread_cond_wait( &( queue->cond_full ), &( queue->mutex ) );
  }

  if ( queue->closing )
  {
    pthread_mutex_unlock( &( queue->mutex ) );
    return false;
  }

  memcpy( &( queue->buffer[queue->in] ), pointer, sizeof( void* ) );

  queue->size++;
  queue->in++;

  queue->in %= queue->capacity;

  pthread_mutex_unlock( &( queue->mutex ) );
  // MUTEX GIVE

  pthread_cond_broadcast( &( queue->cond_empty ) );

  return true;
}

bool port_queue_dequeue( MinitorQueue queue, void** pointer )
{
  // MUTEX TAKE
  pthread_mutex_lock( &( queue->mutex ) );

  /* closing check before blocking */
  if ( queue->closing )
  {
    pthread_cond_broadcast( &( queue->cond_empty ) ); /* wake delete waiter */
    pthread_mutex_unlock( &( queue->mutex ) );
    return false;
  }

  queue->waiter_count++;
  while ( queue->size == 0 && !queue->closing )
  {
    pthread_cond_wait( &( queue->cond_empty ), &( queue->mutex ) );
  }
  queue->waiter_count--;

  if ( queue->closing )
  {
    /* signal port_queue_delete() that this waiter has exited */
    pthread_cond_broadcast( &( queue->cond_empty ) );
    pthread_mutex_unlock( &( queue->mutex ) );
    return false;
  }

  memcpy( pointer, &( queue->buffer[queue->out] ), sizeof( void* ) );

  queue->size--;
  queue->out++;

  queue->out %= queue->capacity;

  pthread_mutex_unlock( &( queue->mutex ) );
  // MUTEX GIVE

  pthread_cond_broadcast( &( queue->cond_full ) );

  return true;
}

bool port_queue_dequeue_nonblocking( MinitorQueue queue, void** pointer )
{
  int ret;

  // MUTEX TAKE
  pthread_mutex_lock( &( queue->mutex ) );

  if ( queue->size == 0 )
  {
    pthread_mutex_unlock( &( queue->mutex ) );
    // MUTEX GIVE

    return false;
  }

  memcpy( pointer, &( queue->buffer[queue->out] ), sizeof( void* ) );

  queue->size--;
  queue->out++;

  queue->out %= queue->capacity;

  pthread_mutex_unlock( &( queue->mutex ) );
  // MUTEX GIVE

  pthread_cond_broadcast( &( queue->cond_full ) );

  return true;
}

int port_messages_waiting( MinitorQueue queue )
{
  int ret;

  // MUTEX TAKE
  pthread_mutex_lock( &( queue->mutex ) );

  ret = queue->size;

  pthread_mutex_unlock( &( queue->mutex ) );
  // MUTEX GIVE

  return ret;
}

void port_queue_delete( MinitorQueue queue )
{
  /* Wake any threads blocked in dequeue/enqueue, then wait for them to exit.
     Destroying a mutex/cond while a thread is waiting on it causes
     xQueueSemaphoreTake(NULL) assert in the FreeRTOS pthread layer. */
  pthread_mutex_lock( &( queue->mutex ) );
  queue->closing = true;
  pthread_cond_broadcast( &( queue->cond_empty ) );
  pthread_cond_broadcast( &( queue->cond_full ) );
  while ( queue->waiter_count > 0 )
  {
    pthread_cond_wait( &( queue->cond_empty ), &( queue->mutex ) );
  }
  pthread_mutex_unlock( &( queue->mutex ) );

  pthread_mutex_destroy( &( queue->mutex ) );
  pthread_cond_destroy( &( queue->cond_empty ) );
  pthread_cond_destroy( &( queue->cond_full ) );
  free( queue->buffer );
  free( queue );
}

bool b_create_core_task( MinitorTask* handle )
{
  // 64KB: manages circuits + calls v_build_circuit() which does wolfSSL TLS
  // handshake inline (unlike consensus fetch which uses separate pthreads).
  // wolfSSL TLS 1.3 + NTOR key exchange + 3-hop extension needs ~32KB of stack
  // frames; doubling from 32KB eliminates stack-overflow crashes during INIT_CIRCUIT.
  return _pthread_create_with_stack( handle, v_minitor_daemon, NULL, 65536 ) == 0;
}

bool b_create_connections_task( MinitorTask* handle )
{
  // 64KB: "CONNECTIONS DAEMON: Starting handshake" → wolfSSL TLS 1.3 runs here.
  // wolfSSL + NaCl/NTOR + cert chain parsing needs ~32KB of stack frames;
  // 32KB was overflowing after the first few intro-circuit handshakes.
  return _pthread_create_with_stack( handle, v_connections_daemon, NULL, 65536 ) == 0;
}

bool b_create_poll_task( MinitorTask* handle )
{
  // 16KB: poll loop, reads encrypted cells
  return _pthread_create_with_stack( handle, v_poll_daemon, NULL, 16384 ) == 0;
}

bool b_create_local_connection_handler( MinitorTask* handle, void* local_connection )
{
  // 16KB: proxies local SSH traffic through Tor circuit
  return _pthread_create_with_stack( handle, v_handle_local_connection,
                                     local_connection, 16384 ) == 0;
}

bool b_create_fetch_task( MinitorTask* handle, void* consensus )
{
  // 32KB: fetches consensus/descriptors via TLS from directory servers
  return _pthread_create_with_stack( handle, v_handle_relay_fetch,
                                     consensus, 32768 ) == 0;
}

bool b_create_insert_task( MinitorTask* handle, void* consensus )
{
  // 16KB: crypto + DB insert for consensus entries
  return _pthread_create_with_stack( handle, v_handle_crypto_and_insert,
                                     consensus, 16384 ) == 0;
}

void port_task_delete( MinitorTask task )
{
  if ( task == NULL )
  {
    /* pthread_cancel() is not supported on ESP32 (returns ENOSYS) and the
       calling thread would continue running after a failed cancel, then
       access already-freed queues/structs → divide-by-zero or use-after-free.
       pthread_exit() terminates the calling thread cleanly. */
    pthread_exit( NULL );
  }
  else
  {
    pthread_cancel( task );  /* best-effort: still not supported, may fail */
  }
}

int port_random()
{
  uint32_t r;
  esp_fill_random( &r, sizeof( r ) );
  return (int)( r & 0x7fffffff );
}

void port_fill_random( uint8_t* dest, int length )
{
  esp_fill_random( dest, (size_t)length );
  {
    int i = length; /* suppress unused-variable warning on old path */
    (void)i;
  }
}
