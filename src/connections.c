/*
Copyright (C) 2022 Triple Layer Development Inc.

Minitor is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

Minitor is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
#include <unistd.h>
#include <stdlib.h>

#include "wolfssl/options.h"

#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "../h/wolfssl_internal.h"

#include "../include/config.h"
#include "../h/port.h"

#include "../h/minitor.h"
#include "../h/circuit.h"
#include "../h/cell.h"
#include "../h/encoding.h"
#include "../h/structures/onion_message.h"
#include "../h/models/relay.h"
#include "../h/connections.h"
#include "../h/consensus.h"
#include "../h/core.h"

static const char* CONN_TAG = "CONNECTIONS DAEMON";

uint32_t conn_id = 0;
MinitorTask connections_daemon_task_handle = NULL;
struct pollfd connections_poll[16];
DlConnection* connections;
MinitorMutex connections_mutex;
MinitorMutex connection_access_mutex[16];
MinitorQueue connections_task_queue;
MinitorQueue poll_task_queue;

static WC_INLINE int d_ignore_ca_callback( int preverify, WOLFSSL_X509_STORE_CTX* store )
{
  if ( store->error == ASN_NO_SIGNER_E ) {
    return SSL_SUCCESS;
  }

  MINITOR_LOG( CONN_TAG, "SSL callback error %d", store->error );

  return 0;
}

static int conn_secrects_cb( WOLFSSL* ssl, void* secret, int* secretSz, void* ctx )
{
  DlConnection* or_connection = ctx;

  memcpy( or_connection->master_secret, secret, 48 );

  return 0;
}

static void v_cleanup_connection_in_lock( DlConnection* dl_connection )
{
  int i;
  OnionMessage* onion_message;

  // we only need to inform the core daemon if an or connection
  // closed, local connections closing already triggered a
  // RELAY_END and don't need aditonal work
  if ( dl_connection->is_or == 1 )
  {
    onion_message = malloc( sizeof( OnionMessage ) );
    onion_message->type = CONN_CLOSE;
    onion_message->data = dl_connection->conn_id;

    // TODO this should work need to figure out why it breaks things
    //wolfSSL_shutdown( dl_connection->ssl );
    wolfSSL_free( dl_connection->ssl );

    for ( i = 0; i < RING_BUF_LEN; i++ )
    {
      if ( dl_connection->cell_ring_buf[i] != NULL )
      {
        free( dl_connection->cell_ring_buf[i] );
      }
    }

    if (
      dl_connection->status == CONNECTION_WANT_VERSIONS ||
      dl_connection->status == CONNECTION_WANT_CERTS ||
      dl_connection->status == CONNECTION_WANT_CHALLENGE
    )
    {
      wc_FreeRsaKey( &dl_connection->initiator_rsa_auth_key );

      /* circuit.c fail paths already free and NULL these; guard against double-free */
      if ( dl_connection->responder_rsa_identity_key_der != NULL )
      {
        free( dl_connection->responder_rsa_identity_key_der );
      }
      if ( dl_connection->initiator_rsa_identity_key_der != NULL )
      {
        free( dl_connection->initiator_rsa_identity_key_der );
      }

      wc_Sha256Free( &dl_connection->responder_sha );
      wc_Sha256Free( &dl_connection->initiator_sha );
    }

    MINITOR_ENQUEUE_BLOCKING( core_task_queue, (void*)(&onion_message) );
  }

  connections_poll[dl_connection->poll_index].fd = -1;

  shutdown( dl_connection->sock_fd, 0 );
  close( dl_connection->sock_fd );

  v_remove_connection_from_list( dl_connection, &connections );

  free( dl_connection );
}

void v_cleanup_connection( DlConnection* dl_connection )
{
  MinitorMutex access_mutex;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

  if ( b_verify_or_connection( dl_connection->conn_id ) == false )
  {
    MINITOR_MUTEX_GIVE( connections_mutex );
    // MUTEX GIVE

    return;
  }

  access_mutex = connection_access_mutex[dl_connection->mutex_index];

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( access_mutex );

  v_cleanup_connection_in_lock( dl_connection );

  MINITOR_MUTEX_GIVE( access_mutex );
  // MUTEX TAKE

  MINITOR_MUTEX_GIVE( connections_mutex );
  // MUTEX GIVE
}

static OnionMessage* px_recv_on_or_connection( DlConnection* or_connection )
{
  int succ;
  uint8_t* cell;
  OnionMessage* onion_message = NULL;
  int read_before;
  int read_after;

  if ( ( or_connection->cell_ring_end + 1 ) % RING_BUF_LEN == or_connection->cell_ring_start )
  {
    return NULL;
  }

  if ( or_connection->has_versions == false )
  {
    succ = d_recv_cell( or_connection->ssl, &cell, LEGACY_CIRCID_LEN );

    or_connection->has_versions = true;
  }
  else
  {
    succ = d_recv_cell( or_connection->ssl, &cell, CIRCID_LEN );
  }

  if ( succ <= 0 )
  {
    MINITOR_LOG( CONN_TAG, "recv fail conn_id=%d succ=%d ssl_err=%d status=%d", or_connection->conn_id, succ, wolfSSL_get_error( or_connection->ssl, succ ), or_connection->status );
    return NULL;
  }

  {
    // After d_recv_cell shifts by FIXED_CELL_OFFSET=2: circ_id at bytes 2-5, cmd at byte 6
    uint32_t dbg_circ = ( (uint32_t)(uint8_t)cell[2] << 24 ) | ( (uint32_t)(uint8_t)cell[3] << 16 ) | ( (uint32_t)(uint8_t)cell[4] << 8 ) | (uint8_t)cell[5];
    uint8_t  dbg_cmd  = cell[6];
    MINITOR_LOG( CONN_TAG, "rx cell circ_id=%x cmd=%d", dbg_circ, dbg_cmd );
  }

  or_connection->cell_ring_buf[or_connection->cell_ring_end] = cell;

  onion_message = malloc( sizeof( OnionMessage ) );
  onion_message->data = or_connection->conn_id;
  onion_message->length = succ;

  if ( or_connection->status == CONNECTION_LIVE )
  {
    onion_message->type = TOR_CELL;
  }
  else
  {
    onion_message->type = CONN_HANDSHAKE;
  }

  or_connection->cell_ring_end = ( or_connection->cell_ring_end + 1 ) % RING_BUF_LEN;

  return onion_message;
}

static OnionMessage* px_recv_on_local_connection( DlConnection* local_connection )
{
  int succ;
  OnionMessage* onion_message = NULL;

  onion_message = malloc( sizeof( OnionMessage ) );

  onion_message->type = SERVICE_TCP_DATA;
  onion_message->data = malloc( sizeof( ServiceTcpTraffic ) );
  ( (ServiceTcpTraffic*)onion_message->data )->circ_id = local_connection->circ_id;
  ( (ServiceTcpTraffic*)onion_message->data )->stream_id = local_connection->stream_id;
  ( (ServiceTcpTraffic*)onion_message->data )->data = malloc( sizeof( uint8_t ) * RELAY_PAYLOAD_LEN );

  succ = recv( local_connection->sock_fd, ( (ServiceTcpTraffic*)onion_message->data )->data, sizeof( uint8_t ) * RELAY_PAYLOAD_LEN, 0 );

  if ( succ <= 0 )
  {
    ( (ServiceTcpTraffic*)onion_message->data )->length = 0;
    free( ( (ServiceTcpTraffic*)onion_message->data )->data );
  }
  else
  {
    ( (ServiceTcpTraffic*)onion_message->data )->length = succ;
  }

  return onion_message;
}

static bool b_recv_on_connection( DlConnection* dl_connection )
{
  OnionMessage* onion_message;

  if ( dl_connection->is_or == 1 )
  {
    onion_message = px_recv_on_or_connection( dl_connection );
  }
  else
  {
    onion_message = px_recv_on_local_connection( dl_connection );
  }

  MINITOR_MUTEX_GIVE( connection_access_mutex[dl_connection->mutex_index] );
  // MUTEX GIVE

  if ( onion_message == NULL )
  {
    return false;
  }

  MINITOR_ENQUEUE_BLOCKING( core_task_queue, (void*)(&onion_message) );

  return true;
}

void v_poll_daemon( void* pv_parameters )
{
  int count;
  bool ready = true;

  while ( 1 )
  {
    /* 500ms timeout so we check for a cooperative quit signal regularly.
       pthread_cancel() is not supported on ESP32; the connections daemon
       sends false via poll_task_queue and calls pthread_join() instead. */
    count = poll( connections_poll, 16, 500 );

    /* Non-blocking check for quit signal between poll() calls */
    if ( MINITOR_DEQUEUE_NONBLOCKING( poll_task_queue, &ready ) )
    {
      if ( ready == false )
      {
        MINITOR_TASK_DELETE( NULL );
      }
    }

    if ( count > 0 )
    {
      MINITOR_ENQUEUE_BLOCKING( connections_task_queue, (void*)(&ready) );

      /* Wait for ACK from connections daemon; false ACK means quit */
      if ( !MINITOR_DEQUEUE_BLOCKING( poll_task_queue, &ready ) || ready == false )
      {
        MINITOR_TASK_DELETE( NULL );
      }
    }
  }
}

void v_connections_daemon( void* pv_parameters )
{
  int i;
  time_t now;
  int want_next;
  bool ready;
  bool read_success;
  int readable_bytes;
  uint8_t* rx_buffer;
  MinitorMutex access_mutex;
  OnionMessage* onion_message;
  DlConnection* dl_connection = NULL;
  DlConnection* tmp_connection;
  int ready_connids[16];
  bool needs_hup[16];  // true = drain then cleanup (POLLHUP)
  DlConnection* ready_connection;
  MinitorTask poll_daemon_task_handle = NULL;

  // create the poll queue and task
  poll_task_queue = MINITOR_QUEUE_CREATE( 25, sizeof( OnionMessage* ) );
  b_create_poll_task( &poll_daemon_task_handle );

  MINITOR_LOG( CONN_TAG, "made poll task" );

  while ( MINITOR_DEQUEUE_BLOCKING( connections_task_queue, &ready ) )
  {
    //MINITOR_LOG( CONN_TAG, "got message %d", ready );

    // restart the poll task to include new connections
    if ( ready == false )
    {
      // delete the poll task
      /* Cooperative shutdown: send false as ACK/quit signal so the poll
         daemon exits via MINITOR_TASK_DELETE(NULL) → pthread_exit(NULL).
         Then join the thread (max ~500ms due to poll() timeout) before
         freeing the queue.  pthread_cancel() is a no-op on ESP32. */
      {
        bool quit = false;
        MINITOR_ENQUEUE_BLOCKING( poll_task_queue, (void*)(&quit) );
        pthread_join( poll_daemon_task_handle, NULL );
      }
      MINITOR_QUEUE_DELETE( poll_task_queue );

      // create the poll queue and task
      poll_task_queue = MINITOR_QUEUE_CREATE( 25, sizeof( OnionMessage* ) );
      b_create_poll_task( &poll_daemon_task_handle );

      MINITOR_LOG( CONN_TAG, "made poll task" );

      continue;
    }

    dl_connection = NULL;

    // MUTEX TAKE
    MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

    i = 0;
    time( &now );

    dl_connection = connections;

    while ( dl_connection != NULL )
    {
      if ( dl_connection->is_or == 1 )
      {
        int revents = connections_poll[dl_connection->poll_index].revents;
        int ssl_pend = wolfSSL_pending( dl_connection->ssl );
        // On ESP32/LwIP: POLLIN=1, POLLERR=32, POLLHUP=64.
        // When relay sends data+FIN simultaneously LwIP gives POLLIN|POLLERR (33).
        // Always drain POLLIN / wolfSSL data before treating POLLERR/POLLHUP as
        // a close event; needs_hup marks that cleanup is required after the drain.
        int err_bits = ( revents & POLLERR ) | ( revents & POLLHUP );
        int has_data = ( revents & POLLIN ) || ssl_pend > 0;

        if ( has_data || err_bits )
        {
          if ( err_bits )
          {
            MINITOR_LOG( CONN_TAG, "HUP drain conn_id=%d revents=%d", dl_connection->conn_id, revents );
          }
          ready_connids[i] = dl_connection->conn_id;
          needs_hup[i]     = err_bits != 0;
          i++;
        }
      }

      dl_connection = dl_connection->next;
    }

    MINITOR_MUTEX_GIVE( connections_mutex );
    // MUTEX GIVE

    for ( i = i - 1; i >= 0; i-- )
    {
      // read until there's nothing left to read
      while ( 1 )
      {
        // MUTEX TAKE
        ready_connection = px_get_conn_by_id_and_lock( ready_connids[i] );

        if ( ready_connection == NULL )
        {
          break;
        }

        access_mutex = connection_access_mutex[ready_connection->mutex_index];

        // check if our ready connection can still be read
        if ( MINITOR_GET_READABLE( ready_connection->sock_fd, &readable_bytes ) < 0 )
        {
          MINITOR_MUTEX_GIVE( access_mutex );
          // MUTEX GIVE

          if ( needs_hup[i] )
          {
            v_cleanup_connection( ready_connection );
          }

          break;
        }

        // check pending in case it's no longer on the fd
        if ( ready_connection->is_or == 1 && ( readable_bytes < CELL_LEN && ( ready_connection->status != CONNECTION_WANT_CERTS || readable_bytes <= 0 ) ) )
        {
          readable_bytes += wolfSSL_pending( ready_connection->ssl );
        }

        // if we don't have enough bytes to read to make a cell, give up
        if (
          ( ready_connection->is_or == 0 && readable_bytes <= 0 ) ||
          ( ready_connection->is_or == 1 && ( readable_bytes < CELL_LEN && ( ready_connection->status != CONNECTION_WANT_CERTS || readable_bytes <= 0 ) ) )
        )
        {
          MINITOR_MUTEX_GIVE( access_mutex );
          // MUTEX GIVE

          // POLLHUP with nothing left to read: cleanup the connection now.
          // access_mutex was just given back above; v_cleanup_connection()
          // acquires both mutexes itself — do NOT call px_get_conn_by_id_and_lock
          // first, that would take access_mutex and cause a deadlock.
          if ( needs_hup[i] )
          {
            MINITOR_LOG( CONN_TAG, "HUP drained conn_id=%d, cleaning up", ready_connids[i] );
            v_cleanup_connection( ready_connection );
          }

          break;
        }

        // read and send to core, block if need be
        read_success = b_recv_on_connection( ready_connection );
        // MUTEX GIVE

        // if the read failed, destroy the connection
        if ( read_success == false )
        {
          v_cleanup_connection( ready_connection );

          break;
        }

        if ( ready_connection->is_or == 0 )
        {
          time( &( ready_connection->last_action ) );
        }
      }
    }

    ready = true;
    MINITOR_ENQUEUE_BLOCKING( poll_task_queue, (void*)(&ready) );
  }
}

static DlConnection* px_create_or_connection( uint32_t address, uint16_t port )
{
  int i;
  int succ;
  int sock_fd;
  bool ready;
  struct sockaddr_in dest_addr;
  WOLFSSL* ssl;
  DlConnection* or_connection;

  // connect to the relay over ssl
  dest_addr.sin_addr.s_addr = address;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( port );

  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 )
  {
    MINITOR_LOG( CONN_TAG, "Failed to create socket" );

    return NULL;
  }

  if ( connect( sock_fd, (struct sockaddr*)&dest_addr , sizeof( dest_addr ) ) != 0 )
  {
    MINITOR_LOG( CONN_TAG, "Failed to connect socket, errno: %d", errno );

    close( sock_fd );

    return NULL;
  }

  ssl = wolfSSL_new( xMinitorWolfSSL_Context );

  if ( ssl == NULL )
  {
    MINITOR_LOG( CONN_TAG, "Failed to create an ssl object, error code: %d", wolfSSL_get_error( ssl, 0 ) );

    shutdown( sock_fd, 0 );
    close( sock_fd );

    return NULL;
  }

  or_connection = malloc( sizeof( DlConnection ) );

  memset( or_connection, 0, sizeof( DlConnection ) );

  wolfSSL_set_verify( ssl, SSL_VERIFY_NONE, NULL );
  wolfSSL_KeepArrays( ssl );
  //wolfSSL_set_session_secret_cb( ssl, conn_secrects_cb, or_connection );

  succ = wolfSSL_set_fd( ssl, sock_fd );

  if ( succ != SSL_SUCCESS )
  {
    MINITOR_LOG( CONN_TAG, "Failed to set ssl fd %d", succ );

    free( or_connection );
    goto clean_ssl;
  }

  succ = wolfSSL_connect( ssl );

  if ( succ != SSL_SUCCESS )
  {
    MINITOR_LOG( CONN_TAG, "Failed to wolfSSL_connect %d", wolfSSL_get_error( ssl, succ ) );

    free( or_connection );
    goto clean_ssl;
  }

  MINITOR_LOG( CONN_TAG, "Starting handshake" );

  or_connection->address = address;
  or_connection->port = port;
  or_connection->ssl = ssl;
  or_connection->sock_fd = sock_fd;
  or_connection->is_or = 1;
  or_connection->conn_id = conn_id++;

  if ( d_start_v3_handshake( or_connection ) < 0 )
  {
    MINITOR_LOG( CONN_TAG, "Failed to handshake with first relay" );

    goto clean_connection;
  }

  or_connection->status = CONNECTION_WANT_VERSIONS;

  // Do the link protocol synchronously so this connection is CONNECTION_LIVE
  // before we return. Without this, the daemon blocks in px_create_or_connection
  // for the next circuit while CONN_HANDSHAKE cells from this guard pile up
  // unprocessed — the relay times out and closes before we ever respond.
  {
    Cell* lc = NULL;
    int lc_len;

    lc_len = d_recv_cell( or_connection->ssl, (uint8_t**)&lc, LEGACY_CIRCID_LEN );
    or_connection->has_versions = true;
    if ( lc_len <= 0 || ((CellShortVariable*)lc)->command != VERSIONS )
    {
      if ( lc != NULL ) { free( lc ); }
      MINITOR_LOG( CONN_TAG, "sync link: VERSIONS fail" );
      goto clean_link_proto;
    }
    v_process_versions( or_connection, (CellShortVariable*)lc, lc_len );
    free( lc ); lc = NULL;
    or_connection->status = CONNECTION_WANT_CERTS;

    lc_len = d_recv_cell( or_connection->ssl, (uint8_t**)&lc, CIRCID_LEN );
    if ( lc_len <= 0 || ((CellVariable*)lc)->command != CERTS || d_process_certs( or_connection, (CellVariable*)lc, lc_len ) < 0 )
    {
      if ( lc != NULL ) { free( lc ); }
      MINITOR_LOG( CONN_TAG, "sync link: CERTS fail" );
      goto clean_link_proto;
    }
    free( lc ); lc = NULL;
    or_connection->status = CONNECTION_WANT_CHALLENGE;

    lc_len = d_recv_cell( or_connection->ssl, (uint8_t**)&lc, CIRCID_LEN );
    if ( lc_len <= 0 || ((CellVariable*)lc)->command != AUTH_CHALLENGE )
    {
      if ( lc != NULL ) { free( lc ); }
      MINITOR_LOG( CONN_TAG, "sync link: AUTH_CHALLENGE fail" );
      goto clean_link_proto;
    }
    free( lc ); lc = NULL;
    // We are a client (hidden service), not a relay — skip AUTHENTICATE.
    // Free the RSA auth material that d_start_v3_handshake allocated.
    wc_FreeRsaKey( &or_connection->initiator_rsa_auth_key );
    if ( or_connection->responder_rsa_identity_key_der != NULL ) { free( or_connection->responder_rsa_identity_key_der ); or_connection->responder_rsa_identity_key_der = NULL; }
    if ( or_connection->initiator_rsa_identity_key_der != NULL ) { free( or_connection->initiator_rsa_identity_key_der ); or_connection->initiator_rsa_identity_key_der = NULL; }
    wc_Sha256Free( &or_connection->responder_sha );
    wc_Sha256Free( &or_connection->initiator_sha );
    // wolfSSL arrays (master_secret etc.) no longer needed after link setup
    wolfSSL_FreeArrays( or_connection->ssl );
    or_connection->status = CONNECTION_WANT_NETINFO;

    lc_len = d_recv_cell( or_connection->ssl, (uint8_t**)&lc, CIRCID_LEN );
    if ( lc_len <= 0 || ((Cell*)lc)->command != NETINFO || d_process_netinfo( or_connection, lc ) < 0 )
    {
      if ( lc != NULL ) { free( lc ); }
      MINITOR_LOG( CONN_TAG, "sync link: NETINFO fail" );
      goto clean_connection; // RSA already freed in skip-AUTHENTICATE block
    }
    free( lc ); lc = NULL;
    or_connection->status = CONNECTION_LIVE;

    MINITOR_LOG( CONN_TAG, "sync link OK conn_id=%d", or_connection->conn_id );
  }

  v_add_connection_to_list( or_connection, &connections );

  if ( connections_daemon_task_handle == NULL )
  {
    for ( i = 0; i < 16; i++ )
    {
      connections_poll[i].fd = -1;
      connection_access_mutex[i] = MINITOR_MUTEX_CREATE();
    }
  }

  for ( i = 0; i < 16; i++ )
  {
    if ( connections_poll[i].fd == -1 )
    {
      or_connection->poll_index = i;
      or_connection->mutex_index = i;
      connections_poll[i].fd = sock_fd;
      connections_poll[i].events = POLLIN;

      break;
    }
  }

  if ( i >= 16 )
  {
    MINITOR_LOG( CONN_TAG, "couldn't find an open poll spot" );

    goto clean_connection;
  }

  if ( connections_daemon_task_handle == NULL )
  {
    b_create_connections_task( &connections_daemon_task_handle );
  }
  // need to reset poll now that a connection has been added
  else
  {
    ready = false;

    MINITOR_ENQUEUE_BLOCKING( connections_task_queue, (void*)(&ready) );
  }

  return or_connection;

clean_link_proto:
  // RSA keys and SHA contexts were allocated by d_start_v3_handshake.
  // Free them for any failure before WANT_NETINFO (at which point we have
  // already freed them explicitly in the skip-AUTHENTICATE block above).
  if ( or_connection->status == CONNECTION_WANT_VERSIONS ||
       or_connection->status == CONNECTION_WANT_CERTS    ||
       or_connection->status == CONNECTION_WANT_CHALLENGE )
  {
    wc_FreeRsaKey( &or_connection->initiator_rsa_auth_key );
    if ( or_connection->responder_rsa_identity_key_der != NULL ) { free( or_connection->responder_rsa_identity_key_der ); or_connection->responder_rsa_identity_key_der = NULL; }
    if ( or_connection->initiator_rsa_identity_key_der != NULL ) { free( or_connection->initiator_rsa_identity_key_der ); or_connection->initiator_rsa_identity_key_der = NULL; }
    wc_Sha256Free( &or_connection->responder_sha );
    wc_Sha256Free( &or_connection->initiator_sha );
  }
clean_connection:
  free( or_connection );
clean_ssl:
  wolfSSL_shutdown( ssl );
  wolfSSL_free( ssl );
  shutdown( sock_fd, 0 );
  close( sock_fd );

  return NULL;
}

int d_attach_or_connection( uint32_t address, uint16_t port, OnionCircuit* circuit )
{
  int i;
  DlConnection* dl_connection;
  DlConnection* live_guard = NULL;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

  dl_connection = connections;

  while ( dl_connection != NULL )
  {
    if ( dl_connection->is_or == 1 && dl_connection->address == address && dl_connection->port == port )
    {
      break;
    }

    // Entry-guard model: track any live OR connection as potential guard reuse.
    if ( dl_connection->is_or == 1 && dl_connection->status == CONNECTION_LIVE && live_guard == NULL )
    {
      live_guard = dl_connection;
    }

    dl_connection = dl_connection->next;
  }

  if ( dl_connection == NULL )
  {
    if ( live_guard != NULL )
    {
      // Reuse existing guard connection. Update circuit's head relay to use
      // the guard's identity/ntor_key so CREATE2 targets the right relay.
      MINITOR_LOG( CONN_TAG, "guard reuse conn_id=%d for circ=%x", live_guard->conn_id, circuit->circ_id );
      circuit->relay_list.head->relay->address  = live_guard->address;
      circuit->relay_list.head->relay->or_port  = live_guard->port;
      memcpy( circuit->relay_list.head->relay->identity,      live_guard->guard_identity, 20 );
      memcpy( circuit->relay_list.head->relay->ntor_onion_key, live_guard->guard_ntor_key, 32 );
      dl_connection = live_guard;
    }
    else
    {
      dl_connection = px_create_or_connection( address, port );

      if ( dl_connection == NULL )
      {
        MINITOR_MUTEX_GIVE( connections_mutex );
        // MUTEX GIVE

        return -1;
      }

      // Store the relay keys for future circuits reusing this guard connection.
      memcpy( dl_connection->guard_identity,  circuit->relay_list.head->relay->identity,      20 );
      memcpy( dl_connection->guard_ntor_key,  circuit->relay_list.head->relay->ntor_onion_key, 32 );
    }
  }

  circuit->conn_id = dl_connection->conn_id;

  MINITOR_MUTEX_GIVE( connections_mutex );
  // MUTEX GIVE

  if ( dl_connection->status == CONNECTION_LIVE )
  {
    return 1;
  }

  return 0;
}

void v_handle_local_connection( void* pv_parameters )
{
  int len;
  uint8_t data_buf[RELAY_PAYLOAD_LEN];
  DlConnection* local_connection = pv_parameters;
  OnionMessage* onion_message;

  while ( 1 )
  {
    onion_message = px_recv_on_local_connection( local_connection );

    if ( onion_message == NULL )
    {
      MINITOR_TASK_DELETE( NULL );
    }

    MINITOR_ENQUEUE_BLOCKING( core_task_queue, (void*)(&onion_message) );

    if ( ( (ServiceTcpTraffic*)onion_message->data )->length == 0 )
    {
      MINITOR_TASK_DELETE( NULL );
    }
  }
}

int d_create_local_connection( uint32_t circ_id, uint16_t stream_id, uint16_t port )
{
  int i;
  int succ;
  bool ready;
  int sock_fd;
  struct sockaddr_in dest_addr;
  DlConnection* local_connection;
  MinitorTask* dummy_handle;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

  // set the address of the directory server
  dest_addr.sin_addr.s_addr = inet_addr( "127.0.0.1" );
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons( port );

  sock_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

  if ( sock_fd < 0 )
  {
    MINITOR_LOG( CONN_TAG, "couldn't create a socket to the local port, err: %d, errno: %d", sock_fd, errno );

    goto fail;
  }

  succ = connect( sock_fd, (struct sockaddr*) &dest_addr, sizeof( dest_addr ) );

  if ( succ != 0 )
  {
    MINITOR_LOG( CONN_TAG, "couldn't connect to the local port" );

    goto clean_socket;
  }

  local_connection = malloc( sizeof( DlConnection ) );

  memset( local_connection, 0, sizeof( DlConnection ) );

  local_connection->circ_id = circ_id;
  local_connection->stream_id = stream_id;
  local_connection->sock_fd = sock_fd;
  local_connection->is_or = 0;
  // set last action to uint max so it isn't killed before it can read (no one should be killed before they can read)
  local_connection->last_action = INT_MAX;
  local_connection->conn_id = conn_id++;

  v_add_connection_to_list( local_connection, &connections );

  b_create_local_connection_handler( &dummy_handle, local_connection );

  MINITOR_MUTEX_GIVE( connections_mutex );
  // MUTEX GIVE

  return 0;

clean_socket:
  shutdown( sock_fd, 0 );
  close( sock_fd );
fail:
  MINITOR_MUTEX_GIVE( connections_mutex );
  // MUTEX GIVE

  return -1;
}

int d_forward_to_local_connection( uint32_t circ_id, uint32_t stream_id, uint8_t* data, uint32_t length )
{
  int ret = 0;
  DlConnection* local_connection;

  local_connection = connections;

  while ( local_connection != NULL )
  {
    if ( local_connection->is_or == 0 && local_connection->circ_id == circ_id && local_connection->stream_id == stream_id )
    {
      ret = send( local_connection->sock_fd, data, length, 0 );

      break;
    }

    local_connection = local_connection->next;
  }

  if ( local_connection == NULL )
  {
    ret = -1;
  }

  return ret;
}

void v_cleanup_local_connection( uint32_t circ_id, uint32_t stream_id )
{
  DlConnection* local_connection;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

  local_connection = connections;

  while ( local_connection != NULL )
  {
    if ( local_connection->is_or == 0 && local_connection->circ_id == circ_id && local_connection->stream_id == stream_id )
    {
      v_cleanup_connection_in_lock( local_connection );
      break;
    }

    local_connection = local_connection->next;
  }

  MINITOR_MUTEX_GIVE( connections_mutex );
  // MUTEX GIVE
}

void v_cleanup_local_connections_by_circ_id( uint32_t circ_id )
{
  DlConnection* local_connection;
  DlConnection* tmp_connection;

  local_connection = connections;

  while ( local_connection != NULL )
  {
    if ( local_connection->is_or == 0 && local_connection->circ_id == circ_id )
    {
      tmp_connection = local_connection->next;
      v_cleanup_connection_in_lock( local_connection );
      local_connection = tmp_connection;
    }
    else
    {
      local_connection = local_connection->next;
    }
  }
}

bool b_verify_or_connection( uint32_t id )
{
  bool ret = false;
  DlConnection* in_list;

  in_list = connections;

  while ( in_list != NULL )
  {
    if ( in_list->is_or == 1 && in_list->conn_id == id )
    {
      ret = true;
      break;
    }

    in_list = in_list->next;
  }

  return ret;
}

void v_dettach_connection( DlConnection* dl_connection )
{
  OnionCircuit* check_circuit;
  MinitorMutex access_mutex;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( circuits_mutex );

  check_circuit = onion_circuits;

  while ( check_circuit != NULL )
  {
    if ( check_circuit->conn_id == dl_connection->conn_id )
    {
      break;
    }

    check_circuit = check_circuit->next;
  }

  MINITOR_MUTEX_GIVE( circuits_mutex );
  // MUTEX GIVE

  if ( check_circuit == NULL )
  {
    v_cleanup_connection( dl_connection );
  }
}

// caller must give the access semaphore
DlConnection* px_get_conn_by_id_and_lock( uint32_t id )
{
  DlConnection* dl_connection;

  // MUTEX TAKE
  MINITOR_MUTEX_TAKE_BLOCKING( connections_mutex );

  dl_connection = connections;

  while ( dl_connection != NULL )
  {
    if ( dl_connection->conn_id == id )
    {
      // MUTEX TAKE
      MINITOR_MUTEX_TAKE_BLOCKING( connection_access_mutex[dl_connection->mutex_index] );

      break;
    }

    dl_connection = dl_connection->next;
  }

  MINITOR_MUTEX_GIVE( connections_mutex );
  // MUTEX GIVE

  return dl_connection;
}
