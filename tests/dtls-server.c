
/* This is needed for apple */
#define __APPLE_USE_RFC_3542

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>

#include "tinydtls.h" 
#include "dtls.h" 
#include "debug.h" 

#define DEFAULT_PORT 20220

static const unsigned char ecdsa_priv_key[] = {
			0xD9, 0xE2, 0x70, 0x7A, 0x72, 0xDA, 0x6A, 0x05,
			0x04, 0x99, 0x5C, 0x86, 0xED, 0xDB, 0xE3, 0xEF,
			0xC7, 0xF1, 0xCD, 0x74, 0x83, 0x8F, 0x75, 0x70,
			0xC8, 0x07, 0x2D, 0x0A, 0x76, 0x26, 0x1B, 0xD4};

static const unsigned char ecdsa_pub_key_x[] = {
			0xD0, 0x55, 0xEE, 0x14, 0x08, 0x4D, 0x6E, 0x06,
			0x15, 0x59, 0x9D, 0xB5, 0x83, 0x91, 0x3E, 0x4A,
			0x3E, 0x45, 0x26, 0xA2, 0x70, 0x4D, 0x61, 0xF2,
			0x7A, 0x4C, 0xCF, 0xBA, 0x97, 0x58, 0xEF, 0x9A};

static const unsigned char ecdsa_pub_key_y[] = {
			0xB4, 0x18, 0xB6, 0x4A, 0xFE, 0x80, 0x30, 0xDA,
			0x1D, 0xDC, 0xF4, 0xF4, 0x2E, 0x2F, 0x26, 0x31,
			0xD0, 0x43, 0xB1, 0xFB, 0x03, 0xE2, 0x2F, 0x4D,
			0x17, 0xDE, 0x43, 0xF9, 0xF9, 0xAD, 0xEE, 0x70};

#if 0
/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  dsrv_stop(dsrv_get_context());
}
#endif

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {

  struct keymap_t 
  {
    unsigned char *id;
    size_t id_length;
    unsigned char *key;
    size_t key_length;
  } psk[3] = {
	    { (unsigned char *)"Client_identity", 15,
	      (unsigned char *)"secretPSK", 9 },
	      
	    { (unsigned char *)"default identity", 16,
	      (unsigned char *)"\x11\x22\x33", 3 },
	      
	    { (unsigned char *)"\0", 2,
	      (unsigned char *)"", 1 }
	  };

  if (type != DTLS_PSK_KEY) {
    return 0;
  }

  if (id) 
  {
    int i;
    for (i = 0; i < sizeof(psk)/sizeof(struct keymap_t); i++) 
	{
	      if (id_len == psk[i].id_length && memcmp(id, psk[i].id, id_len) == 0) 
		  {
				if (result_length < psk[i].key_length) 
				{
				  dtls_warn("buffer too small for PSK");
				  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
				}
				
				memcpy(result, psk[i].key, psk[i].key_length);
				return psk[i].key_length;
	      }
	}
  }

  return dtls_alert_fatal_create(DTLS_ALERT_DECRYPT_ERROR);
}

#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };

  *result = &ecdsa_key;
  return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}
#endif /* DTLS_ECC */

#define DTLS_SERVER_CMD_CLOSE "server:close"
#define DTLS_SERVER_CMD_RENEGOTIATE "server:renegotiate"

/*
check_server_hello(dtls_context_t *ctx, 
		      dtls_peer_t *peer,
		      uint8 *data, size_t data_length)
		     //按照server_hello的报文格式，移动指针，依次解读对应部分
		     //(ctx,peer,data,data_length)
{
  dtls_handshake_parameters_t *handshake = peer->handshake_params;

   This function is called when we expect a ServerHello (i.e. we
   * have sent a ClientHello).  We might instead receive a HelloVerify
   * request containing a cookie. If so, we must repeat the
   * ClientHello with the given Cookie.
   
  if (data_length < DTLS_HS_LENGTH + DTLS_HS_LENGTH)
    return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
  update_hs_hash(peer, data, data_length);

   FIXME: check data_length before accessing fields 

   Get the server's random data and store selected cipher suite
   * and compression method (like dtls_update_parameters().

   * Then calculate master secret and wait for ServerHelloDone. When received,
   * send ClientKeyExchange (?) and ChangeCipherSpec + ClientFinished. 
  
   check server version 
  data += DTLS_HS_LENGTH;
  data_length -= DTLS_HS_LENGTH;

  
  
  if (dtls_uint16_to_int(data) != DTLS_VERSION) {
    dtls_alert("unknown DTLS version\n");
    return dtls_alert_fatal_create(DTLS_ALERT_PROTOCOL_VERSION);
  }
  data += sizeof(uint16);	       skip version field 
  data_length -= sizeof(uint16);	//指针往前移动，来读取每个部分
  

   store server random data 
  memcpy(handshake->tmp.random.server, data, DTLS_RANDOM_LENGTH);
   skip server random 
  data += DTLS_RANDOM_LENGTH;
  data_length -= DTLS_RANDOM_LENGTH;

  SKIP_VAR_FIELD(data, data_length, uint8);  skip session id 

	
   Check cipher suite. As we offer all we have, it is sufficient
   * to check if the cipher suite selected by the server is in our
   * list of known cipher suites. Subsets are not supported. 

   
  handshake->cipher = dtls_uint16_to_int(data);

  
  if (!known_cipher(ctx, handshake->cipher, 1)) {
    dtls_alert("unsupported cipher 0x%02x 0x%02x\n",
	     data[0], data[1]);
    return dtls_alert_fatal_create(DTLS_ALERT_INSUFFICIENT_SECURITY);
  }
  data += sizeof(uint16);
  data_length -= sizeof(uint16);



   Check if NULL compression was selected. We do not know any other. 
  if (dtls_uint8_to_int(data) != TLS_COMPRESSION_NULL) {
    dtls_alert("unsupported compression method 0x%02x\n", data[0]);
    return dtls_alert_fatal_create(DTLS_ALERT_INSUFFICIENT_SECURITY);
  }
  data += sizeof(uint8);
  data_length -= sizeof(uint8);

//这个时候data指针已经移动到了server_hello报文中被选择的压缩方式尾部
//如果有附加部分，则在附加部分的开始地方,data_length表示附加部分的长度
  return dtls_check_tls_extension(peer, data, data_length, 0);

error:
  return dtls_alert_fatal_create(DTLS_ALERT_DECODE_ERROR);
}





typedef struct __attribute__((__packed__))
{
    uint24 payload_length;
    uint24 app_seq;
    uint24 app_ack;
    uint24 frag_offset;
    uint24 frag_length;
}dtls_app_header_t;
*/
    
static int read_from_peer(struct dtls_context_t *ctx, 
               session_t *session, uint8 *data, size_t len) 
{
  printf("in d_server.c, read_from_peer len=%d\n",len);

  int rec_payload_length,rec_app_seq,rec_app_ack,rec_frag_offset,rec_frag_length;
  size_t i;
  uint8 *start=data;

    rec_payload_length=dtls_uint24_to_int(data);
    data+=sizeof(uint24);

    rec_app_seq=dtls_uint24_to_int(data);
    data+=sizeof(uint24);

    rec_app_ack=dtls_uint24_to_int(data);
    data+=sizeof(uint24);

    rec_frag_offset=dtls_uint24_to_int(data);
    data+=sizeof(uint24);

    rec_frag_length=dtls_uint24_to_int(data);
    data+=sizeof(uint24);

    printf("rec_payload_length=%d \n",rec_payload_length);
    printf("rec_app_seq=%d\n",rec_app_seq);
    if(ctx->peers->send_app_ack>0)
        printf("rec_app_ack=%d\n",rec_app_ack);
    printf("rec_frag_offset=%d\n",rec_frag_offset);
    printf("rec_frag_length=%d\n",rec_frag_length);

    int flag_in_order=0;

    if(ctx->peers->send_app_ack<0)
    {   
        flag_in_order=1;
        printf("\nthis is the first received packet,send_app_ack=%d\n\n",ctx->peers->send_app_ack);
    }
    else if(rec_app_seq==ctx->peers->send_app_ack)
    {
        flag_in_order=1;
        printf("\nthe received packet is in order\n");
        printf("the last send_app_ack=%d,now rec_app_seq=%d\n\n",ctx->peers->send_app_ack,rec_app_seq);
    }
    else if(rec_app_seq<ctx->peers->send_app_ack)
    {
        printf("the received packet has already been recevied\n");
        printf("the last send_app_ack=%d,now rec_app_seq=%d\n\n",ctx->peers->send_app_ack,rec_app_seq);
    }
    else if(rec_app_seq>ctx->peers->send_app_ack)
    {
        printf("lost some packets in the middle\n");
        printf("the last send_app_ack=%d,now rec_app_seq=%d\n\n",ctx->peers->send_app_ack,rec_app_seq);
    }


    if(ctx->peers->send_app_ack>0 )
    {
        printf("before seq=%d,the data has been received by client\n",rec_app_ack);
        if(rec_app_ack==ctx->peers->send_app_seq)
        {
            printf("all of the data server sended has been received by client\n");
            printf("next send_app_seq=%d ,now rec_app_ack=%d\n\n",ctx->peers->send_app_seq,rec_app_ack);
        }
        else if(rec_app_ack<ctx->peers->send_app_seq)
        {
            printf("some data lost,between %d and %d \n\n",rec_app_ack,ctx->peers->send_app_seq);
        }
    }

    
    //     printf("before add,send_ack=%d\n",ctx->peers->send_app_ack);
    if(flag_in_order==1)//所接收的包为按序到达
    {
        ctx->peers->send_app_ack=rec_app_seq+len-15;
    }
    else
    {
        //因为基于累积确认，所以send_app_ack保持不变
    }
      printf("after add,send_ack=%d\n",ctx->peers->send_app_ack);
      
    
/*
  printf("the whole received app data:\n");
  for (i = 0; i < len; i++)
    printf("%#02x ", start[i]);
*/


  
  if (len >= strlen(DTLS_SERVER_CMD_CLOSE) &&
      !memcmp(data, DTLS_SERVER_CMD_CLOSE, strlen(DTLS_SERVER_CMD_CLOSE))) 
  {
    printf("server: closing connection\n");
    dtls_close(ctx, session);
    return len;
  } 
  else if (len >= strlen(DTLS_SERVER_CMD_RENEGOTIATE) &&
      !memcmp(data, DTLS_SERVER_CMD_RENEGOTIATE, strlen(DTLS_SERVER_CMD_RENEGOTIATE))) {
    printf("server: renegotiate connection\n");
    dtls_renegotiate(ctx, session);
    return len;
  }
  
  printf("\n\n\n");

  return dtls_write(ctx, session, data+15, len-15);
}

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) {

  int fd = *(int *)dtls_get_app_data(ctx);
   // printf("in server send_to_peer() ,call sendto()\n");
  int res=sendto(fd, data, len, MSG_DONTWAIT,
		&session->addr.sa, session->size);
    printf("UDP: sendto()=%d\n",res);
    return res;
}

static int
dtls_handle_read(struct dtls_context_t *ctx) {
  int *fd;
  session_t session;
  static uint8 buf[DTLS_MAX_BUF];
  int len;

  fd = dtls_get_app_data(ctx);

  assert(fd);

  memset(&session, 0, sizeof(session_t));
  session.size = sizeof(session.addr);//此时session为0

//调用UDP的recvfrom接口接收字节，存储进buf,并且session保存有对方(此处为client)的地址  
  len = recvfrom(*fd, buf, sizeof(buf), MSG_TRUNC,&session.addr.sa, &session.size);



  if (len < 0) {
    perror("recvfrom");
    return -1;
  } 
  else {
    dtls_debug("got %d bytes from port %d\n", len, ntohs(session.addr.sin6.sin6_port));

	if (sizeof(buf) < len) {
      dtls_warn("packet was truncated (%d bytes lost)\n", len - sizeof(buf));
    }
  }

  return dtls_handle_message(ctx, &session, buf, len);
}    

static int
resolve_address(const char *server, struct sockaddr *dst) {
  //resolve_address(optarg, (struct sockaddr *)&listen_addr
  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;

  memset(addrstr, 0, sizeof(addrstr));
  if (server && strlen(server) > 0)
    memcpy(addrstr, server, strlen(server));
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, "", &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) 
	{
    case AF_INET6:

      memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
      return ainfo->ai_addrlen;
    default:
      ;
    }
  }

  freeaddrinfo(res);
  return -1;
}

static void
usage(const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf(stderr, "%s v%s -- DTLS server implementation\n"
	  "(c) 2011-2014 Olaf Bergmann <bergmann@tzi.org>\n\n"
	  "usage: %s [-A address] [-p port] [-v num]\n"
	  "\t-A address\t\tlisten on specified address (default is ::)\n"
	  "\t-p port\t\tlisten on specified port (default is %d)\n"
	  "\t-v num\t\tverbosity level (default: 3)\n",
	   program, version, program, DEFAULT_PORT);
}

static dtls_handler_t cb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .event = NULL,
#ifdef DTLS_PSK
  .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  .get_ecdsa_key = get_ecdsa_key,
  .verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
};

int 
main(int argc, char **argv) {
  dtls_context_t *the_context = NULL;
  log_t log_level = DTLS_LOG_WARN;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd, opt, result;
  int on = 1;
  
  struct sockaddr_in6 listen_addr;
  memset(&listen_addr, 0, sizeof(struct sockaddr_in6));
  /* fill extra field for 4.4BSD-based systems (see RFC 3493, section 3.4) */
#if defined(SIN6_LEN) || defined(HAVE_SOCKADDR_IN6_SIN6_LEN)
  listen_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
  listen_addr.sin6_family = AF_INET6;
  listen_addr.sin6_port = htons(DEFAULT_PORT);
  listen_addr.sin6_addr = in6addr_any;


  while ((opt = getopt(argc, argv, "A:p:v:")) != -1) 
  {
    switch (opt) 
	{
	    case 'A' :
	      if (resolve_address(optarg, (struct sockaddr *)&listen_addr) < 0) 
		  {
			fprintf(stderr, "cannot resolve address\n");
			exit(-1);
	      }
	      break;
	    case 'p' :
	      listen_addr.sin6_port = htons(atoi(optarg));
	      break;
	    case 'v' :
	      log_level = strtol(optarg, NULL, 10);
	      break;
	    default:
	      usage(argv[0], dtls_package_version());
	      exit(1);
    }
  }

  dtls_set_log_level(log_level);

  /* init socket and set it to non-blocking */
  fd = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);

  if (fd < 0) {
    dtls_alert("socket: %s\n", strerror(errno));
    return 0;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    dtls_alert("setsockopt SO_REUSEADDR: %s\n", strerror(errno));
  }
#if 0
  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    dtls_alert("fcntl: %s\n", strerror(errno));
    goto error;
  }
#endif
  on = 1;


#ifdef IPV6_RECVPKTINFO
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) 
  {
#else /* IPV6_RECVPKTINFO */
		  if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) 
		  {
#endif /* IPV6_RECVPKTINFO */

		    dtls_alert("setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
		  }

	  if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
	    dtls_alert("bind: %s\n", strerror(errno));
	    goto error;
	  }



	  dtls_init();

	  the_context = dtls_new_context(&fd);

	  dtls_set_handler(the_context, &cb);//ctx->h = h

	//前面应该都是准备工作，在这里开始和client通信

	  while (1) 
	  {
	    FD_ZERO(&rfds);
	    FD_ZERO(&wfds);

	    FD_SET(fd, &rfds);
	    /* FD_SET(fd, &wfds); */
	    
	    timeout.tv_sec = 5;
	    timeout.tv_usec = 0;
	    
	    result = select( fd+1, &rfds, &wfds, 0, &timeout);
	    
	    if (result < 0) 
		{		/* error */
		      if (errno != EINTR)
			perror("select");
	    } 
		else if (result == 0) 
		{	/* timeout */
	    } 
		else //result>0
		{			/* ok */
	      if (FD_ISSET(fd, &wfds))
			;

		  
	      else if (FD_ISSET(fd, &rfds)) 
		  {
			dtls_handle_read(the_context);
	      }
	    }
	  }
	  
	 error:
	  dtls_free_context(the_context);
	  exit(0);
}
