#include "tinydtls.h" 

/* This is needed for apple */
#define __APPLE_USE_RFC_3542

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "global.h" 
#include "debug.h" 
#include "dtls.h" 

#define DEFAULT_PORT 20220

#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"
#define PSK_OPTIONS          "i:k:"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__((unused))
#else
#define UNUSED_PARAM
#endif /* __GNUC__ */

static char buf[10000];
static size_t len = 0;

typedef struct {
  size_t length;               /* length of string */
  unsigned char *s;            /* string data */
} dtls_str;

static dtls_str output_file = { 0, NULL }; /* output file name */

static dtls_context_t *dtls_context = NULL;


static const unsigned char ecdsa_priv_key[] = {
			0x41, 0xC1, 0xCB, 0x6B, 0x51, 0x24, 0x7A, 0x14,
			0x43, 0x21, 0x43, 0x5B, 0x7A, 0x80, 0xE7, 0x14,
			0x89, 0x6A, 0x33, 0xBB, 0xAD, 0x72, 0x94, 0xCA,
			0x40, 0x14, 0x55, 0xA1, 0x94, 0xA9, 0x49, 0xFA};

static const unsigned char ecdsa_pub_key_x[] = {
			0x36, 0xDF, 0xE2, 0xC6, 0xF9, 0xF2, 0xED, 0x29,
			0xDA, 0x0A, 0x9A, 0x8F, 0x62, 0x68, 0x4E, 0x91,
			0x63, 0x75, 0xBA, 0x10, 0x30, 0x0C, 0x28, 0xC5,
			0xE4, 0x7C, 0xFB, 0xF2, 0x5F, 0xA5, 0x8F, 0x52};

static const unsigned char ecdsa_pub_key_y[] = {
			0x71, 0xA0, 0xD4, 0xFC, 0xDE, 0x1A, 0xB8, 0x78,
			0x5A, 0x3C, 0x78, 0x69, 0x35, 0xA7, 0xCF, 0xAB,
			0xE9, 0x3F, 0x98, 0x72, 0x09, 0xDA, 0xED, 0x0B,
			0x4F, 0xAB, 0xC3, 0x6F, 0xC7, 0x72, 0xF8, 0x29};

#ifdef DTLS_PSK
ssize_t
read_from_file(char *arg, unsigned char *buf, size_t max_buf_len) {
  FILE *f;
  ssize_t result = 0;

  f = fopen(arg, "r");
  if (f == NULL)
    return -1;

  while (!feof(f)) 
  {
	    size_t bytes_read;
	    bytes_read = fread(buf, 1, max_buf_len, f);
	    if (ferror(f)) {
	      result = -1;
	      break;
	    }

	    buf += bytes_read;
	    result += bytes_read;
	    max_buf_len -= bytes_read;
  }

  fclose(f);
  return result;//返回的是读取的字节数目
}

/* The PSK information for DTLS */
#define PSK_ID_MAXLEN 256
#define PSK_MAXLEN 256
static unsigned char psk_id[PSK_ID_MAXLEN];
static size_t psk_id_length = 0;
static unsigned char psk_key[PSK_MAXLEN];
static size_t psk_key_length = 0;


/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx UNUSED_PARAM,
	    const session_t *session UNUSED_PARAM,
	    dtls_credentials_type_t type,
	    const unsigned char *id, size_t id_len,
	    unsigned char *result, size_t result_length) 
/*
typedef enum dtls_credentials_type_t {
  DTLS_PSK_HINT, DTLS_PSK_IDENTITY, DTLS_PSK_KEY
} dtls_credentials_type_t;

/test/d-client.c:
len = CALL(ctx, get_psk_info, &peer->session, 
				DTLS_PSK_IDENTITY,
				  handshake->keyx.psk.identity, handshake->keyx.psk.id_length,
				  buf + sizeof(uint16),
				  min(sizeof(buf) - sizeof(uint16),
				  sizeof(handshake->keyx.psk.identity)));


calculate_key_block:
len = CALL(ctx, get_psk_info, session, 
			   DTLS_PSK_KEY, //type
			  handshake->keyx.psk.identity,//id
			  handshake->keyx.psk.id_length,//id_len
			  psk, DTLS_PSK_MAX_KEY_LEN);//result,result_len


*/
{

  switch (type) 
  {
	  case DTLS_PSK_IDENTITY:
		    if (id_len) {
		      dtls_debug("got psk_identity_hint: '%.*s'\n", id_len, id);
		    }

		    if (result_length < psk_id_length) {
		      dtls_warn("cannot set psk_identity -- buffer too small\n");
		      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
		    }
			
		    memcpy(result, psk_id, psk_id_length);
		    return psk_id_length;
			
	  case DTLS_PSK_KEY:
		    if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {
		      dtls_warn("PSK for unknown id requested, exiting\n");
		      return dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);
		    }

/*if (id_len != psk_id_length || memcmp(psk_id, id, id_len) != 0) {      
dtls_warn("PSK for unknown id requested, exiting\n");      return 
dtls_alert_fatal_create(DTLS_ALERT_ILLEGAL_PARAMETER);    }*/
            
			else if (result_length < psk_key_length) {
		      dtls_warn("cannot set psk -- buffer too small\n");
		      return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
		    }
			
		    memcpy(result, psk_key, psk_key_length);
		    return psk_key_length;
	  default:
	    dtls_warn("unsupported request type: %d\n", type);
  }
  return dtls_alert_fatal_create(DTLS_ALERT_INTERNAL_ERROR);
}
#endif /* DTLS_PSK */


//CALL(ctx, get_ecdsa_key, &peer->session, &ecdsa_key);
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
		 size_t key_size) 
{
  return 0;
}
#endif /* DTLS_ECC */

static int //发送应用数据，本质依然是用dtls_send_multi
try_send(struct dtls_context_t *ctx, session_t *dst) {
  //printf("before d_write(),len=%d\n",len);
  int res= dtls_write(ctx, dst, (uint8 *)buf, len);
  printf("in try_send(), dtls_write()=%d\n",res);

  if (res >= 0) 
  {
    len+=15;// pkl
    // len本身为应用数据载荷，在后面加了25字节的头部，dtls_write的返回值res为已经
    //发送了的字节数，所以要把len+25
   // printf("now len=%d res=%d\n",len,res);
    memmove(buf, buf + res, len - res);
    len -= res;
   // printf("len-=res len=%d\n",len);
  }
 // printf("in try_send() now return res\n");
  return res;
}

static void 
handle_stdin() {
   // printf("in d_client handle_stdin(),before fgets(),len=%d\n",len);
  if (fgets(buf + len, sizeof(buf) - len, stdin))
    len += strlen(buf + len); //buf为首地址，len为长度
 // printf(" after fgets len=%d   buf=%s\n",len,buf);


   // buf="hello pkl";
}

//client
static int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8 *data, size_t len) 

/*read_from_peer(struct dtls_context_t *ctx, 
               dtls_peer_t *peer, uint8 *data, size_t len) 
*/

{
   

	printf("in d_client.c, read_from_peer() len=%d:\n",len);
 //   printf("role=%d  send_seq=%d\n",ctx->peers->role,ctx->peers->send_app_seq);

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

    //int flag=1;//not the first packet
    if(ctx->peers->send_app_ack<0)
    {
        printf("\nthis is the first received packet\n\n");
        
    }
    else if(rec_app_seq==ctx->peers->send_app_ack)
    {
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

   
    printf("before seq=%d,the data has been received by client\n",rec_app_ack);
    if(rec_app_ack==ctx->peers->send_app_seq)
    {
        printf("all of the data client sended has been received by server\n");
        printf("next send_app_seq=%d ,now rec_app_ack=%d\n\n",ctx->peers->send_app_seq,rec_app_ack);
    }
    else if(rec_app_ack<ctx->peers->send_app_seq)
    {
        printf("some data lost,between %d and %d \n\n",rec_app_ack,ctx->peers->send_app_seq);
    }
    


   //   printf("before add,send_ack=%d\n",ctx->peers->send_app_ack);
      ctx->peers->send_app_ack=rec_app_seq+len-15;
      printf("after add,send_ack=%d\n",ctx->peers->send_app_ack);
      
  /*
    printf("the whole received app data:\n");
    for (i = 0; i < len; i++)
      printf("%#02x ", *(start+i));
    printf("\n");
*/
  return 0;
}

static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8 *data, size_t len) //data是要传送的数据
{

  int fd = *(int *)dtls_get_app_data(ctx);//fd为socket描述符
 // printf("in client send_to_peer,call sendto()\n");
  int res=sendto(fd, data, len, MSG_DONTWAIT,&session->addr.sa, session->size);
    printf("client sendto()=%d\n",res);
    return res;
}

static int
dtls_handle_read(struct dtls_context_t *ctx) 
{
  //  printf("in client: d_handle_read()\n");
	  int fd;
	  session_t session;
#define MAX_READ_BUF 10000
	  static uint8 buf[MAX_READ_BUF];
	  int len;

	  fd = *(int *)dtls_get_app_data(ctx);
	  
	  if (!fd)
	    return -1;

	  memset(&session, 0, sizeof(session_t));
	  session.size = sizeof(session.addr);//此处session全被填充为
	  //把接收到的数据存入buf，len为接收数据的长度
	 // printf("in client d_handle_read, call recvfrom():\n");
	  len = recvfrom(fd, buf, MAX_READ_BUF, 0, &session.addr.sa, &session.size);
	//猜测此时session里已经存储有发送方的信息了

        printf("recvfrom()=%d\n",len);
	  
	  if (len < 0) {
	    perror("recvfrom");
	    return -1;
	  } 
      else {
	    dtls_dsrv_log_addr(DTLS_LOG_DEBUG, "peer", &session);
	    dtls_debug_dump("bytes from peer", buf, len);
	  }

      //  printf("in d_handle_read: call d_handle_message()\n");
	   int res=dtls_handle_message(ctx, &session, buf, len);
       // printf("d_handle_message()=%d\n",res);
        return res;
}    



static void dtls_handle_signal(int sig)
{
  dtls_free_context(dtls_context);
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}


/* stolen from libcoap: */
static int
resolve_address(const char *server, struct sockaddr *dst) 
//res = resolve_address(argv[optind++], &dst.addr.sa);
{
//声明变量
  struct addrinfo hints,*res, *ainfo;
  struct addrinfo ;
  static char addrstr[256];
  int error;
//给addrstr赋值
  memset(addrstr, 0, sizeof(addrstr));
  if (server && strlen(server) > 0)
    memcpy(addrstr, server, strlen(server));
  else
    memcpy(addrstr, "localhost", 9);
//给hints赋值
  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;
  
//调用socket函数getaddrinfo，结果存入res
  error = getaddrinfo(addrstr, "", &hints, &res);
//判断执行getaddrinfo是否出错
  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

//执行for循环，给dst赋值
  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) 
  {
    switch (ainfo->ai_family) 
	{
	    case AF_INET6:
	    case AF_INET:
		      memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
		      return ainfo->ai_addrlen;
	    default:
	      ;
    }
  }
  freeaddrinfo(res);
  return -1;
}

/*---------------------------------------------------------------------------*/
static void
usage( const char *program, const char *version) {
  const char *p;

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf(stderr, "%s v%s -- DTLS client implementation\n"
	  "(c) 2011-2014 Olaf Bergmann <bergmann@tzi.org>\n\n"
#ifdef DTLS_PSK
	  "usage: %s [-i file] [-k file] [-o file] [-p port] [-v num] addr [port]\n"
#else /*  DTLS_PSK */
	  "usage: %s [-o file] [-p port] [-v num] addr [port]\n"
#endif /* DTLS_PSK */

#ifdef DTLS_PSK
	  "\t-i file\t\tread PSK identity from file\n"
	  "\t-k file\t\tread pre-shared key from file\n"
#endif /* DTLS_PSK */
	  "\t-o file\t\toutput received data to this file (use '-' for STDOUT)\n"
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

#define DTLS_CLIENT_CMD_CLOSE "client:close"
#define DTLS_CLIENT_CMD_RENEGOTIATE "client:renegotiate"




int 
main(int argc, char **argv) {
  fd_set rfds, wfds;
  struct timeval timeout;
  unsigned short port = DEFAULT_PORT;
  char port_str[NI_MAXSERV] = "0";
  log_t log_level = DTLS_LOG_WARN;
  int fd, result;
  int on = 1;
  int opt, res;
  session_t dst;

  dtls_init();
  
  snprintf(port_str, sizeof(port_str), "%d", port);

#ifdef DTLS_PSK
  psk_id_length = strlen(PSK_DEFAULT_IDENTITY);
  psk_key_length = strlen(PSK_DEFAULT_KEY);
  memcpy(psk_id, PSK_DEFAULT_IDENTITY, psk_id_length);
  memcpy(psk_key, PSK_DEFAULT_KEY, psk_key_length);

/*
#define PSK_DEFAULT_IDENTITY "Client_identity"
#define PSK_DEFAULT_KEY      "secretPSK"
#define PSK_OPTIONS          "i:k:"
*/
  
#endif /* DTLS_PSK */

  while ((opt = getopt(argc, argv, "p:o:v:" PSK_OPTIONS)) != -1) 
  {
    switch (opt) 
	{
#ifdef DTLS_PSK
	    case 'i' : //psk_id
		{
		      ssize_t result = read_from_file(optarg, psk_id, PSK_ID_MAXLEN);
			 //read_from_file(char *arg, unsigned char *buf, size_t max_buf_len)
		      if (result < 0) 
			  {
					dtls_warn("cannot read PSK identity\n");
		      } 
			  else 
		      {
					psk_id_length = result;
		      }
		      break;
	    }
	    case 'k' :	//psk_key
		{
		      ssize_t result = read_from_file(optarg, psk_key, PSK_MAXLEN);
			
		      if (result < 0) 
			  {
					dtls_warn("cannot read PSK\n");
		      } 
			  else 
		      {
					psk_key_length = result;
		      }
		      break;
    	}
#endif /* DTLS_PSK */

		case 'p' :
	      strncpy(port_str, optarg, NI_MAXSERV-1);
	      port_str[NI_MAXSERV - 1] = '\0';
	      break;
	    case 'o' :
	      output_file.length = strlen(optarg);
	      output_file.s = (unsigned char *)malloc(output_file.length + 1);
	      
	      if (!output_file.s) 
		  {
			dtls_crit("cannot set output file: insufficient memory\n");
			exit(-1);
	      } 
		  else 
		  {  	
			/* copy filename including trailing zero */
			memcpy(output_file.s, optarg, output_file.length + 1);
	      }
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
  
  if (argc <= optind) {
    usage(argv[0], dtls_package_version());
    exit(1);
  }
  
  memset(&dst, 0, sizeof(session_t));
  
  /* resolve destination address where server should be sent */
  res = resolve_address(argv[optind++], &dst.addr.sa);

  
  if (res < 0) {
    dtls_emerg("failed to resolve address\n");
    exit(-1);
  }
  dst.size = res;

  /* use port number from command line when specified or the listen
     port, otherwise */
  dst.addr.sin.sin_port = htons(atoi(optind < argc ? argv[optind++] : port_str));


  
  /* init socket and set it to non-blocking */
  fd = socket(dst.addr.sa.sa_family, SOCK_DGRAM, 0);

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
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on) ) < 0) {
#else /* IPV6_RECVPKTINFO */
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on) ) < 0) {
#endif /* IPV6_RECVPKTINFO */
    dtls_alert("setsockopt IPV6_PKTINFO: %s\n", strerror(errno));
  }

  if (signal(SIGINT, dtls_handle_signal) == SIG_ERR) {
    dtls_alert("An error occurred while setting a signal handler.\n");
    return EXIT_FAILURE;
  }


  dtls_context = dtls_new_context(&fd);//(void * app_data)  c->app = app_data=&fd

  if (!dtls_context) {
    dtls_emerg("cannot create context\n");
    exit(-1);
  }

  dtls_set_handler(dtls_context, &cb);//ctx->h=h

//第一次，与服务器建立连接
  dtls_connect(dtls_context, &dst);//发送了client_hello



//已经发送了clientHello,所以首先会等待接收server发过来的verify或者serverHello
  while (1) 
  {
        printf("\n in new loop\n");
        
	    FD_ZERO(&rfds);
	    FD_ZERO(&wfds);

	    FD_SET(fileno(stdin), &rfds);
	    FD_SET(fd, &rfds);
	    /* FD_SET(fd, &wfds); */
	    
	    timeout.tv_sec = 150;
	    timeout.tv_usec = 0;

	    result = select(fd+1, &rfds, &wfds, 0, &timeout);
        //printf("select()=%d\n",result);
        
	    if (result < 0) 
		{		/* error */
	      	if (errno != EINTR)
			perror("select");
	    } 
		else if (result == 0) 
		{	/* timeout */
		    printf("time out\n");
	    } 
		else //if (result>0)
		{			/* ok */
            //printf("select()>0\n\n");
			if (FD_ISSET(fd, &wfds))
				/* FIXME */;
		    else if (FD_ISSET(fd, &rfds))
            {
               // printf("in d_client: call d_handle_read()\n");
                dtls_handle_read(dtls_context);
            }      		
		    else if (FD_ISSET(fileno(stdin), &rfds))
            {
               // printf("\n\n\nin d_client:call handle_stdin()\n");
                  handle_stdin();
            };      
					
			  /* 
				static void	handle_stdin() 
				{
				  if (fgets(buf + len, sizeof(buf) - len, stdin))
				    len += strlen(buf + len);
				}
*/
	    }

      //  printf("in d_client.c ,len=%d\n",len);
	    if (len) //通过比较len的不同长度做出不同选择
		{
			//close
	      if (len >= strlen(DTLS_CLIENT_CMD_CLOSE) &&
		  !memcmp(buf, DTLS_CLIENT_CMD_CLOSE, strlen(DTLS_CLIENT_CMD_CLOSE))) 
		  {
				printf("client: closing connection\n");
				dtls_close(dtls_context, &dst);
				len = 0;
	      } 
		  	//renegotiate
		  else if (len >= strlen(DTLS_CLIENT_CMD_RENEGOTIATE) &&
		         !memcmp(buf, DTLS_CLIENT_CMD_RENEGOTIATE, strlen(DTLS_CLIENT_CMD_RENEGOTIATE))) {

				printf("client: renegotiate connection\n");
				dtls_renegotiate(dtls_context, &dst);
				len = 0;
	      } 
		  	//send
		  else {
          //  printf("\n\nin d_client :call try_send\n");
        //    printf("in client, before call try_send ,len=%d\n",len);
			int res_try_send=try_send(dtls_context, &dst);//用try_send来发送具体的应用数据
            printf("in d_client.c: try_send()=%d\n",res_try_send);
          }
	    }
       // printf("the loop complete,len=%d\n",len);
  }
  
  dtls_free_context(dtls_context);
  exit(0);
}

