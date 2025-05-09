#include "sig.h"
#include "readwrite.h"
#include "stralloc.h"
#include "substdio.h"
#include "alloc.h"
#include "auto_qmail.h"
#include "control.h"
#include "received.h"
#include "constmap.h"
#include "error.h"
#include "ipme.h"
#include "ip.h"
#include "qmail.h"
#include "str.h"
#include "fmt.h"
#include "scan.h"
#include "byte.h"
#include "case.h"
#include "env.h"
#include "now.h"
#include "exit.h"
#include "fork.h"
#include "wait.h"
#include "rcpthosts.h"
#include "slurpclose.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "commands.h"
#include "wait.h"
#include "fd.h"
#include "base64.h"

#define AUTHSLEEP 5

#define MAXHOPS 100
unsigned int databytes = 0;
int timeout = 1200;

#ifdef TLS
#include <sys/stat.h>
#include "tls.h"
#include "ssl_timeoutio.h"

void tls_init();
int tls_verify();
void tls_nogateway();
int ssl_rfd = -1, ssl_wfd = -1; /* SSL_get_Xfd() are broken */
int forcetls = 1;
#endif

int safewrite(fd,buf,len) int fd; char *buf; int len;
{
  int r;
#ifdef TLS
  if (ssl && fd == ssl_wfd)
    r = ssl_timeoutwrite(timeout, ssl_rfd, ssl_wfd, ssl, buf, len);
  else
#endif
  r = timeoutwrite(timeout,fd,buf,len);
  if (r <= 0) _exit(1);
  return r;
}

char ssoutbuf[512];
substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

void flush() { substdio_flush(&ssout); }
void out(s) char *s; { substdio_puts(&ssout,s); }

void die_read() { _exit(1); }
void die_alarm() { out("451 timeout (#4.4.2)\r\n"); flush(); _exit(1); }
void die_nomem() { out("421 out of memory (#4.3.0)\r\n"); flush(); _exit(1); }
void die_tempfail() { out("421 temporary envelope failure (#4.3.0)\r\n"); flush(); _exit(1); }
void die_tempfail_msg(const char *s) { out("421 temporary envelope failure: "); out(s); out(" (#4.3.0)\r\n"); flush(); _exit(1); }
void die_fork() { out("421 Unable to fork (#4.3.0)\r\n"); flush(); _exit(1); }
void die_exec() { out("421 Unable to exec (#4.3.0)\r\n"); flush(); _exit(1); }
void die_childcrashed() { out("421 Aack, child crashed. (#4.3.0)\r\n"); flush(); _exit(1); }
void die_control() { out("421 unable to read controls (#4.3.0)\r\n"); flush(); _exit(1); }
void die_ipme() { out("421 unable to figure out my IP addresses (#4.3.0)\r\n"); flush(); _exit(1); }
void die_cdb() { out("421 unable to read cdb user database (#4.3.0)\r\n"); flush(); _exit(1); }
void die_sys() { out("421 unable to read system user database (#4.3.0)\r\n"); flush(); _exit(1); }
void die_check() { out("421 unable to create pipe (#4.3.0)\r\n"); flush(); _exit(1); }
void straynewline() { out("451 See http://pobox.com/~djb/docs/smtplf.html.\r\n"); flush(); _exit(1); }

void err_size() { out("552 sorry, that message size exceeds my databytes limit (#5.3.4)\r\n"); }
void err_permfail() { out("553 permanent envelope failure (#5.7.1)\r\n"); flush(); _exit(1); }
void err_permfail_msg(const char *s) { out("553 permanent envelope failure: "); out(s); out(" (#5.7.1)\r\n"); flush(); _exit(1); }
void err_bmf() { out("553 sorry, your envelope sender is in my badmailfrom list (#5.7.1)\r\n"); }
#ifndef TLS
void err_nogateway() { out("553 sorry, that domain isn't in my list of allowed rcpthosts (#5.7.1)\r\n"); }
#else
void err_nogateway()
{
  out("553 sorry, that domain isn't in my list of allowed rcpthosts");
  tls_nogateway();
  out(" (#5.7.1)\r\n");
}
#endif
void err_unimpl(arg) char *arg; { out("502 unimplemented (#5.5.1)\r\n"); }
void err_syntax() { out("555 syntax error (#5.5.4)\r\n"); }
void err_wantmail() { out("503 MAIL first (#5.5.1)\r\n"); }
void err_wantrcpt() { out("503 RCPT first (#5.5.1)\r\n"); }
void err_noop(arg) char *arg; { out("250 ok\r\n"); }
void err_vrfy(arg) char *arg; { out("252 send some mail, i'll try my best\r\n"); }
void err_qqt() { out("451 qqt failure (#4.3.0)\r\n"); }

extern void realrcptto_init();
extern void realrcptto_start();
extern int realrcptto();
extern int realrcptto_deny();

int err_child() { out("454 oops, problem with child and I can't auth (#4.3.0)\r\n"); return -1; }
int err_fork() { out("454 oops, child won't start and I can't auth (#4.3.0)\r\n"); return -1; }
int err_pipe() { out("454 oops, unable to open pipe and I can't auth (#4.3.0)\r\n"); return -1; }
int err_write() { out("454 oops, unable to write pipe and I can't auth (#4.3.0)\r\n"); return -1; }
void err_authd() { out("503 you're already authenticated (#5.5.0)\r\n"); }
void err_authmail() { out("503 no auth during mail transaction (#5.5.0)\r\n"); }
int err_noauth() { out("504 auth type unimplemented (#5.5.1)\r\n"); return -1; }
int err_authabrt() { out("501 auth exchange canceled (#5.0.0)\r\n"); return -1; }
int err_input() { out("501 malformed auth input (#5.5.4)\r\n"); return -1; }
void err_authfail() { out("535 authentication failed (#5.7.1)\r\n"); }
void err_submission() { out("530 Authorization required (#5.7.1) \r\n"); }

stralloc greeting = {0};

void smtp_greet(code) char *code;
{
  substdio_puts(&ssout,code);
  substdio_put(&ssout,greeting.s,greeting.len);
}
void smtp_help(arg) char *arg;
{
  out("214 netqmail home page: http://qmail.org/netqmail\r\n");
}
void smtp_quit(arg) char *arg;
{
  smtp_greet("221 "); out("\r\n"); flush(); _exit(0);
}

char *protocol;
char *remoteip;
char *remotehost;
char *remoteinfo;
char *local;
char *localport;
char *relayclient;
char *auth;

stralloc helohost = {0};
char *fakehelo; /* pointer into helohost, or 0 */

void dohelo(arg) char *arg; {
  if (!stralloc_copys(&helohost,arg)) die_nomem(); 
  if (!stralloc_0(&helohost)) die_nomem(); 
  if (!env_put2("SMTPHELO", helohost.s)) die_nomem();
  fakehelo = case_diffs(remotehost,helohost.s) ? helohost.s : 0;
}

int smtpauth = 0;
int liphostok = 0;
stralloc liphost = {0};
int bmfok = 0;
stralloc bmf = {0};
struct constmap mapbmf;

void setup()
{
  char *x;
  unsigned long u;
 
  if (control_init() == -1) die_control();
  if (control_rldef(&greeting,"control/smtpgreeting",1,(char *) 0) != 1)
    die_control();
  liphostok = control_rldef(&liphost,"control/localiphost",1,(char *) 0);
  if (liphostok == -1) die_control();
  if (control_readint(&timeout,"control/timeoutsmtpd") == -1) die_control();
  if (timeout <= 0) timeout = 1;
  if (rcpthosts_init() == -1) die_control();

  bmfok = control_readfile(&bmf,"control/badmailfrom",0);
  if (bmfok == -1) die_control();
  if (bmfok)
    if (!constmap_init(&mapbmf,bmf.s,bmf.len,0)) die_nomem();

  realrcptto_init();
 
  if (control_readint(&databytes,"control/databytes") == -1) die_control();
  x = env_get("DATABYTES");
  if (x) { scan_ulong(x,&u); databytes = u; }
  if (!(databytes + 1)) --databytes;
 
  protocol = "SMTP";
  remoteip = env_get("TCPREMOTEIP");
  if (!remoteip) remoteip = "unknown";
  local = env_get("TCPLOCALHOST");
  if (!local) local = env_get("TCPLOCALIP");
  if (!local) local = "unknown";
  localport = env_get("TCPLOCALPORT");
  if (!localport) localport = "0";
  remotehost = env_get("TCPREMOTEHOST");
  if (!remotehost) remotehost = "unknown";
  remoteinfo = env_get("TCPREMOTEINFO");
  relayclient = env_get("RELAYCLIENT");

  auth = env_get("SMTPAUTH");
  if (auth) {
    smtpauth = 1;
    case_lowers(auth);
    if (!case_diffs(auth,"-")) smtpauth = 0;
    if (!case_diffs(auth,"!")) smtpauth = 11;
    if (case_starts(auth,"cram")) smtpauth = 2;
    if (case_starts(auth,"+cram")) smtpauth = 3;
    if (case_starts(auth,"!cram")) smtpauth = 12;
    if (case_starts(auth,"!+cram")) smtpauth = 13;
  }
#ifdef TLS
  x = env_get("FORCETLS");
  if (x && !str_diff(x, "0")) forcetls = 0;
  if (env_get("SMTPS")) { smtps = 1; tls_init(); }
  else
#endif
  dohelo(remotehost);
}

stralloc addr = {0}; /* will be 0-terminated, if addrparse returns 1 */

int addrparse(arg)
char *arg;
{
  int i;
  char ch;
  char terminator;
  struct ip_address ip;
  int flagesc;
  int flagquoted;
 
  terminator = '>';
  i = str_chr(arg,'<');
  if (arg[i])
    arg += i + 1;
  else { /* partner should go read rfc 821 */
    terminator = ' ';
    arg += str_chr(arg,':');
    if (*arg == ':') ++arg;
    while (*arg == ' ') ++arg;
  }

  /* strip source route */
  if (*arg == '@') while (*arg) if (*arg++ == ':') break;

  if (!stralloc_copys(&addr,"")) die_nomem();
  flagesc = 0;
  flagquoted = 0;
  for (i = 0;ch = arg[i];++i) { /* copy arg to addr, stripping quotes */
    if (flagesc) {
      if (!stralloc_append(&addr,&ch)) die_nomem();
      flagesc = 0;
    }
    else {
      if (!flagquoted && (ch == terminator)) break;
      switch(ch) {
        case '\\': flagesc = 1; break;
        case '"': flagquoted = !flagquoted; break;
        default: if (!stralloc_append(&addr,&ch)) die_nomem();
      }
    }
  }
  /* could check for termination failure here, but why bother? */
  if (!stralloc_append(&addr,"")) die_nomem();

  if (liphostok) {
    i = byte_rchr(addr.s,addr.len,'@');
    if (i < addr.len) /* if not, partner should go read rfc 821 */
      if (addr.s[i + 1] == '[')
        if (!addr.s[i + 1 + ip_scanbracket(addr.s + i + 1,&ip)])
          if (ipme_is(&ip)) {
            addr.len = i + 1;
            if (!stralloc_cat(&addr,&liphost)) die_nomem();
            if (!stralloc_0(&addr)) die_nomem();
          }
  }

  if (addr.len > 900) return 0;
  return 1;
}

int bmfcheck()
{
  int j;
  if (!bmfok) return 0;
  if (constmap(&mapbmf,addr.s,addr.len - 1)) return 1;
  j = byte_rchr(addr.s,addr.len,'@');
  if (j < addr.len)
    if (constmap(&mapbmf,addr.s + j,addr.len - j - 1)) return 1;
  return 0;
}

int addrallowed()
{
  int r;
  r = rcpthosts(addr.s,str_len(addr.s));
  if (r == -1) die_control();
#ifdef TLS
  if (r == 0) if (tls_verify()) r = -2;
#endif
  return r;
}

char *auth;
int seenauth = 0;
int seenmail = 0;
int flagbarf; /* defined if seenmail */
int flagsize;
stralloc mailfrom = {0};
stralloc rcptto = {0};
stralloc fuser = {0};
stralloc mfparms = {0};

int mailfrom_size(arg) char *arg;
{
  long r;
  unsigned long sizebytes = 0;

  scan_ulong(arg,&r);
  sizebytes = r;
  if (databytes) if (sizebytes > databytes) return 1;
  return 0;
}

void mailfrom_auth(arg,len) 
char *arg; 
int len;
{
  if (!stralloc_copys(&fuser,"")) die_nomem();
  if (case_starts(arg,"<>")) { if (!stralloc_cats(&fuser,"unknown")) die_nomem(); }
  else 
    while (len) {
      if (*arg == '+') {
        if (case_starts(arg,"+3D")) { arg=arg+2; len=len-2; if (!stralloc_cats(&fuser,"=")) die_nomem(); }
        if (case_starts(arg,"+2B")) { arg=arg+2; len=len-2; if (!stralloc_cats(&fuser,"+")) die_nomem(); }
      }
      else
        if (!stralloc_catb(&fuser,arg,1)) die_nomem();
      arg++; len--;
    }
  if(!stralloc_0(&fuser)) die_nomem();
  if (!remoteinfo) {
    remoteinfo = fuser.s;
    if (!env_unset("TCPREMOTEINFO")) die_read();
    if (!env_put2("TCPREMOTEINFO",remoteinfo)) die_nomem();
  }
}

void mailfrom_parms(arg) char *arg;
{
  int i;
  int len;

    len = str_len(arg);
    if (!stralloc_copys(&mfparms,"")) die_nomem();
    i = byte_chr(arg,len,'>');
    if (i > 4 && i < len) {
      while (len) {
        arg++; len--; 
        if (*arg == ' ' || *arg == '\0' ) {
           if (case_starts(mfparms.s,"SIZE=")) if (mailfrom_size(mfparms.s+5)) { flagsize = 1; return; }
           if (case_starts(mfparms.s,"AUTH=")) mailfrom_auth(mfparms.s+5,mfparms.len-5);  
           if (!stralloc_copys(&mfparms,"")) die_nomem();
        }
        else
          if (!stralloc_catb(&mfparms,arg,1)) die_nomem(); 
      }
    }
}

void checkenv()
{
  int pi[2];
  int child;
  int wstat;
  stralloc chkmsg = {0};
  char *checkenvarg[] = { "bin/qmail-checkenv", mailfrom.s, addr.s, 0 };

  if (pipe(pi) == -1) die_check();
  switch(child = fork())
  {
    case -1:
      die_fork();
    case 0:
      close(pi[0]);
      if(dup2(pi[1], 3) == -1) die_check();
      sig_pipedefault();
      execv(*checkenvarg,checkenvarg);
      die_exec();
  }
  close(pi[1]);

  if (!stralloc_ready(&chkmsg,0)) die_nomem();
  chkmsg.len = 0;
  if (pi[0] != -1 && slurpclose(pi[0], &chkmsg, 256) == -1) die_nomem();
  if (chkmsg.len > 0) {
    if (!stralloc_0(&chkmsg)) die_nomem();
  }

  wait_pid(&wstat,child);
  if (wait_crashed(wstat))
    die_childcrashed();
  if (wait_exitcode(wstat) == 0) return;
  if (wait_exitcode(wstat) == 100) {
    if (chkmsg.len > 0) err_permfail_msg(chkmsg.s);
    err_permfail();
  }
  if (chkmsg.len > 0) die_tempfail_msg(chkmsg.s);
  die_tempfail();
}

void smtp_helo(arg) char *arg;
{
  smtp_greet("250 "); out("\r\n");
  seenmail = 0; dohelo(arg);
}
/* ESMTP extensions are published here */
void smtp_ehlo(arg) char *arg;
{
#ifdef TLS
  struct stat st;
#endif
  smtp_greet("250-");
#ifdef TLS
  if (!ssl && (stat("control/servercert.pem",&st) == 0))
    out("\r\n250-STARTTLS");
#endif
  out("\r\n250-PIPELINING\r\n250-8BITMIME\r\n");
#ifdef TLS
  if (!forcetls || ssl) {
#endif
  if (smtpauth == 1 || smtpauth == 11) out("250-AUTH LOGIN PLAIN\r\n");
  if (smtpauth == 2 || smtpauth == 12) out("250-AUTH CRAM-MD5\r\n");
  if (smtpauth == 3 || smtpauth == 13) out("250-AUTH LOGIN PLAIN CRAM-MD5\r\n");
#ifdef TLS
  }
#endif
  char size[FMT_ULONG];
  size[fmt_ulong(size,(unsigned int) databytes)] = 0;
  out("250 SIZE "); out(size); out("\r\n");
  seenmail = 0; dohelo(arg);
}
void smtp_rset(arg) char *arg;
{
  seenmail = 0; seenauth = 0; 
  mailfrom.len = 0; rcptto.len = 0;
  out("250 flushed\r\n");
}
void smtp_mail(arg) char *arg;
{
  if (smtpauth)
    if (smtpauth > 10 && !seenauth) { err_submission(); return; }
  if (!addrparse(arg)) { err_syntax(); return; }
  flagsize = 0;
  mailfrom_parms(arg);
  if (flagsize) { err_size(); return; }
  flagbarf = bmfcheck();
  seenmail = 1;
  if (!stralloc_copys(&rcptto,"")) die_nomem();
  if (!stralloc_copys(&mailfrom,addr.s)) die_nomem();
  if (!stralloc_0(&mailfrom)) die_nomem();
  realrcptto_start();
  out("250 ok\r\n");
}
void smtp_rcpt(arg) char *arg; {
  if (!seenmail) { err_wantmail(); return; }
  if (!addrparse(arg)) { err_syntax(); return; }
  if (flagbarf) { err_bmf(); return; }
  if (relayclient) {
    --addr.len;
    if (!stralloc_cats(&addr,relayclient)) die_nomem();
    if (!stralloc_0(&addr)) die_nomem();
  }
  else
    if (!addrallowed()) { err_nogateway(); return; }
  if (!realrcptto(addr.s)) {
    out("550 sorry, no mailbox here by that name. (#5.1.1)\r\n");
    return;
  }
  if (!stralloc_cats(&rcptto,"T")) die_nomem();
  if (!stralloc_cats(&rcptto,addr.s)) die_nomem();
  if (!stralloc_0(&rcptto)) die_nomem();
  if (env_get("CHECKENV")) checkenv();
  out("250 ok\r\n");
}


int saferead(fd,buf,len) int fd; char *buf; int len;
{
  int r;
  flush();
#ifdef TLS
  if (ssl && fd == ssl_rfd)
    r = ssl_timeoutread(timeout, ssl_rfd, ssl_wfd, ssl, buf, len);
  else
#endif
  r = timeoutread(timeout,fd,buf,len);
  if (r == -1) if (errno == error_timeout) die_alarm();
  if (r <= 0) die_read();
  return r;
}

char ssinbuf[1024];
substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);
#ifdef TLS
void flush_io() { ssin.p = 0; flush(); }
#endif

struct qmail qqt;
unsigned int bytestooverflow = 0;

void put(ch)
char *ch;
{
  if (bytestooverflow)
    if (!--bytestooverflow)
      qmail_fail(&qqt);
  qmail_put(&qqt,ch,1);
}

void blast(hops)
int *hops;
{
  char ch;
  int state;
  int flaginheader;
  int pos; /* number of bytes since most recent \n, if fih */
  int flagmaybex; /* 1 if this line might match RECEIVED, if fih */
  int flagmaybey; /* 1 if this line might match \r\n, if fih */
  int flagmaybez; /* 1 if this line might match DELIVERED, if fih */
 
  state = 1;
  *hops = 0;
  flaginheader = 1;
  pos = 0; flagmaybex = flagmaybey = flagmaybez = 1;
  for (;;) {
    substdio_get(&ssin,&ch,1);
    if (flaginheader) {
      if (pos < 9) {
        if (ch != "delivered"[pos]) if (ch != "DELIVERED"[pos]) flagmaybez = 0;
        if (flagmaybez) if (pos == 8) ++*hops;
        if (pos < 8)
          if (ch != "received"[pos]) if (ch != "RECEIVED"[pos]) flagmaybex = 0;
        if (flagmaybex) if (pos == 7) ++*hops;
        if (pos < 2) if (ch != "\r\n"[pos]) flagmaybey = 0;
        if (flagmaybey) if (pos == 1) flaginheader = 0;
	++pos;
      }
      if (ch == '\n') { pos = 0; flagmaybex = flagmaybey = flagmaybez = 1; }
    }
    switch(state) {
      case 0:
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 4; continue; }
        break;
      case 1: /* \r\n */
        if (ch == '\n') straynewline();
        if (ch == '.') { state = 2; continue; }
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 2: /* \r\n + . */
        if (ch == '\n') straynewline();
        if (ch == '\r') { state = 3; continue; }
        state = 0;
        break;
      case 3: /* \r\n + .\r */
        if (ch == '\n') return;
        put(".");
        put("\r");
        if (ch == '\r') { state = 4; continue; }
        state = 0;
        break;
      case 4: /* + \r */
        if (ch == '\n') { state = 1; break; }
        if (ch != '\r') { put("\r"); state = 0; }
    }
    put(&ch);
  }
}

char accept_buf[FMT_ULONG];
void acceptmessage(qp) unsigned long qp;
{
  datetime_sec when;
  when = now();
  out("250 ok ");
  accept_buf[fmt_ulong(accept_buf,(unsigned long) when)] = 0;
  out(accept_buf);
  out(" qp ");
  accept_buf[fmt_ulong(accept_buf,qp)] = 0;
  out(accept_buf);
  out("\r\n");
}

void smtp_data(arg) char *arg; {
  int hops;
  unsigned long qp;
  char *qqx;
 
  if (!seenmail) { err_wantmail(); return; }
  if (!rcptto.len) { err_wantrcpt(); return; }
  if (realrcptto_deny()) { out("554 sorry, no mailbox here by that name. (#5.1.1)\r\n"); return; }
  seenmail = 0;
  if (databytes) bytestooverflow = databytes + 1;
  if (qmail_open(&qqt) == -1) { err_qqt(); return; }
  qp = qmail_qp(&qqt);
  out("354 go ahead\r\n");
 
  received(&qqt,protocol,local,remoteip,remotehost,remoteinfo,fakehelo);
  blast(&hops);
  hops = (hops >= MAXHOPS);
  if (hops) qmail_fail(&qqt);
  qmail_from(&qqt,mailfrom.s);
  qmail_put(&qqt,rcptto.s,rcptto.len);
 
  qqx = qmail_close(&qqt);
  if (!*qqx) { acceptmessage(qp); return; }
  if (hops) { out("554 too many hops, this message is looping (#5.4.6)\r\n"); return; }
  if (databytes) if (!bytestooverflow) { err_size(); return; }
  if (*qqx == 'D') out("554 "); else out("451 ");
  out(qqx + 1);
  out("\r\n");
}

/* this file is too long ----------------------------------------- SMTP AUTH */

char unique[FMT_ULONG + FMT_ULONG + 3];
static stralloc authin = {0};   /* input from SMTP client */
static stralloc user = {0};     /* authorization user-id */
static stralloc pass = {0};     /* plain passwd or digest */
static stralloc resp = {0};     /* b64 response */
static stralloc chal = {0};     /* plain challenge */
static stralloc slop = {0};     /* b64 challenge */

char **childargs;
char ssauthbuf[512];
substdio ssauth = SUBSTDIO_FDBUF(safewrite,3,ssauthbuf,sizeof(ssauthbuf));

int authgetl(void) {
  int i;

  if (!stralloc_copys(&authin,"")) die_nomem();
  for (;;) {
    if (!stralloc_readyplus(&authin,1)) die_nomem(); /* XXX */
    i = substdio_get(&ssin,authin.s + authin.len,1);
    if (i != 1) die_read();
    if (authin.s[authin.len] == '\n') break;
    ++authin.len;
  }

  if (authin.len > 0) if (authin.s[authin.len - 1] == '\r') --authin.len;
  authin.s[authin.len] = 0;
  if (*authin.s == '*' && *(authin.s + 1) == 0) { return err_authabrt(); }
  if (authin.len == 0) { return err_input(); }
  return authin.len;
}

int authenticate(void)
{
  int child;
  int wstat;
  int pi[2];

  if (!stralloc_0(&user)) die_nomem();
  if (!stralloc_0(&pass)) die_nomem();
  if (!stralloc_0(&chal)) die_nomem();

  if (pipe(pi) == -1) return err_pipe();
  switch(child = fork()) {
    case -1:
      return err_fork();
    case 0:
      close(pi[1]);
      if(fd_copy(3,pi[0]) == -1) return err_pipe();
      sig_pipedefault();
        execvp(*childargs, childargs);
      _exit(1);
  }
  close(pi[0]);

  substdio_fdbuf(&ssauth,write,pi[1],ssauthbuf,sizeof ssauthbuf);
  if (substdio_put(&ssauth,user.s,user.len) == -1) return err_write();
  if (substdio_put(&ssauth,pass.s,pass.len) == -1) return err_write();
  if (smtpauth == 2 || smtpauth == 3 || smtpauth == 12 || smtpauth == 13)  
    if (substdio_put(&ssauth,chal.s,chal.len) == -1) return err_write();
  if (substdio_flush(&ssauth) == -1) return err_write();

  close(pi[1]);
  if (!stralloc_copys(&chal,"")) die_nomem();
  if (!stralloc_copys(&slop,"")) die_nomem();
  byte_zero(ssauthbuf,sizeof ssauthbuf);
  if (wait_pid(&wstat,child) == -1) return err_child();
  if (wait_crashed(wstat)) return err_child();
  if (wait_exitcode(wstat)) { sleep(AUTHSLEEP); return 1; } /* no */
  return 0; /* yes */
}

int auth_login(arg) char *arg;
{
  int r;

  if (*arg) {
    if (r = b64decode(arg,str_len(arg),&user) == 1) return err_input();
  }
  else {
    out("334 VXNlcm5hbWU6\r\n"); flush();       /* Username: */
    if (authgetl() < 0) return -1;
    if (r = b64decode(authin.s,authin.len,&user) == 1) return err_input();
  }
  if (r == -1) die_nomem();

  out("334 UGFzc3dvcmQ6\r\n"); flush();         /* Password: */

  if (authgetl() < 0) return -1;
  if (r = b64decode(authin.s,authin.len,&pass) == 1) return err_input();
  if (r == -1) die_nomem();

  if (!user.len || !pass.len) return err_input();
  return authenticate();
}

int auth_plain(arg) char *arg;
{
  int r, id = 0;

  if (*arg) {
    if (r = b64decode(arg,str_len(arg),&resp) == 1) return err_input();
  }
  else {
    out("334 \r\n"); flush();
    if (authgetl() < 0) return -1;
    if (r = b64decode(authin.s,authin.len,&resp) == 1) return err_input();
  }
  if (r == -1 || !stralloc_0(&resp)) die_nomem();
  while (resp.s[id]) id++;                       /* "authorize-id\0userid\0passwd\0" */

  if (resp.len > id + 1)
    if (!stralloc_copys(&user,resp.s + id + 1)) die_nomem();
  if (resp.len > id + user.len + 2)
    if (!stralloc_copys(&pass,resp.s + id + user.len + 2)) die_nomem();

  if (!user.len || !pass.len) return err_input();
  return authenticate();
}

int auth_cram()
{
  int i, r;
  char *s;

  s = unique;                                           /* generate challenge */
  s += fmt_uint(s,getpid());
  *s++ = '.';
  s += fmt_ulong(s,(unsigned long) now());
  *s++ = '@';
  *s++ = 0;
  if (!stralloc_copys(&chal,"<")) die_nomem();
  if (!stralloc_cats(&chal,unique)) die_nomem();
  if (!stralloc_cats(&chal,local)) die_nomem();
  if (!stralloc_cats(&chal,">")) die_nomem();
  if (b64encode(&chal,&slop) < 0) die_nomem();
  if (!stralloc_0(&slop)) die_nomem();

  out("334 ");                                          /* "334 base64_challenge \r\n" */
  out(slop.s);
  out("\r\n");
  flush();

  if (authgetl() < 0) return -1;                        /* got response */
  if (r = b64decode(authin.s,authin.len,&resp) == 1) return err_input();
  if (r == -1 || !stralloc_0(&resp)) die_nomem();

  i = str_rchr(resp.s,' ');
  s = resp.s + i;
  while (*s == ' ') ++s;
  resp.s[i] = 0;
  if (!stralloc_copys(&user,resp.s)) die_nomem();       /* userid */
  if (!stralloc_copys(&pass,s)) die_nomem();            /* digest */

  if (!user.len || !pass.len) return err_input();
  return authenticate();
}

struct authcmd {
  char *text;
  int (*fun)();
} authcmds[] = {
  { "login",auth_login }
, { "plain",auth_plain }
, { "cram-md5",auth_cram }
, { 0,err_noauth }
};

void smtp_auth(arg)
char *arg;
{
  int i;
  char *cmd = arg;

  if (!smtpauth || !*childargs) { out("503 auth not available (#5.3.3)\r\n"); return; }
  if (seenauth) { err_authd(); return; }
  if (seenmail) { err_authmail(); return; }

#ifdef TLS
  if (forcetls && !ssl) { out("538 auth not available without TLS (#5.3.3)\r\n"); return; }
#endif

  if (!stralloc_copys(&user,"")) die_nomem();
  if (!stralloc_copys(&pass,"")) die_nomem();
  if (!stralloc_copys(&resp,"")) die_nomem();
  if (!stralloc_copys(&chal,"")) die_nomem();

  i = str_chr(cmd,' ');
  arg = cmd + i;
  while (*arg == ' ') ++arg;
  cmd[i] = 0;

  for (i = 0;authcmds[i].text;++i)
    if (case_equals(authcmds[i].text,cmd)) break;

  switch (authcmds[i].fun(arg)) {
    case 0:
      seenauth = 1;
      protocol = "ESMTPA";
      relayclient = "";
      remoteinfo = user.s;
      if (!env_unset("TCPREMOTEINFO")) die_read();
      if (!env_put2("TCPREMOTEINFO",remoteinfo)) die_nomem();
      if (!env_put2("RELAYCLIENT",relayclient)) die_nomem();
      out("235 ok, go ahead (#2.0.0)\r\n");
      break;
    case 1:
      err_authfail(user.s,authcmds[i].text);
  }
}

#ifdef TLS
stralloc proto = {0};
int ssl_verified = 0;
const char *ssl_verify_err = 0;

void smtp_tls(char *arg)
{
  if (ssl) err_unimpl();
  else if (*arg) out("501 Syntax error (no parameters allowed) (#5.5.4)\r\n");
  else tls_init();
}

/* don't want to fail handshake if cert isn't verifiable */
int verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx) { return 1; }

void tls_nogateway()
{
  /* there may be cases when relayclient is set */
  if (!ssl || relayclient) return;
  out("; no valid cert for gatewaying");
  if (ssl_verify_err) { out(": "); out(ssl_verify_err); }
}
void tls_out(const char *s1, const char *s2)
{
  out("454 TLS "); out(s1);
  if (s2) { out(": "); out(s2); }
  out(" (#4.3.0)\r\n"); flush();
}
void tls_err(const char *s) { tls_out(s, ssl_error()); if (smtps) die_read(); }

# define CLIENTCA "control/clientca.pem"
# define CLIENTCRL "control/clientcrl.pem"
# define SERVERCERT "control/servercert.pem"
# define SERVERCERT2 "control/servercert2.pem"

int tls_verify()
{
  stralloc clients = {0};
  struct constmap mapclients;

  if (!ssl || relayclient || ssl_verified) return 0;
  ssl_verified = 1; /* don't do this twice */

  /* request client cert to see if it can be verified by one of our CAs
   * and the associated email address matches an entry in tlsclients */
  switch (control_readfile(&clients, "control/tlsclients", 0))
  {
  case 1:
    if (constmap_init(&mapclients, clients.s, clients.len, 0)) {
      /* if CLIENTCA contains all the standard root certificates, a
       * 0.9.6b client might fail with SSL_R_EXCESSIVE_MESSAGE_SIZE;
       * it is probably due to 0.9.6b supporting only 8k key exchange
       * data while the 0.9.6c release increases that limit to 100k */
      STACK_OF(X509_NAME) *sk = SSL_load_client_CA_file(CLIENTCA);
      if (sk) {
        SSL_set_client_CA_list(ssl, sk);
        SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_cb);
        break;
      }
      constmap_free(&mapclients);
    }
  case 0: alloc_free(clients.s); return 0;
  case -1: die_control();
  }

  if (ssl_timeoutrehandshake(timeout, ssl_rfd, ssl_wfd, ssl) <= 0) {
    const char *err = ssl_error_str();
    tls_out("rehandshake failed", err); die_read();
  }

  do { /* one iteration */
    X509 *peercert;
    X509_NAME *subj;
    stralloc email = {0};

    int n = SSL_get_verify_result(ssl);
    if (n != X509_V_OK)
      { ssl_verify_err = X509_verify_cert_error_string(n); break; }
    peercert = SSL_get_peer_certificate(ssl);
    if (!peercert) break;

    subj = X509_get_subject_name(peercert);
    n = X509_NAME_get_index_by_NID(subj, NID_pkcs9_emailAddress, -1);
    if (n >= 0) {
      const ASN1_STRING *s = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subj, n));
      if (s) { email.len = s->length; email.s = s->data; }
    }

    if (email.len <= 0)
      ssl_verify_err = "contains no email address";
    else if (!constmap(&mapclients, email.s, email.len))
      ssl_verify_err = "email address not in my list of tlsclients";
    else {
      /* add the cert email to the proto if it helped allow relaying */
      --proto.len;
      if (!stralloc_cats(&proto, "\n  (cert ") /* continuation line */
        || !stralloc_catb(&proto, email.s, email.len)
        || !stralloc_cats(&proto, ")")
        || !stralloc_0(&proto)) die_nomem();
      protocol = proto.s;
      relayclient = "";
      /* also inform qmail-queue */
      if (!env_put("RELAYCLIENT=")) die_nomem();
    }

    X509_free(peercert);
  } while (0);
  constmap_free(&mapclients); alloc_free(clients.s);

  /* we are not going to need this anymore: free the memory */
  SSL_set_client_CA_list(ssl, NULL);
  SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

  return relayclient ? 1 : 0;
}

int tls_proto_info(SSL *ssl, stralloc *proto)
{
    const char *tls_version;
    const SSL_CIPHER *tls_cipher;
    const char *server_pubkey_type = "unknown";
    const char *peer_pubkey_type = "unknown";
    const char *group_name = "unknown";
    int group_nid = NID_undef;

    if (ssl == NULL) { return; }
    if ((tls_version = SSL_get_version(ssl)) == NULL) { return; }
    if ((tls_cipher = SSL_get_current_cipher(ssl)) == NULL) { return; }

    /* kex group, if applicable */

    {
        group_nid = SSL_get_negotiated_group(ssl);

        if (group_nid != NID_undef) {
            group_name = OBJ_nid2sn(group_nid);
            if (group_name == NULL) group_name = "unknown";
        }
    }

    /* server cert */

    {
        X509 *server_cert = NULL;
        EVP_PKEY *server_pubkey = NULL;

        server_cert = SSL_get_certificate(ssl); /* do not free */

        if (server_cert != NULL) {
            server_pubkey = X509_get_pubkey(server_cert); /* free */

            if (server_pubkey != NULL) {
                const char *key_type_name = EVP_PKEY_get0_type_name(server_pubkey);

                if (key_type_name != NULL) {
                    if (strcmp(key_type_name, "RSA") == 0) {
                        server_pubkey_type = "RSA";
                    } else if (strcmp(key_type_name, "EC") == 0) {
                        server_pubkey_type = "ECDSA";
                    } else if (strcmp(key_type_name, "ED25519") == 0 ||
                               strcmp(key_type_name, "ED448") == 0) {
                        server_pubkey_type = "EdDSA";
                    }
                } else {
                    int base_id = EVP_PKEY_get_base_id(server_pubkey);
                    if (base_id == EVP_PKEY_RSA) {
                        server_pubkey_type = "RSA";
                    } else if (base_id == EVP_PKEY_EC) {
                        server_pubkey_type = "ECDSA";
                    } else if (base_id == EVP_PKEY_ED25519 ||
                               base_id == EVP_PKEY_ED448) {
                        server_pubkey_type = "EdDSA";
                    }
                }

                EVP_PKEY_free(server_pubkey);
            }
        }
    }

    /* mTLS? */

    {
        X509 *peer_cert = NULL;
        EVP_PKEY *pubkey = NULL;

        peer_cert = SSL_get_peer_certificate(ssl);

        if (peer_cert != NULL) {
            pubkey = X509_get_pubkey(peer_cert);

            if (pubkey != NULL) {
                const char *key_type_name = EVP_PKEY_get0_type_name(pubkey);

                if (key_type_name != NULL) {
                    if (strcmp(key_type_name, "RSA") == 0)
                        peer_pubkey_type = "RSA";
                    else if (strcmp(key_type_name, "EC") == 0)
                        peer_pubkey_type = "ECDSA";
                    else if (strcmp(key_type_name, "ED25519") == 0 ||
                             strcmp(key_type_name, "ED448") == 0)
                        peer_pubkey_type = "EdDSA";
                } else {
                    int base_id = EVP_PKEY_get_base_id(pubkey);
                    if (base_id == EVP_PKEY_RSA)
                        peer_pubkey_type = "RSA";
                    else if (base_id == EVP_PKEY_EC)
                        peer_pubkey_type = "ECDSA";
                    else if (base_id == EVP_PKEY_ED25519 ||
                             base_id == EVP_PKEY_ED448)
                        peer_pubkey_type = "EdDSA";
                }

                EVP_PKEY_free(pubkey);
            } else {
                peer_pubkey_type = "error";
            }

            X509_free(peer_cert);
        } else {
            peer_pubkey_type = "none";
        }
    }

    /* Determine Kx and Au based on TLS Version */

    if (strcmp(tls_version, "TLSv1.3") == 0) {
        /* TLS 1.3 */

        /* TLS 1.3 kex (group based) */

        const char *kex_mechanism_13 = "unknown";

        if (group_nid != NID_undef) {
            /* Map NID to Kx mechanism */

             if (group_nid == NID_ffdhe2048 ||
                 group_nid == NID_ffdhe3072 ||
                 group_nid == NID_ffdhe4096 ||
                 group_nid == NID_ffdhe6144 ||
                 group_nid == NID_ffdhe8192) {
                 kex_mechanism_13 = "DHE";
             } else {
                 kex_mechanism_13 = "ECDHE";
             }
        }

        if (!stralloc_cats(proto, "kex ")) return 0;
        if (!stralloc_cats(proto, kex_mechanism_13)) return 0;
        if (!stralloc_cats(proto, " group ")) return 0;
        if (!stralloc_cats(proto, group_name)) return 0;
        if (!stralloc_cats(proto, " auth ")) return 0;
        if (!stralloc_cats(proto, server_pubkey_type)) return 0;
        if (!stralloc_cats(proto, " peer ")) return 0;
        if (!stralloc_cats(proto, peer_pubkey_type)) return 0;
    } else if (strcmp(tls_version, "TLSv1.1") == 0 ||
               strcmp(tls_version, "TLSv1.2") == 0) {
        /* TLS 1.(1|2) */

        int kex_nid = SSL_CIPHER_get_kx_nid(tls_cipher);
        int auth_nid = SSL_CIPHER_get_auth_nid(tls_cipher);
        const char *kex_name = OBJ_nid2sn(kex_nid);
        const char *auth_name = OBJ_nid2sn(auth_nid);

        if (kex_name == NULL) kex_name = "unknown";
        if (auth_name == NULL) auth_name = "unknown";

        const char *kex_mechanism_12 = "unknown";
        const char *auth_mechanism_12 = "unknown";

        /* Map common NID short names to user-friendly Kx/Au terms */

        if (kex_nid == NID_kx_rsa) kex_mechanism_12 = "RSA";
        else if (kex_nid == NID_kx_dhe) kex_mechanism_12 = "DHE";
        else if (kex_nid == NID_kx_ecdhe) kex_mechanism_12 = "ECDHE";

        if (auth_nid == NID_auth_rsa) auth_mechanism_12 = "RSA";
        else if (auth_nid == NID_auth_ecdsa) auth_mechanism_12 = "ECDSA";
        else if (auth_nid == NID_auth_psk) auth_mechanism_12 = "PSK";
        else if (auth_nid == NID_auth_null) auth_mechanism_12 = "none";

        /* server_pubkey_type is a synonym for auth_mechanism_12 also */

        if (!stralloc_cats(proto, "kex ")) return 0;
        if (!stralloc_cats(proto, kex_mechanism_12)) return 0;
        if (!stralloc_cats(proto, " group ")) return 0;
        if (!stralloc_cats(proto, group_name)) return 0;
        if (!stralloc_cats(proto, " auth ")) return 0;
        if (!stralloc_cats(proto, auth_mechanism_12)) return 0;
        if (!stralloc_cats(proto, " peer ")) return 0;
        if (!stralloc_cats(proto, peer_pubkey_type)) return 0;
    }

    /* pre-TLS 1.1 is not handled at all */

    return 1;
}

void tls_init()
{
  SSL *myssl;
  SSL_CTX *ctx;
  const char *ciphers;
  stralloc saciphers = {0};
  X509_STORE *store;
  X509_LOOKUP *lookup;
  int servercert2 = 0;
  int session_id_context = 1; /* anything will do */

  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

  /* a new SSL context with the bare minimum of options */
  ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) { tls_err("unable to initialize ctx"); return; }

  /* renegotiation should include certificate request */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

  /* required to test TLSv1.0 and TLSv1.1 on modern OpenSSL */
  //SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
  //SSL_CTX_set_security_level(ctx, 0);

  /* server picks cipher based on its ordering not client's */
  SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

  /* never bother the application with retries if the transport is blocking */
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

  /* relevant in renegotiation */
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
  if (!SSL_CTX_set_session_id_context(ctx, (void *)&session_id_context,
                                        sizeof(session_id_context))) 
    { SSL_CTX_free(ctx); tls_err("failed to set session_id_context"); return; }

  if (!SSL_CTX_use_certificate_chain_file(ctx, SERVERCERT))
    { SSL_CTX_free(ctx); tls_err("missing certificate"); return; }
  if (!SSL_CTX_use_certificate_chain_file(ctx, SERVERCERT2))
    { /* missing optional second server cert; continuing */ }
  else
    { servercert2 = 1; }
  SSL_CTX_load_verify_locations(ctx, CLIENTCA, NULL);

  /* crl checking */
  store = SSL_CTX_get_cert_store(ctx);
  if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) &&
      (X509_load_crl_file(lookup, CLIENTCRL, X509_FILETYPE_PEM) == 1))
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
                                X509_V_FLAG_CRL_CHECK_ALL);
  
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  SSL_CTX_set_dh_auto(ctx, 1);

  /* a new SSL object, with the rest added to it directly to avoid copying */
  myssl = SSL_new(ctx);
  SSL_CTX_free(ctx);
  if (!myssl) { tls_err("unable to initialize ssl"); return; }

  /* this will also check whether public and private keys match */
  if (!SSL_use_PrivateKey_file(myssl, SERVERCERT, SSL_FILETYPE_PEM))
    { SSL_free(myssl); tls_err("no valid private key"); return; }
  if (servercert2 && !SSL_use_PrivateKey_file(myssl, SERVERCERT2, SSL_FILETYPE_PEM))
    { SSL_free(myssl); tls_err("no valid private key"); return; }

  ciphers = env_get("TLSCIPHERS");
  if (!ciphers) {
    if (control_readfile(&saciphers, "control/tlsserverciphers", 0) == -1)
      { SSL_free(myssl); die_control(); }
    if (saciphers.len) { /* convert all '\0's except the last one to ':' */
      int i;
      for (i = 0; i < saciphers.len - 1; ++i)
        if (!saciphers.s[i]) saciphers.s[i] = ':';
      ciphers = saciphers.s;
    }
  }
  if (!ciphers || !*ciphers) ciphers = "DEFAULT";
  /* TLSv1.2 and lower*/
  SSL_set_cipher_list(myssl, ciphers);
  /* TLSv1.3 and above*/
  SSL_set_ciphersuites(myssl, ciphers);
  alloc_free(saciphers.s);

  SSL_set_rfd(myssl, ssl_rfd = substdio_fileno(&ssin));
  SSL_set_wfd(myssl, ssl_wfd = substdio_fileno(&ssout));

  if (!smtps) { out("220 ready for tls\r\n"); flush(); }

  if (ssl_timeoutaccept(timeout, ssl_rfd, ssl_wfd, myssl) <= 0) {
    /* neither cleartext nor any other response here is part of a standard */
    const char *err = ssl_error_str();
    tls_out("connection failed", err); ssl_free(myssl); die_read();
  }
  ssl = myssl;

  /* populate the protocol string, used in Received */
  if (!stralloc_copys(&proto, "ESMTPS (")
    || !stralloc_cats(&proto, SSL_get_version(ssl))
    || !stralloc_cats(&proto, " encrypted; suite ")
    || !stralloc_cats(&proto, SSL_get_cipher(ssl))
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    || !stralloc_cats(&proto, " ")
    || !tls_proto_info(ssl, &proto)
#endif
    || !stralloc_cats(&proto, ")")) die_nomem();
  if (!stralloc_0(&proto)) die_nomem();
  protocol = proto.s;

  /* have to discard the pre-STARTTLS HELO/EHLO argument, if any */
  dohelo(remotehost);
}

# undef SERVERCERT
# undef CLIENTCA

#endif

struct commands smtpcommands[] = {
  { "rcpt", smtp_rcpt, 0 }
, { "mail", smtp_mail, 0 }
, { "data", smtp_data, flush }
, { "auth", smtp_auth, flush }
, { "quit", smtp_quit, flush }
, { "helo", smtp_helo, flush }
, { "ehlo", smtp_ehlo, flush }
, { "rset", smtp_rset, 0 }
, { "help", smtp_help, flush }
#ifdef TLS
, { "starttls", smtp_tls, flush_io }
#endif
, { "noop", err_noop, flush }
, { "vrfy", err_vrfy, flush }
, { 0, err_unimpl, flush }
} ;

void main(argc,argv)
int argc;
char **argv;
{
  childargs = argv + 1;
  sig_pipeignore();
  if (chdir(auto_qmail) == -1) die_control();
  setup();
  if (ipme_init() != 1) die_ipme();
  smtp_greet("220 ");
  out(" ESMTP\r\n");
  if (commands(&ssin,&smtpcommands) == 0) die_read();
  die_nomem();
}
