#include <unistd.h>
#include <crypt.h>
#include "substdio.h"
#include "stralloc.h"
#include "getln.h"
#include "open.h"
#include "strerr.h"
#include "error.h"
#include "case.h"
#include "byte.h"
#include "str.h"
#include "auto_qmail.h"

/* checkpassword interface: reads name\0password\0 on fd 3, looks the
   name up (any case, first entry wins) in QMAILHOME/control/passwd
   (name:crypt-hash[:...]), and runs argv[1...] on a match.
   exit 1: bad credentials; 2: misuse; 111: temporary failure. */

#define FATAL "qmail-checkpassword: fatal: "

/* crypt() runs for unknown or locked names too, so they take as long */
#define NOHASH "$6$qmail.checkpw$"

char up[513];

stralloc fn = {0};
stralloc line = {0};
stralloc hash = {0};

char inbuf[1024];
substdio ss;

void die(int e) { byte_zero(up,sizeof up); _exit(e); }
void die_nomem(void) { byte_zero(up,sizeof up); strerr_die2x(111,FATAL,"out of memory"); }
void die_open(void) { byte_zero(up,sizeof up); strerr_die4sys(111,FATAL,"unable to open ",fn.s,": "); }
void die_read(void) { byte_zero(up,sizeof up); strerr_die4sys(111,FATAL,"unable to read ",fn.s,": "); }

int main(int argc,char **argv)
{
  unsigned int uplen;
  char *login;
  unsigned int loginlen;
  char *password;
  char *encrypted;
  unsigned int i;
  unsigned int n;
  unsigned char diff;
  int fd;
  int r;
  int match;
  int ok;

  if (!argv[1]) _exit(2);

  uplen = 0;
  while (uplen < sizeof up) {
    do
      r = read(3,up + uplen,sizeof up - uplen);
    while ((r == -1) && (errno == error_intr));
    if (r == -1) die(111);
    if (r == 0) break;
    uplen += r;
  }
  if (uplen >= sizeof up) die(1);
  close(3);

  login = up;
  loginlen = byte_chr(up,uplen,0);
  if (loginlen == uplen) die(2);
  password = up + loginlen + 1;
  n = uplen - loginlen - 1;
  if (byte_chr(password,n,0) == n) die(2);
  if (!loginlen || !*password) die(1);

  if (!stralloc_copys(&fn,auto_qmail)) die_nomem();
  if (!stralloc_cats(&fn,"/control/passwd")) die_nomem();
  if (!stralloc_0(&fn)) die_nomem();
  fd = open_read(fn.s);
  if (fd == -1) die_open();
  substdio_fdbuf(&ss,read,fd,inbuf,sizeof inbuf);

  ok = 0;
  do {
    if (getln(&ss,&line,&match,'\n') == -1) die_read();
    if (match) --line.len;
    i = byte_chr(line.s,line.len,':');
    if ((i < line.len) && (i == loginlen) && !case_diffb(line.s,i,login)) {
      ++i;
      n = byte_chr(line.s + i,line.len - i,':');
      if (!stralloc_copyb(&hash,line.s + i,n)) die_nomem();
      if (!stralloc_0(&hash)) die_nomem();
      ok = (hash.s[0] != 0) && (hash.s[0] != '*') && (hash.s[0] != '!');
      break;
    }
  } while (match);
  close(fd);

  encrypted = crypt(password,ok ? hash.s : NOHASH);
  byte_zero(up,sizeof up);
  if (!ok || !encrypted || (*encrypted == '*')) _exit(1);

  n = str_len(encrypted);
  if (n != hash.len - 1) _exit(1);
  diff = 0;
  for (i = 0;i < n;++i) diff |= encrypted[i] ^ hash.s[i];
  if (diff) _exit(1);

  execvp(argv[1],argv + 1);
  _exit(111);
}
