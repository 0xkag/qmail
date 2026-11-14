#!/bin/sh
# Drive qmail-checkpassword-t (qmail-checkpassword.o linked with QMAILHOME
# ".") against a scratch control/passwd: make test-checkpassword
# Run it as a normal user; root skips the unreadable-file case.

prog="$1"
[ -x "$prog" ] || { echo "usage: $0 /abs/path/qmail-checkpassword-t"; exit 2; }

dir=`mktemp -d` || exit 111
trap 'rm -rf "$dir"' 0
cd "$dir" || exit 111
mkdir control || exit 111

x507=`printf '%0507d' 0 | tr 0 x`

# hashes of "right", "other", "", 507 x's (sha512crypt) and "right" (yescrypt)
cat > control/passwd <<'EOF'
alice:$6$rightsalt$091MEEQ51ygFZp1CVecUesOWap12lt8uOd8bMW2dOy3O4buOEU2NYnal.LfJo64jD7wh1FIfUQgoWoyONH4am0:1:1:alice:/var/qmail:/bin/false
ALICE:$6$othersalt$eMcU/nJ8pRnR7JyhmYydf4xIZpFEZN9gbUjJ67B9PG9TZgoBq5B5mUj.2afJl1okAmT9zZv82ieToiVvvaEr50:1:1:alice:/var/qmail:/bin/false
yes:$y$j9T$yescryptsaltxxxx$35PC6A04OO099TCpwD1DftN0Q8zOOWR1N.VASktgux5:1:1::/:
twofield:$6$rightsalt$091MEEQ51ygFZp1CVecUesOWap12lt8uOd8bMW2dOy3O4buOEU2NYnal.LfJo64jD7wh1FIfUQgoWoyONH4am0
big:$6$long507$l/90ZQ.VzxTKFLXQTj9yFRjIFSODQ7ArnpDj75JqhuryevGuUHj008aEFy5diE4fgUBPySZDmGNXa.AJPwDU5/:1:1::/:
big2:$6$long507$l/90ZQ.VzxTKFLXQTj9yFRjIFSODQ7ArnpDj75JqhuryevGuUHj008aEFy5diE4fgUBPySZDmGNXa.AJPwDU5/:1:1::/:
:$6$rightsalt$091MEEQ51ygFZp1CVecUesOWap12lt8uOd8bMW2dOy3O4buOEU2NYnal.LfJo64jD7wh1FIfUQgoWoyONH4am0:1:1::/:
nopw:$6$emptysalt$TrI.h19YNad.S.Xw2WEgON9ojBrkXYcCfZrEcOEa9k/Bp5Sw4dxhsyY0KdBJ5Vt2UbEFOMolXqrfnZHc1QRM..:1:1::/:
locked:!$6$rightsalt$091MEEQ51ygFZp1CVecUesOWap12lt8uOd8bMW2dOy3O4buOEU2NYnal.LfJo64jD7wh1FIfUQgoWoyONH4am0:1:1::/:
star:*:1:1::/:
bang:!:1:1::/:
empty::1:1::/:
EOF
printf 'last:$6$rightsalt$091MEEQ51ygFZp1CVecUesOWap12lt8uOd8bMW2dOy3O4buOEU2NYnal.LfJo64jD7wh1FIfUQgoWoyONH4am0' >> control/passwd

tests=0
failed=0

# t exit output description input [program ...]: input is a printf format
t() {
  want="$1"; wantout="$2"; desc="$3"; input="$4"; shift 4
  out=`printf "$input" | "$prog" "$@" 3<&0 </dev/null 2>err`
  got=$?
  tests=`expr $tests + 1`
  if [ "$got" = "$want" ] && [ "$out" = "$wantout" ] && ! grep -q right err
  then
    echo "ok: $desc"
  else
    echo "FAIL: $desc: exit $got (want $want), output '$out' (want '$wantout')"
    cat err
    failed=`expr $failed + 1`
  fi
}

t 0 ran 'right password' 'alice\000right\000' echo ran
t 1 '' 'wrong password' 'alice\000wrong\000' echo ran
t 1 '' 'unknown name' 'nobody\000right\000' echo ran
t 0 ran 'name in upper case' 'ALICE\000right\000' echo ran
t 0 ran 'name in mixed case' 'aLiCe\000right\000' echo ran
t 1 '' 'only the first entry for a name counts' 'ALICE\000other\000' echo ran
t 0 ran 'yescrypt hash' 'yes\000right\000' echo ran
t 0 ran 'entry with two fields' 'twofield\000right\000' echo ran
t 0 ran 'last line without newline' 'last\000right\000' echo ran
t 0 ran 'trailing timestamp ignored' 'alice\000right\000123\000' echo ran
t 0 ran 'input of 512 bytes' "big\\000$x507\\000" echo ran
t 1 '' 'input of 513 bytes' "big2\\000$x507\\000" echo ran
t 2 '' 'empty input' '' echo ran
t 2 '' 'no NUL' 'alice' echo ran
t 2 '' 'no NUL after password' 'alice\000right' echo ran
t 1 '' 'empty name' '\000right\000' echo ran
t 1 '' 'empty password' 'nopw\000\000' echo ran
t 1 '' 'hash starting with !' 'locked\000right\000' echo ran
t 1 '' 'hash *' 'star\000*\000' echo ran
t 1 '' 'hash !' 'bang\000!\000' echo ran
t 1 '' 'empty hash' 'empty\000x\000' echo ran
t 2 '' 'no program to run' 'alice\000right\000'
t 111 '' 'program to run is missing' 'alice\000right\000' ./missing

mv control/passwd control/passwd.x
t 111 '' 'missing passwd file' 'alice\000right\000' echo ran
mv control/passwd.x control/passwd

chmod 0 control/passwd
if [ "`id -u`" = 0 ]
then
  echo "skip: unreadable passwd file (running as root)"
else
  t 111 '' 'unreadable passwd file' 'alice\000right\000' echo ran
fi

echo "$tests tests, $failed failed"
[ "$failed" = 0 ]
