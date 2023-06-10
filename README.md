# he-dyn-dns
Dynamic DNS update client for dns.he.net
he-dyn-dns requires dnspython:
https://dnspython.readthedocs.io/

Requires DNS to be hosted by https://dns.he.net

Dynamic DNS setup documentation:
https://dns.he.net/docs.html

Add one more more hosts to update in hosts.cfg. EX:
  hostname=example.com,password=passwordexample,dual

Add update_he_dns.py to a cronjob to have it check and update DNS automatically
Example cron job entry, runs every 10 minutes:
  */10 * * * * /opt/he-dyn-dns/update_he_dns.py
