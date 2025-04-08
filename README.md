Linux LAB – Running a Virtual Mail Server (Postfix, SMTP AUTH, Dovecot, MySQL, OpenSSL and Rspamd)
![image](https://github.com/user-attachments/assets/5847c222-5df2-4b18-b7cf-b247214cf023)
 

Virtual Mail System Components
● Postfix (Mail/SMTP Server, MTA)
○ STARTTLS used for encryption
○ SMTP AUTH (SASL) used for authentication
● Dovecot (IMAP/POP3 Server, MDA)
○ (SSL/TLS) used for encryption
● MySql
○ stores the domains and the virtual users
● Spam Filter (Rspamd/SpamAssassin)



1. Installing Software Packages
apt update && apt install postfix postfix-mysql postfix-doc dovecot-common dovecot-imapd dovecot-pop3d libsasl2-2 libsasl2-modules libsasl2-modules-sql sasl2-bin libpam-mysql mailutils dovecot-mysql dovecot-sieve dovecot-managesieved
![image](https://github.com/user-attachments/assets/0823e9b5-6264-4c79-92b3-49ff84ce5012)
![image](https://github.com/user-attachments/assets/8d64bc82-a6c3-40bc-9658-d4500268a52d)
![image](https://github.com/user-attachments/assets/c5566b49-5d0a-40c4-8a88-7d95b66a8664)
![image](https://github.com/user-attachments/assets/c86d8cc5-4de1-49f9-a995-da9c8c4d7ddb)
![image](https://github.com/user-attachments/assets/135c7366-7c62-415b-a243-ede04f23cb8a)
  

2. Configuring MySQL and Connect it With Postfix
mysql -u root
mysql> CREATE DATABASE mail;
mysql> USE mail;
mysql> CREATE USER 'mail_admin'@'localhost' IDENTIFIED BY 'mail_admin_password';  
mysql> GRANT SELECT, INSERT, UPDATE, DELETE ON mail.* TO 'mail_admin'@'localhost';
mysql> FLUSH PRIVILEGES;
mysql> CREATE TABLE domains (domain varchar(50) NOT NULL, PRIMARY KEY (domain));
mysql> CREATE TABLE users (email varchar(80) NOT NULL, password varchar(128) NOT NULL, PRIMARY KEY (email));
mysql> CREATE TABLE forwardings (source varchar(80) NOT NULL, destination TEXT NOT NULL, PRIMARY KEY (source));
mysql> exit
![image](https://github.com/user-attachments/assets/6ab60481-354b-4054-8279-6e4c01a14e4a)
 

3. Configuring Postfix to communicate with MySql
a) vim /etc/postfix/mysql_virtual_domains.cf 
user = mail_admin
password = mail_admin_password
dbname = mail
query = SELECT domain FROM domains WHERE domain='%s'
hosts = 127.0.0.1
![image](https://github.com/user-attachments/assets/e6481816-8c5b-44c7-b0cf-9c915cac3946)
 

b) vim /etc/postfix/mysql_virtual_forwardings.cf
user = mail_admin
password = mail_admin_password
dbname = mail
query = SELECT destination FROM forwardings WHERE source='%s'
hosts = 127.0.0.1
![image](https://github.com/user-attachments/assets/7b3f478c-286c-4b67-8615-e6e1e4da96d7)
 

c) vim /etc/postfix/mysql_virtual_mailboxes.cf
user = mail_admin
password = mail_admin_password
dbname = mail
query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM users WHERE email='%s'
hosts = 127.0.0.1
![image](https://github.com/user-attachments/assets/9e5ce4ee-af37-4a6e-8902-11c1cee59079)
 

d) vim /etc/postfix/mysql_virtual_email2email.cf 
user = mail_admin
password = mail_admin_password
dbname = mail
query = SELECT email FROM users WHERE email='%s'
hosts = 127.0.0.1
![image](https://github.com/user-attachments/assets/9d6005dd-e581-4b6d-a7d7-b7690c4ac407)
 
e) Setting the ownership and permissions
chmod o-rwx /etc/postfix/mysql_virtual_*
chown root.postfix /etc/postfix/mysql_virtual_*
![image](https://github.com/user-attachments/assets/133bee33-8f20-4d18-bbcd-aad0ba700871)
![image](https://github.com/user-attachments/assets/dca58a86-6f5e-43bc-b0db-164e3570dbea)
 
 


4. Creating a user and group for mail handling
groupadd -g 5000 vmail
useradd -g vmail -u 5000 -d /var/vmail -m vmail
![image](https://github.com/user-attachments/assets/7b43514f-c471-406f-928a-0f20219fbef1)
 


5. Configuring postfix
cat /etc/postfix/main.cf
postconf -e "myhostname = mail.sky29.co.za"
postconf -e "mydestination = mail.sky29.co.za, localhost, localhost.localdomain"
postconf -e "mynetworks = 127.0.0.0/8"
postconf -e "message_size_limit = 31457280"
postconf -e "virtual_alias_domains ="
postconf -e "virtual_alias_maps = proxy:mysql:/etc/postfix/mysql_virtual_forwardings.cf, mysql:/etc/postfix/mysql_virtual_email2email.cf"
postconf -e "virtual_mailbox_domains = proxy:mysql:/etc/postfix/mysql_virtual_domains.cf"
postconf -e "virtual_mailbox_maps = proxy:mysql:/etc/postfix/mysql_virtual_mailboxes.cf"
postconf -e "virtual_mailbox_base = /var/vmail"
postconf -e "virtual_uid_maps = static:5000"
postconf -e "virtual_gid_maps = static:5000"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "broken_sasl_auth_clients = yes"
postconf -e "smtpd_sasl_authenticated_header = yes"
postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
postconf -e "smtpd_use_tls = yes"
postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/sky29.co.za /fullchain.pem"
postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/sky29.co.za /privkey.pem"
postconf -e "virtual_transport=dovecot"
postconf -e 'proxy_read_maps = $local_recipient_maps $mydestination $virtual_alias_maps $virtual_alias_domains $virtual_mailbox_maps $virtual_mailbox_domains $relay_recipient_maps $relay_domains $canonical_maps $sender_canonical_maps $recipient_canonical_maps $relocated_maps $transport_maps $mynetworks $virtual_mailbox_limit_maps'
![image](https://github.com/user-attachments/assets/1a327af8-12f3-4297-bacc-061a355f547c)
 


6. Configuring SMTP AUTH (SASLAUTHD and MySql)\
![image](https://github.com/user-attachments/assets/b591aae3-d57c-41f8-9b7d-f3bb7cc2752e)
 
a) Creating a directory where saslauthd will save its information:  
`mkdir -p /var/spool/postfix/var/run/saslauthd`
![image](https://github.com/user-attachments/assets/03f70bca-395e-4bba-b433-967f603bf106)
 

b) Editing the configuration file of saslauthd: vim /etc/default/saslauthd
START=yes
DESC="SASL Authentication Daemon"
NAME="saslauthd"
MECHANISMS="pam"
MECH_OPTIONS=""
THREADS=5
OPTIONS="-c -m /var/spool/postfix/var/run/saslauthd -r"
![image](https://github.com/user-attachments/assets/97aa18f5-363f-4c0b-a0f4-9aa4cfe6c5a6)
 

c) Creating a new file: vim /etc/pam.d/smtp
auth required pam_mysql.so user=mail_admin passwd=mail_admin_password host=127.0.0.1 db=mail table=users usercolumn=email passwdcolumn=password crypt=3
account sufficient pam_mysql.so user=mail_admin passwd=mail_admin_password host=127.0.0.1 db=mail table=users usercolumn=email passwdcolumn=password crypt=3
![image](https://github.com/user-attachments/assets/553553fc-2263-42b7-8f5a-4f2ed56199d9)
 

d) vim /etc/postfix/sasl/smtpd.conf
pwcheck_method: saslauthd 
mech_list: plain login 
log_level: 4
![image](https://github.com/user-attachments/assets/ede36c54-bc9a-4830-92f5-4019caf6f3bd)
 

e) Setting the permissions
chmod o-rwx /etc/pam.d/smtp
chmod o-rwx /etc/postfix/sasl/smtpd.conf
![image](https://github.com/user-attachments/assets/722b39cf-34a1-43d9-865e-b283522c45a6)
 
f) Adding the postfix user to the sasl group for group access permissions: 
usermod  -aG sasl postfix
![image](https://github.com/user-attachments/assets/7d3ca261-7480-46b1-8487-efa7c37e8006)
 

g) Restarting the services:
systemctl restart postfix
systemctl restart saslauthd
![image](https://github.com/user-attachments/assets/7931215b-9706-4f90-a3e6-8d4a9033aa3b)
 

7. Configuring Dovecot (POP3/IMAP)
![image](https://github.com/user-attachments/assets/7dc8e33f-edb8-4891-bcd7-f6a0d73b8433)
 
a) At the end of /etc/postfix/master.cf add:
dovecot   unix  -       n       n       -       -       pipe
    flags=DRhu user=vmail:vmail argv=/usr/lib/dovecot/deliver -d ${recipient}
![image](https://github.com/user-attachments/assets/dadc3f06-a065-4bd6-86bc-cb3baba2d77c)
 
b) Edit Dovecot config file: vim /etc/dovecot/dovecot.conf
log_timestamp = "%Y-%m-%d %H:%M:%S "
mail_location = maildir:/var/vmail/%d/%n/Maildir
managesieve_notify_capability = mailto
managesieve_sieve_capability = fileinto reject envelope encoded-character vacation subaddress comparator-i;ascii-numeric relational regex imap4flags copy include variables body enotify environment mailbox date
namespace {
  inbox = yes
  location = 
  prefix = INBOX.
  separator = .
  type = private
}
passdb {
  args = /etc/dovecot/dovecot-sql.conf
  driver = sql
}
protocols = imap pop3

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
  unix_listener auth-master {
    mode = 0600
    user = vmail
  }
  user = root
}

userdb {
  args = uid=5000 gid=5000 home=/var/vmail/%d/%n allow_all_users=yes
  driver = static
}

protocol lda {
  auth_socket_path = /var/run/dovecot/auth-master
  log_path = /var/vmail/dovecot-deliver.log
  mail_plugins = sieve
  postmaster_address = postmaster@example.com
}

protocol pop3 {
  pop3_uidl_format = %08Xu%08Xv
}

service stats {
  unix_listener stats-reader {
    user = dovecot
    group = vmail
    mode = 0660
  }
  unix_listener stats-writer {
    user = dovecot
    group = vmail
    mode = 0660
  }
}

ssl = yes
ssl_cert = </etc/letsencrypt/live/crystalmind.academy/fullchain.pem
ssl_key = </etc/letsencrypt/live/crystalmind.academy/privkey.pem
![image](https://github.com/user-attachments/assets/1499bf0c-abc7-43a6-afca-db3771dbd7ab)
 
c) vim /etc/dovecot/dovecot-sql.conf
driver = mysql
connect = host=127.0.0.1 dbname=mail user=mail_admin password=mail_admin_password
default_pass_scheme = PLAIN-MD5
password_query = SELECT email as user, password FROM users WHERE email='%u';
![image](https://github.com/user-attachments/assets/723b241c-64b9-4115-9f4d-36be0922fb26)
 
d) Restart Dovecot
1systemctl restart dovecot1
![image](https://github.com/user-attachments/assets/e68aa0b8-2ae8-4105-8383-3a91266f6402)
 

8. Adding Domains and Virtual Users. 
mysql -u root
msyql>USE mail;
mysql>INSERT INTO domains (domain) VALUES ('sky29.co.za');
mysql>insert into users(email,password) values('u1@sky29.co.za', md5('pass123'));
mysql>insert into users(email,password) values('u2@sky29.co.za', md5('pass123'));
mysql>quit;
![image](https://github.com/user-attachments/assets/16b43d22-c821-4efd-8a0b-96b27f33adcb)
![image](https://github.com/user-attachments/assets/5e8c00a0-2209-4ef7-b296-be84827ae264)

9. Testing the Mail System.
Set up a Mail client like Mozilla Thunderbird, send and receive mail to both local and external accounts.

Congratulations on making it so far! :)
This was a complex project with lots of details and steps to follow.

