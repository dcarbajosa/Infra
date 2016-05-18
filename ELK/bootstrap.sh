#!/bin/bash  -x

############################################################################
#install packages needed
##############################################################################
yum install -y system-storage-manager
yum install -y wget git net-tools bind-utils iptables-services bridge-utils bash-completion

yum update -y

yum -y install epel-release

sed -i -e "s/^enabled=1/enabled=0/" /etc/yum.repos.d/epel.repo

yum -y --enablerepo=epel install ansible pyOpenSSL

yum -y install ruby

yum -y install rubygems
#
yum install -y ntpdate ntp

##############################################################################
# Configure logging - journald
##############################################################################
mkdir /var/log/journal
sed -i "s/#Storage/Storage/g" /etc/systemd/journald.conf
sed -i "s/#SystemMaxUse=/SystemMaxUse=50M/g" /etc/systemd/journald.conf
sed -i "s/#Compress/Compress/g" /etc/systemd/journald.conf

systemctl restart systemd-journald

##############################################################################
# Firewalld
##############################################################################
systemctl stop firewalld
##############################################################################
# NTP services
##############################################################################
ntpdate ntp2a.mcc.ac.uk
systemctl enable ntpd.service
systemctl start ntpd.service

##############################################################################
# Java - jdk-8u72-linux-x64
##############################################################################
cd /opt/
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u72-b15/jdk-8u72-linux-x64.tar.gz"
tar xzf jdk-8u72-linux-x64.tar.gz

cd /opt/jdk1.8.0_72/
alternatives --install /usr/bin/java java /opt/jdk1.8.0_72/jre/bin/java 2
alternatives --install /usr/bin/jar jar /opt/jdk1.8.0_72/bin/jar 2
alternatives --install /usr/bin/javac javac /opt/jdk1.8.0_72/bin/javac 2
alternatives --install /usr/bin/javaws javaws /opt/jdk1.8.0_72/jre/bin/javaws 2

alternatives --set java /opt/jdk1.8.0_72/jre/bin/java
alternatives --set javaws /opt/jdk1.8.0_72/jre/bin/javaws
alternatives --set jar /opt/jdk1.8.0_72/bin/jar
alternatives --set javac /opt/jdk1.8.0_72/bin/javac

java -version

export JAVA_HOME=/opt/jdk1.8.0_72
export JRE_HOME=/opt/jdk1.8.0_72/jre
export PATH=$PATH:/opt/jdk1.8.0_72/bin:/opt/jdk1.8.0_72/jre/bin

##############################################################################
# ELK
##############################################################################
##############################################################################
# Elasticsearch
##############################################################################

rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch

echo '[elasticsearch-2.x]
name=Elasticsearch repository for 2.x packages
baseurl=http://packages.elastic.co/elasticsearch/2.x/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | sudo tee /etc/yum.repos.d/elasticsearch.repo

yum -y install elasticsearch

sed -i -e "s/^# network.host: 192.168.0.1/network.host: localhost/" /etc/elasticsearch/elasticsearch.yml
sed -i -e "s/^# http.port: 9200/http.port: 9200/" /etc/elasticsearch/elasticsearch.yml

systemctl start elasticsearch
systemctl enable elasticsearch

##############################################################################
# Kibana
##############################################################################
echo '[kibana-4.4]
name=Kibana repository for 4.4.x packages
baseurl=http://packages.elastic.co/kibana/4.4/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | sudo tee /etc/yum.repos.d/kibana.repo

yum -y install kibana

sed -i -e "s/^# server.host: \"0\.0\.0\.0\"/server.host: \"localhost\"/" /opt/kibana/config/kibana.yml

systemctl start kibana
chkconfig kibana on

##############################################################################
# Nginx
##############################################################################

yum -y --enablerepo=epel install nginx httpd-tools

htpasswd -c -b /etc/nginx/htpasswd.users kibanaadmin Codedev1!

sed -i '35,54 s/^/#/' /etc/nginx/nginx.conf

echo 'server {
    listen 80;

    server_name example.com;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}' | sudo tee /etc/nginx/conf.d/kibana.conf

systemctl start nginx
systemctl enable nginx

setenforce permissive

setsebool -P httpd_can_network_connect 1

##############################################################################
# Logstash
##############################################################################

echo '[logstash-2.2]
name=logstash repository for 2.2 packages
baseurl=http://packages.elasticsearch.org/logstash/2.2/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
' | sudo tee /etc/yum.repos.d/logstash.repo

yum -y install logstash

echo 'input {
  http {
    host => "192.168.56.110" # default: 0.0.0.0
    port => 31311 # default: 8080
  }
}
' | sudo tee /etc/logstash/conf.d/02-http-input.conf

echo 'filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
' | sudo tee /etc/logstash/conf.d/10-syslog-filter.conf

echo '
output {
  elasticsearch {
    hosts => "localhost:9200"
    workers => 2
  }
}
' | sudo tee /etc/logstash/conf.d/30-elasticsearch-output.conf

service logstash configtest

systemctl restart logstash
chkconfig logstash on
