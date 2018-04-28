#!/bin/bash
#注意:必须是bash，如果是dash则下面的type -p命令不支持
nginx_path=`type -p nginx`
config_path=`pwd`
${nginx_path} -s stop -p ${config_path} -c ${config_path}/conf/nginx.conf
