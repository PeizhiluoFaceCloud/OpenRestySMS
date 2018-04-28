#Dockerfile
#FROM openresty_face/base:v0.01
FROM daocloud.io/peizhiluo007/openresty:latest
MAINTAINER peizhiluo007<25159673@qq.com>

#����supervisor�����������
#�����ļ���·���仯��(since Supervisor 3.3.0)
COPY supervisord.conf /etc/supervisor/supervisord.conf
COPY sms_lua/ /xm_workspace/xmcloud3.0/sms_lua/
RUN	chmod 777 /xm_workspace/xmcloud3.0/sms_lua/*

EXPOSE 8002
#WORKDIR /xm_workspace/xmcloud3.0/common_lua/
#CMD ./sockproc /tmp/shell.sock && chmod 0666 /tmp/shell.sock && supervisord
WORKDIR /xm_workspace/xmcloud3.0/sms_lua/
CMD ["supervisord"]

