#!/bin/bash
# Program:每天凌晨的时候对nginx日志进行切割和回收
# 此文件的日志路径都是以docker镜像作为依据，在docker中运行。
# 注意:此脚本运行之前必须要确保当前路径为在logs的同级目录(在supervisor中确保)

#上次回收的时间(只取天)
last_running_day=$(date +%d)

#判断是否到了日志回收的时候了
function is_running_time()
{
		cur_day=$(date +%d)
		if [ ${cur_day} -eq ${last_running_day} ]; then
			 	return 0
		fi
		last_running_day=${cur_day}
    return 1
}

#执行日志回收的动作
function rotate_log()
{
	#当前时间
	time=$(date -d "yesterday" +"%Y-%m-%d")
	
	#对目录中的转储日志文件的文件名进行统一转换
	mkdir -p ./logs_bak
	cd ./logs
	for i in $(ls ./ | grep -E "^(.*).log$")
	do
		newname=$(echo ${i} | sed -n 's/.log//p' )-$(echo $time).log
		#echo "newname $newname"
		mv ${i} ../logs_bak/$(echo ${i} | sed -n 's/.log//p' )-$(echo $time).log
	done
  cd ..

	#通知nginx重建日志文件
	nginxpid=$(echo `cat ./logs/*nginx.pid`)
	kill -USR1 ${nginxpid}
	
	#只保留最近3天的日志文件
	find ./logs_bak/* -name "*.log" -mtime 3 -type f -exec rm -rf {} \; > /dev/null 2>&1
}

echo "Reclaim Nginx Log is Start!"
while true
do
		is_running_time
		run_flag=$?
		if [ $run_flag -eq 1 ] ;then
   			rotate_log
		fi
		sleep 1h 	#睡眠1小时
done

echo "Reclaim Nginx Log is Exit!"

