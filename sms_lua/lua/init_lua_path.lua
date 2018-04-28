#!/usr/local/openresty/luajit/bin/luajit-2.1.0-alpha

--[设定搜索路径]
--将自定义包路径加入package的搜索路径中。也可以加到环境变量LUA_PATH中
local p = "/xm_workspace/xmcloud3.0/"
local m_package_path = package.path
package.path = string.format("%s;%s?.lua;%s?/init.lua",m_package_path, p, p)