

local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.dogood-kong-proxy.access"

local DogoodProxyPlugin = BasePlugin:extend()

function DogoodProxyPlugin:new()
	DogoodProxyPlugin.super.new(self, "dogood-kong-proxy")
end

function DogoodProxyPlugin:access(conf)
	DogoodProxyPlugin.super.access(self)
	access.run(conf)
end

return DogoodProxyPlugin
