package = "dogood-kong-proxy"
version = "0.1-5"
source = {
  url = "git://github.com/marcelomata/dogood-kong-proxy"
}
description = {
  summary = "A Kong plugin, that let you proxy Oauth 2.0 to your API",
  license = "Apache 2.0"
}
dependencies = {
  "lua >= 5.1"
  -- If you depend on other rocks, add them here
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.dogood-kong-proxy.access"] = "src/access.lua",
    ["kong.plugins.dogood-kong-proxy.handler"] = "src/handler.lua",
    ["kong.plugins.dogood-kong-proxy.schema"] = "src/schema.lua"
  }
}
