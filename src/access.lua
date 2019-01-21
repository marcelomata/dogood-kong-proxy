

local _M = {}
local http = require "resty.http"
local print_table = require 'pl.pretty'
local ngx_re_match = ngx.re.match
local responses = require "kong.tools.responses"

function _M.run(conf)

    -- print('###################### Dump of conf)')
    -- print(print_table.dump(conf))
    -- print('###################### Dump of ngx)')
    -- print(print_table.dump(ngx))
    -- local callback_url = ngx.var.scheme .. "://" .. ngx.var.host ..  ":" .. ngx.var.server_port .. ngx.var.request_uri
    -- print('###################### Print ngx.var.scheme .. "://" .. ngx.var.host ..  ":" .. ngx.var.server_port .. ngx.var.request_uri)')
    -- print(print_table.dump(callback_url))
    -- print('###################### Dump of ngx.ctx)')
    -- print(print_table.dump(ngx.ctx))
    -- print('###################### Dump of ngx.var)')
    -- print(print_table.dump(ngx.var))
    -- print('###################### Dump of ngx)')
    -- print(print_table.dump(ngx))
    -- print('###################### Dump of ngx.unescape_uri())')
    -- print(print_table.dump(ngx.unescape_uri()))
    -- -- print('###################### Dump of ngx.encode_args()) ERROR')
    -- -- print(print_table.dump(ngx.encode_args()))
    -- -- print('###################### Dump of ngx.ctx.balancer_data)')
    -- -- print(print_table.dump(ngx.ctx.balancer_data))
    -- print('###################### Dump of ngx.ctx.service)')
    -- print(print_table.dump(ngx.ctx.service))
    -- print('###################### Dump of ngx.ctx.api)')
    -- print(print_table.dump(ngx.ctx.api))
    -- print('###################### Dump of ngx.req)')
    -- print(print_table.dump(ngx.req))
    -- -- print('###################### Dump of ngx.ctx.api.hosts)')
    -- -- print(print_table.dump(ngx.ctx.api.hosts))
    -- -- print('###################### Print of ngx.ctx.api.id)')
    -- -- print(ngx.ctx.api.id)
    -- -- print('###################### Print of ngx.ctx.api.upstream_url)')
    -- -- print(ngx.ctx.api.upstream_url)
    -- print('###################### Dump of ngx.req.get_headers())')
    -- headers =  ngx.req.get_headers()
    -- print(print_table.dump(headers))
    -- -- print('###################### Print of headers["Authorization"]')
    -- -- print(headers["Authorization"])
    -- print('###################### Print of ngx.req.get_body_data()')
    -- print(print_table.dump(ngx.req.get_body_data()))
    -- print('###################### Print of ngx.req.read_body()')
    -- print(print_table.dump(ngx.req.read_body()))
    -- print('###################### Print of ngx.req.get_query_args()')
    -- print(print_table.dump(ngx.req.get_query_args()))
    -- print('###################### Print of ngx.req.get_post_args()')
    -- print(print_table.dump(ngx.req.get_post_args()))
    -- print('###################### Print of ngx.req.get_uri_args()')
    -- print(print_table.dump(ngx.req.get_uri_args()))
    -- print('###################### Print of ngx.req.get_method()')
    -- print(print_table.dump(ngx.req.get_method()))

    local headers =  ngx.req.get_headers()
    local authorization_header = headers["Authorization"]

    if authorization_header then
        local header_list, iter_err = ngx_re_match(authorization_header, "\\s*[Bb]earer\\s*(.+)")
        if not header_list then
            ngx.log(ngx.ERR, iter_err)
            responses.send(401, 'Token not provided.')
        end

        if header_list and header_list[1] then
            -- print('###################### Print only the token 222222')
            -- print(header_list[0])
            -- print(header_list[1])
            local token = header_list[1]

            print('###################### Print the authorization endpint')
            print(conf.authorize_url)

            -- Here will be performed the call to the authentication api
            local httpc = http:new()
            local res, err = httpc:request_uri(conf.authorize_url , {
                method = "GET",
                headers = {
                    ["Content-Type"] = "application/json",
                    ["Authorization"] = "Baerer "..header_list[1],
                }
            })

            if err or res.status ~= 200 then
                print('###################### Print the error from authorization server')    
                print(print_table.dump(err))
                responses.send(res.status, res.body)
            end       
            -- -- print('###################### Print the response from authorization server')
            -- -- print(print_table.dump(res))

            -- ngx.req.read_body()
            -- if ngx.req.get_post_args() then
            --     body_data = ngx.req.get_post_args()
            -- else
            --     body_data = nil
            -- end
            
            -- query_args = ngx.req.get_query_args()
            -- http_method = ngx.req.get_method()

            -- request_obj = {
            --     method = http_method,
            --     headers = {
            --         ["Content-Type"] = "application/json",
            --     }
            -- }

            -- -- print('###################### Print the body_data')
            -- -- print(print_table.dump(body_data))

            -- request_body = "";
            -- if body_data then 
            --     for k, v in pairs(body_data) do
            --         -- print(print_table.dump(k))
            --         -- print(print_table.dump(v))
            --         request_obj["body"] = k
            --     end
            -- end

            -- -- url = ngx.ctx.service.host .. ":" .. ngx.ctx.service.port .. "/" .. ngx.ctx.service.path
            -- url = ngx.var.scheme .. "://" .. ngx.ctx.service.host ..  ":" .. ngx.ctx.service.port .. ngx.var.request_uri

            -- request_args = "?"
            -- for _, v in pairs(query_args) do
            --     request_args = request_args .. v .. "&"
            -- end

            -- if string.len(request_args) > 1 then
            --     request_args = request_args:sub(1, -2)
            --     url = url .. request_args
            -- end

            -- print('###################### Print the request obj')
            -- print(print_table.dump(request_obj))
            -- print('###################### Print the request url')
            -- print(print_table.dump(url))

            -- local httpc = http:new()
            -- local res, err = httpc:request_uri(url, request_obj)

            -- print('###################### Print the response from upstream server')
            -- print(print_table.dump(res))
            -- print('###################### Print the error from upstream server')
            -- print(print_table.dump(err))

            -- responses.send(res.status, res.body)

        else
            responses.send(401, 'Token not provided.')
        end

    else    
        return responses.send(401, 'Token not provided. This service is not allowed to be accessed without authorization.')
    end
    
end


-- function get_token(token, conf)
--     status, token = pcall(function () return crypto.decrypt("aes-128-cbc", ngx.decode_base64(token), crypto.digest('md5',conf.client_secret)) end)
--     if status then
--         return token
--     else
--         return nil
--     end
-- end


return _M
