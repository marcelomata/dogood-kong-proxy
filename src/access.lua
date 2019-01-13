

local _M = {}
local cjson = require "cjson.safe"
local pl_stringx = require "pl.stringx"
local http = require "resty.http"
-- local crypto = require "crypto"
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
    -- print(callback_url)
    print('###################### Dump of ngx.ctx)')
    print(print_table.dump(ngx.ctx))
    print('###################### Dump of ngx.var)')
    print(print_table.dump(ngx.var))
    -- print('###################### Dump of ngx.ctx.balancer_data)')
    -- print(print_table.dump(ngx.ctx.balancer_data))
    print('###################### Dump of ngx.ctx.service)')
    print(print_table.dump(ngx.ctx.service))
    print('###################### Dump of ngx.ctx.api)')
    print(print_table.dump(ngx.ctx.api))
    print('###################### Dump of ngx.req)')
    print(print_table.dump(ngx.req))
    -- print('###################### Dump of ngx.ctx.api.hosts)')
    -- print(print_table.dump(ngx.ctx.api.hosts))
    -- print('###################### Print of ngx.ctx.api.id)')
    -- print(ngx.ctx.api.id)
    -- print('###################### Print of ngx.ctx.api.upstream_url)')
    -- print(ngx.ctx.api.upstream_url)
    print('###################### Dump of ngx.req.get_headers())')
    headers =  ngx.req.get_headers()
    print(print_table.dump(headers))
    -- print('###################### Print of headers["Authorization"]')
    -- print(headers["Authorization"])
    print('###################### Print of ngx.req.get_body_data()')
    print(print_table.dump(ngx.req.get_body_data()))
    print('###################### Print of ngx.req.read_body()')
    print(print_table.dump(ngx.req.read_body()))
    print('###################### Print of ngx.req.get_query_args()')
    print(print_table.dump(ngx.req.get_query_args()))
    print('###################### Print of ngx.req.get_post_args()')
    print(print_table.dump(ngx.req.get_post_args()))
    print('###################### Print of ngx.req.get_uri_args()')
    print(print_table.dump(ngx.req.get_uri_args()))
    print('###################### Print of ngx.req.get_method()')
    print(print_table.dump(ngx.req.get_method()))

    local headers =  ngx.req.get_headers()
    local authorization_header = headers["Authorization"]

    if authorization_header then
        local header_list, iter_err = ngx.re.match(authorization_header, "\\s*[Bb]earer\\s*(.+)")
        if not header_list then
            ngx.log(ngx.ERR, iter_err)
            responses.send(401, 'Token not provided.')
        end

        if header_list and header_list[1] then
            -- print('###################### Print only the token 222222')
            -- print(header_list[0])
            -- print(header_list[1])
            local token = header_list[1]

            -- print('###################### Print the authorization endpint')
            -- print(conf.authorize_url)

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
                responses.send(401, 'Token not provided.')
            end       

            -- print('###################### Print the response from authorization server')
            -- print(print_table.dump(res))

            ngx.req.read_body()
            if ngx.req.get_post_args() then
                body_data = ngx.req.get_post_args()
            else
                body_data = nil
            end
            
            query_args = ngx.req.get_query_args()
            http_method = ngx.req.get_method()

            request_obj = {
                method = http_method,
                headers = {
                    ["Content-Type"] = "application/json",
                }
            }

            request_body = "";
            if body_data then 
                request_obj["body"] = body_data
            end

            url = ngx.ctx.service.host .. ":" .. ngx.ctx.service.port .. "/" .. ngx.ctx.service.path

            request_args = "?"
            for _, v in pairs(query_args) do
                request_args = request_args .. v .. "&"
            end

            if string.len(request_args) > 1 then
                request_args = request_args:sub(1, -2)
                url = url .. request_args
            end

            print('###################### Print the request obj')
            print(print_table.dump(request_obj))
            print('###################### Print the request url')
            print(print_table.dump(url))

            -- local httpc = http:new()
            -- local res, err = httpc:request_uri(url, request_obj)

            return responses.send(200, 'Ok')

        else
            responses.send(401, 'Token not provided.')
        end


    end
    -- print('###################### Print of headers["Host"]')
    -- print(headers["Host"])

    -- Here will be performed the call to the api
    -- local httpc = http:new()
    -- local res, err = httpc:request_uri(conf.token_url , {
    --     method = "GET",
    --     headers = {
    --         ["Content-Type"] = "application/json",
    --     }
    -- })    
    
    -- return responses.send(200, 'Ok')
    
end

-- function encode_token(token, conf)
--     return ngx.encode_base64(crypto.encrypt("aes-128-cbc", token, crypto.digest('md5',conf.client_secret)))
-- end

-- function decode_token(token, conf)
--     status, token = pcall(function () return crypto.decrypt("aes-128-cbc", ngx.decode_base64(token), crypto.digest('md5',conf.client_secret)) end)
--     if status then
--         return token
--     else
--         return nil
--     end
-- end


return _M
