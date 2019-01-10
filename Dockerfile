FROM kong:latest

# # Version of Lua we're building the image for.
ENV LUA_VERSION 5.1

ENV LUA_PACKAGE lua${LUA_VERSION}

ENV KONG_CUSTOM_PLUGINS dogood-kong-proxy

# Update apk index.
RUN apk update

# # # Install packages necessary for Lua, Luarocks.
RUN apk add --no-cache ${LUA_PACKAGE}
RUN apk add --no-cache ${LUA_PACKAGE}-dev

# # # Build dependencies.
RUN apk add build-base git bash unzip zip openssl openssl-dev

# # # Build Luarocks.
RUN cd /tmp && \
    git clone https://github.com/keplerproject/luarocks.git && \
    cd luarocks && \
    sh ./configure && \
    make build install && \
    cd && \
    rm -rf /tmp/luarocks && \
    luarocks install luacrypto

RUN cd / && \
    git clone https://github.com/marcelomatao/dogood-kong-proxy.git && \
    cd dogood-kong-proxy && \
    ls && \
    luarocks install dogood-kong-proxy-0.1-5.rockspec 

ENTRYPOINT ["/docker-entrypoint.sh"]

# CMD ["kong", "docker-start"]
CMD ["kong", "start"]