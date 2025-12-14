FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------
# Install base packages
# --------------------------------------------------
RUN apt-get update && apt-get install -y \
    freeradius \
    freeradius-utils \
    freeradius-common \
    build-essential \
    git \
    libaio1 \
    libssl-dev \
    wget \
    unzip \
    pkg-config \
    autoconf \
    automake \
    libtool \
    libpam0g-dev \
    libldap2-dev \
libtalloc-dev \
    libkqueue-dev \
    libbrotli-dev \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------
# Install Oracle Instant Client
# --------------------------------------------------
WORKDIR /opt/oracle
COPY --chown=freerad:freerad instantclient-basic-linux.x64-19.23.0.0.0dbru.zip \
     /opt/oracle/instantclient-basic-linux.x64-19.23.0.0.0dbru.zip
COPY --chown=freerad:freerad instantclient-sdk-linux.x64-19.23.0.0.0dbru.zip \
     /opt/oracle/instantclient-sdk-linux.x64-19.23.0.0.0dbru.zip
     
RUN unzip -o instantclient-basic-linux.x64-19.23.0.0.0dbru.zip && \
    unzip -o instantclient-sdk-linux.x64-19.23.0.0.0dbru.zip && \
    rm -f *.zip
#wget https://download.oracle.com/otn_software/linux/instantclient/1923000/instantclient-basic-linux.x64-19.23.0.0.0dbru.zip && \
#    wget https://download.oracle.com/otn_software/linux/instantclient/1923000/instantclient-sdk-linux.x64-19.23.0.0.0dbru.zip && \
ENV ORACLE_HOME=/opt/oracle/instantclient_19_23
#ENV LD_LIBRARY_PATH="$ORACLE_HOME"
ENV LD_LIBRARY_PATH="$ORACLE_HOME:$LD_LIBRARY_PATH"
ENV PATH="$ORACLE_HOME:$PATH"

# --------------------------------------------------
# Build Oracle SQL module from source
# --------------------------------------------------
WORKDIR /build

#RUN git clone https://github.com/FreeRADIUS/freeradius-server.git && \
#    cd freeradius-server && \
#    ./configure \
#        --with-oracle \
#        --with-oracle-lib-dir=$ORACLE_HOME \
#        --with-oracle-include-dir=$ORACLE_HOME/sdk/include && \
#    make src/modules/rlm_sql/drivers/oracle && \
#    cp src/modules/rlm_sql/drivers/oracle/.libs/rlm_sql_oracle.so \
#       /usr/lib/freeradius/
#RUN git clone https://github.com/FreeRADIUS/freeradius-server.git && \
#    cd freeradius-server && \
#    ./configure \
#        --with-oracle \
#        --with-oracle-lib-dir=$ORACLE_HOME \
#        --with-oracle-include-dir=$ORACLE_HOME/sdk/include && \
#    make src/modules/rlm_sql_oracle && \
#    cp src/modules/rlm_sql_oracle/.libs/rlm_sql_oracle.so \
#       /usr/lib/freeradius/

RUN git clone --branch v3.0.x https://github.com/FreeRADIUS/freeradius-server.git && \
    cd freeradius-server && \
    ./configure \
        --with-oracle \
        --with-oracle-lib-dir=$ORACLE_HOME \
        --with-oracle-include-dir=$ORACLE_HOME/sdk/include && \
    make -j$(nproc) && \
    find . -name "rlm_sql_oracle.so" -exec cp {} /usr/lib/freeradius/ \;


# --------------------------------------------------
# Oracle SQL queries config directory
# --------------------------------------------------
RUN mkdir -p /etc/freeradius/3.0/mods-config/sql/main/oracle

COPY --chown=freerad:freerad sql/oracle/queries.conf \
     /etc/freeradius/3.0/mods-config/sql/main/oracle/

# --------------------------------------------------
# Start script
# --------------------------------------------------
RUN cat > /usr/local/bin/start-freeradius.sh << 'EOF' \
&& chmod +x /usr/local/bin/start-freeradius.sh
#!/bin/bash

cat > /etc/freeradius/3.0/mods-available/sql << SQLCONF
sql {
    driver = "rlm_sql_oracle"
    dialect = "oracle"

    server = "${ORACLE_HOST:-192.168.88.8}"
    port   = ${ORACLE_PORT:-8521}
    login  = "${ORACLE_USER:-system}"
    password = "${ORACLE_PASSWORD:-Abcd#1234}"
    radius_db = "//${ORACLE_HOST:-192.168.88.8}:${ORACLE_PORT:-8521}/${ORACLE_SERVICE_NAME:-FREEPDB1}"

    authcheck_table  = "${radius_db:-GO_TECH_RADIUS}.radcheck"
    authreply_table  = "${radius_db:-GO_TECH_RADIUS}.radreply"
    groupcheck_table = "${radius_db:-GO_TECH_RADIUS}.radgroupcheck"
    groupreply_table = "${radius_db:-GO_TECH_RADIUS}.radgroupreply"
    usergroup_table  = "${radius_db:-GO_TECH_RADIUS}.radusergroup"
    postauth_table   = "${radius_db:-GO_TECH_RADIUS}.radpostauth"
    acct_table1      = "${radius_db:-GO_TECH_RADIUS}.radacct"
    acct_table2      = "${radius_db:-GO_TECH_RADIUS}.radacct"

    delete_stale_sessions = yes

    read_clients = yes
    client_table = "${radius_db:-GO_TECH_RADIUS}.nas"
    group_attribute = "SQL-Group"

    \$INCLUDE \${modconfdir}/\${.:name}/main/\${dialect}/queries.conf
}
SQLCONF

ln -sf /etc/freeradius/3.0/mods-available/sql \
       /etc/freeradius/3.0/mods-enabled/sql

exec freeradius -X
EOF

# Remove the separate chmod line since it's now combined above
# RUN chmod +x /usr/local/bin/start-freeradius.sh
# --------------------------------------------------
# Expose ports
# --------------------------------------------------
EXPOSE 1812/udp
EXPOSE 1813/udp

CMD ["/usr/local/bin/start-freeradius.sh"]
