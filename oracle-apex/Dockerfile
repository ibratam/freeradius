FROM container-registry.oracle.com/database/free:latest
LABEL authors="ibraheem"

COPY unattended_apex_install_23c.sh /home/oracle
COPY 00_start_apex_ords_installer.sh /opt/oracle/scripts/startup
CMD ["tail", "-f /home/oracle/unattended_apex_install_23c.log"]