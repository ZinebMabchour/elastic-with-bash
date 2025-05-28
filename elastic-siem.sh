#!/bin/bash

install_figlet() {
    if ! command -v figlet &> /dev/null; then
        apt update -qq && apt install -y figlet -qq
    fi
}

display_header() {
    clear
    echo -e "\e[1;35m"
    figlet -f slant "Elastic SIEM"
    echo -e "\e[33m============================================\e[0m"
    echo -e "\e[32m[*] Multi-node. Cluster ready. SIEM focused.\e[0m"
    echo -e "\e[32m[*] Just deploy and get to work.\e[0m"
    echo -e "\e[33m============================================\e[0m"
    echo ""
}

install_figlet
display_header

LOG_FILE="/tmp/elk_deploy_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

error_exit() {
    echo "Error: $1" >&2
    exit 1
}

run_command() {
    echo "Running: $1"
    eval "$1" || error_exit "Command failed: $1"
}

run_command_continue() {
    echo "Running (non‑critical): $1"
    eval "$1" || echo "Command failed but continuing: $1"
}

check_package_installed() {
    local host=$1
    local user=$2
    local password=$3
    local package=$4

    if sshpass -p "$password" ssh -o StrictHostKeyChecking=no "$user@$host" "dpkg -l | grep -q $package"; then
        return 0
    else
        return 1
    fi
}

check_file_exists() {
    local host=$1
    local user=$2
    local password=$3
    local filepath=$4

    sshpass -p "$password" ssh -o StrictHostKeyChecking=no "$user@$host" "[ -f $filepath ]"
}


if ! command -v sshpass &> /dev/null; then
    run_command "apt update && apt install -y sshpass"
fi

read -p "How many Elasticsearch nodes? : " NODE_COUNT
declare -A NODES
declare -A NODES_USER
declare -a NODE_IPS

for ((i=1;i<=NODE_COUNT;i++)); do
    read    -p "     IP for ES node $i : " nip
    read    -p "     SSH user for $nip            : " nuser
    read -s -p "     SSH password for $nuser@$nip : " npw; echo
    NODE_IPS[$((i-1))]=$nip
    NODES["$nip"]=$npw
    NODES_USER["$nip"]=$nuser
done

echo
read -p "How many Kibana nodes? (>=1) : " KIBANA_COUNT
declare -A KIBANA_PWS
declare -A KIBANA_USERS
declare -a KIBANA_IPS
for ((i=1;i<=KIBANA_COUNT;i++)); do
    read    -p "     IP for Kibana node $i : " kip
    read    -p "     SSH user for $kip               : " kubuser
    read -s -p "     SSH password for $kubuser@$kip  : " kpw; echo
    KIBANA_IPS[$((i-1))]=$kip
    KIBANA_PWS["$kip"]=$kpw
    KIBANA_USERS["$kip"]=$kubuser
done

read -p "Enter your cluster name: " CLUSTER_NAME
echo

read -p "Enter the IP for Logstash (press ENTER to skip): " LOGSTASH_IP
if [[ -n "$LOGSTASH_IP" ]]; then
    read -p "Enter SSH user for $LOGSTASH_IP               : " LOGSTASH_USER
    read -s -p "Enter SSH password for $LOGSTASH_USER@$LOGSTASH_IP : " LOGSTASH_SSH_PASSWORD; echo
    LOGSTASH_SKIP=false
else
    LOGSTASH_SKIP=true
fi
echo

if ! $LOGSTASH_SKIP; then
  LOGSTASH_HOSTNAME=$(
    sshpass -p "$LOGSTASH_SSH_PASSWORD" ssh -o StrictHostKeyChecking=no \
      "$LOGSTASH_USER@$LOGSTASH_IP" hostname
  )
fi


read -p "Clean install (y/n) ? : " CLEAN_INSTALL
CLEAN_INSTALL=$(tr '[:upper:]' '[:lower:]' <<<"$CLEAN_INSTALL")
CERT_PASSWORD="changeme"

declare -A NODE_HOSTNAMES
for ip in "${NODE_IPS[@]}"; do
    pw=${NODES["$ip"]}
    user=${NODES_USER["$ip"]}
    NODE_HOSTNAMES["$ip"]=$(
      sshpass -p "$pw" ssh -o StrictHostKeyChecking=no \
        "$user@$ip" hostname
    )
done

declare -A KIBANA_HOSTNAMES
for kip in "${KIBANA_IPS[@]}"; do
    kpw=${KIBANA_PWS["$kip"]}
    kubuser=${KIBANA_USERS["$kip"]}
    KIBANA_HOSTNAMES["$kip"]=$(
      sshpass -p "$kpw" ssh -o StrictHostKeyChecking=no \
        "$kubuser@$kip" hostname
    )
done


FIRST_NODE_IP="${NODE_IPS[0]}"
FIRST_NODE_USER="${NODES_USER[$FIRST_NODE_IP]}"
FIRST_NODE_PASSWORD="${NODES[$FIRST_NODE_IP]}"
FIRST_NODE_HOSTNAME="${NODE_HOSTNAMES[$FIRST_NODE_IP]}"
FIRST_KIBANA_IP="${KIBANA_IPS[0]}"
FIRST_KIBANA_USER="${KIBANA_USERS[$FIRST_KIBANA_IP]}"
FIRST_KIBANA_PASSWORD="${KIBANA_PWS[$FIRST_KIBANA_IP]}"
KIBANA_IP="$FIRST_KIBANA_IP"
KIBANA_SSH_USER="$FIRST_KIBANA_USER"
KIBANA_SSH_PASSWORD="$FIRST_KIBANA_PASSWORD"

for src in "${NODE_IPS[@]}"; do
    src_user=${NODES_USER["$src"]}
    src_pw=${NODES["$src"]}

    for dst in "${NODE_IPS[@]}"; do
        dst_name=${NODE_HOSTNAMES["$dst"]}
        run_command "\
sshpass -p '$src_pw' ssh -o StrictHostKeyChecking=no \
'$src_user@$src' \
\"grep -q '$dst $dst_name' /etc/hosts || echo '$dst $dst_name' | sudo tee -a /etc/hosts\"\
"
    done
done

echo "Setting up first Elasticsearch node on $FIRST_NODE_HOSTNAME ($FIRST_NODE_IP)..."
if [ "$CLEAN_INSTALL" = "y" ]; then
    echo "Clean install requested. Stopping Elasticsearch and removing certificates on first node..."
    run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo systemctl stop elasticsearch.service || true'"
    run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo rm -rf /etc/elasticsearch/certs/* || true'"
    run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo rm -f /usr/share/elasticsearch/elastic-stack-ca.p12 || true'"
    run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo rm -f /etc/elasticsearch/elasticsearch.keystore || true'"
    run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo rm -rf /data/hot/elasticsearch/* || true'"
    run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo rm -rf /data/log/elasticsearch/* || true'"

    for ((i=1; i<NODE_COUNT; i++)); do
        NODE_IP="${NODE_IPS[$i]}"
        NODE_PASSWORD="${NODES[$NODE_IP]}"
        node_user="${NODES_USER[$NODE_IP]}"
        echo "Stopping Elasticsearch and removing certificates on node $i..."
        run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $node_user@$NODE_IP 'sudo systemctl stop elasticsearch.service || true'"
        run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $node_user@$NODE_IP 'sudo rm -rf /etc/elasticsearch/certs/* || true'"
        run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $node_user@$NODE_IP 'sudo rm -f /usr/share/elasticsearch/elastic-stack-ca.p12 || true'"
        run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $node_user@$NODE_IP 'sudo rm -f /etc/elasticsearch/elasticsearch.keystore || true'"
        run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $node_user@$NODE_IP 'sudo rm -rf /data/hot/elasticsearch/* || true'"
        run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $node_user@$NODE_IP 'sudo rm -rf /data/log/elasticsearch/* || true'"
    done

    run_command_continue "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_SSH_USER@$KIBANA_IP 'sudo systemctl stop kibana.service || true'"
    run_command_continue "sshpass -p '$KIBANA_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $KIBANA_SSH_USER@$KIBANA_IP 'sudo rm -rf /etc/kibana/certs/* /etc/kibana/root-ca* || true'"
    run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo systemctl stop logstash.service || true'"
    run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo rm -rf /etc/logstash/certs/* || true'"
fi

run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'command -v java &> /dev/null || (sudo apt update && sudo apt install default-jre -y)'"
run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'command -v curl &> /dev/null || sudo apt install curl -y'"
run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'command -v wget &> /dev/null || sudo apt install wget -y'"
run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'dpkg -l | grep -q gnupg || sudo apt install gnupg -y'"
run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'dpkg -l | grep -q apt-transport-https || sudo apt install apt-transport-https -y'"
run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'command -v unzip &> /dev/null || sudo apt install unzip -y'"
run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo sysctl -w vm.max_map_count=262144'"
run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'grep -q \"vm.max_map_count=262144\" /etc/sysctl.conf || sudo bash -c \"echo vm.max_map_count=262144 >> /etc/sysctl.conf\"'"
if ! check_package_installed "$FIRST_NODE_IP" "$FIRST_NODE_USER" "$FIRST_NODE_PASSWORD" "elasticsearch"; then
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'wget -q https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.3-amd64.deb'"
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo dpkg -i elasticsearch-8.17.3-amd64.deb || sudo apt --fix-broken install -y'"
fi


run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo mkdir -p /data/hot/elasticsearch /data/log/elasticsearch'"
run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo chown -R elasticsearch:elasticsearch /data/hot/elasticsearch /data/log/elasticsearch'"
run_command_continue "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo chmod 750 /data/hot/elasticsearch /data/log/elasticsearch'"
echo "Available Elasticsearch roles for first node:"
echo "1. master"
echo "2. data_hot"
echo "3. data_warm"
echo "4. data_content"
echo "5. ingest"
echo "6. ml"
echo "7. remote_cluster_client"

read -p "Enter roles for $FIRST_NODE_HOSTNAME (separate by comma like this 1,2,3): " role_numbers

selected_roles=""
IFS=',' read -ra ROLE_ARRAY <<< "$role_numbers"
for role_num in "${ROLE_ARRAY[@]}"; do
    case "$role_num" in
        1) selected_roles="${selected_roles:+$selected_roles, }master" ;;
        2) selected_roles="${selected_roles:+$selected_roles, }data_hot" ;;
        3) selected_roles="${selected_roles:+$selected_roles, }data_warm" ;;
        4) selected_roles="${selected_roles:+$selected_roles, }data_content" ;;
        5) selected_roles="${selected_roles:+$selected_roles, }ingest" ;;
        6) selected_roles="${selected_roles:+$selected_roles, }ml" ;;
        7) selected_roles="${selected_roles:+$selected_roles, }remote_cluster_client" ;;
    esac
done

if [[ "$selected_roles" != *"master"* ]]; then
    if [ -z "$selected_roles" ]; then
        selected_roles="master"
    else
        selected_roles="master, $selected_roles"
    fi
    echo "Added master role to first node as it's required"
fi

SEED_HOSTS=""
for NODE_IP in "${NODE_IPS[@]}"; do
    if [ -z "$SEED_HOSTS" ]; then
        SEED_HOSTS="\"$NODE_IP\""
    else
        SEED_HOSTS="$SEED_HOSTS, \"$NODE_IP\""
    fi
done

INITIAL_MASTER_NODES='"'$FIRST_NODE_HOSTNAME'"'

CLUSTER_ALREADY_RUNNING=false
if [ "$CLEAN_INSTALL" != "y" ]; then
    if sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP "systemctl is-active --quiet elasticsearch"; then
        echo "Elasticsearch service is already running on the first node."
        read -s -p "Enter the current 'elastic' user password for existing cluster: " ELASTIC_PASSWORD
        echo
        CLUSTER_ALREADY_RUNNING=true
    fi
fi

if [ "$CLUSTER_ALREADY_RUNNING" = false ]; then
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo systemctl stop elasticsearch.service || true'"
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch'"
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo chmod 750 /etc/elasticsearch'"
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo rm -f /etc/elasticsearch/elasticsearch.keystore || true'"
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-keystore create'"
    echo "Generating certificates for the cluster..."
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP \"
        sudo systemctl stop elasticsearch.service || true
        sudo rm -rf /etc/elasticsearch/certs/*
        sudo mkdir -p /etc/elasticsearch/certs
        sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil ca --out /etc/elasticsearch/certs/elastic-stack-ca.p12 --pass '$CERT_PASSWORD' --days 3650 --silent
        sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca /etc/elasticsearch/certs/elastic-stack-ca.p12 --ca-pass '$CERT_PASSWORD' --name $FIRST_NODE_HOSTNAME --dns $FIRST_NODE_HOSTNAME,$FIRST_NODE_IP --ip $FIRST_NODE_IP --out /etc/elasticsearch/certs/elastic-certificates.p12 --pass '$CERT_PASSWORD' --days 3650 --silent
        sudo -u elasticsearch cp /etc/elasticsearch/certs/elastic-certificates.p12 /etc/elasticsearch/certs/http.p12
        sudo -u elasticsearch cp /etc/elasticsearch/certs/elastic-certificates.p12 /etc/elasticsearch/certs/transport.p12
        sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca /etc/elasticsearch/certs/elastic-stack-ca.p12 --ca-pass 'changeme' --pem --silent --out /tmp/ca.zip
        cd /tmp && sudo -u elasticsearch unzip -o ca.zip
        sudo -u elasticsearch cp /tmp/instance/instance.crt /etc/elasticsearch/certs/http_ca.crt
        sudo chmod -R 750 /etc/elasticsearch/certs
        echo 'Certificate files:'
        sudo ls -la /etc/elasticsearch/certs/
    \""

    rm -rf /tmp/es-certs
    mkdir -p /tmp/es-certs

    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP \
      \"sudo cp /etc/elasticsearch/certs/elastic-stack-ca.p12 /etc/elasticsearch/certs/http_ca.crt /tmp/ && \
       sudo chown $FIRST_NODE_USER:$FIRST_NODE_USER /tmp/elastic-stack-ca.p12 /tmp/http_ca.crt\""
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' scp -o StrictHostKeyChecking=no \
      $FIRST_NODE_USER@$FIRST_NODE_IP:/tmp/elastic-stack-ca.p12 /tmp/es-certs/"
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' scp -o StrictHostKeyChecking=no \
      $FIRST_NODE_USER@$FIRST_NODE_IP:/tmp/http_ca.crt     /tmp/es-certs/"
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP \
      \"rm -f /tmp/elastic-stack-ca.p12 /tmp/http_ca.crt\""

    echo "Configuring first node"
    cat > /tmp/elasticsearch.yml << EOF
cluster.name: ${CLUSTER_NAME}
node.name: ${FIRST_NODE_HOSTNAME}
path.data: /data/hot/elasticsearch
path.logs: /data/log/elasticsearch
network.host: ${FIRST_NODE_IP}
http.port: 9200
transport.port: 9300
node.roles: [ ${selected_roles} ]
discovery.seed_hosts: [ ${SEED_HOSTS} ]
cluster.initial_master_nodes: [ "${FIRST_NODE_HOSTNAME}" ]
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: /etc/elasticsearch/certs/transport.p12
xpack.security.transport.ssl.keystore.password: ${CERT_PASSWORD}
xpack.security.transport.ssl.truststore.path: /etc/elasticsearch/certs/transport.p12
xpack.security.transport.ssl.truststore.password: ${CERT_PASSWORD}
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: /etc/elasticsearch/certs/http.p12
xpack.security.http.ssl.keystore.password: ${CERT_PASSWORD}
http.host: 0.0.0.0
transport.host: 0.0.0.0
EOF

run_command "cat /tmp/elasticsearch.yml | sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo tee /tmp/elasticsearch.yml > /dev/null'"
run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo cp /tmp/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml'"
run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo chown elasticsearch:elasticsearch /etc/elasticsearch/elasticsearch.yml'"
run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo systemctl daemon-reload'"
run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo systemctl enable elasticsearch.service'"
run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo systemctl restart elasticsearch.service'"


    echo "waiting 1min for elasticsearch to start..."
    sleep 60

    echo "Setting elastic user password..."
    ELASTIC_PASSWORD_OUTPUT=$(sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP "sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b")

    if [[ $ELASTIC_PASSWORD_OUTPUT == *"New value"* ]]; then
        ELASTIC_PASSWORD=$(echo "$ELASTIC_PASSWORD_OUTPUT" | grep -oP 'New value: \K.*')
        echo "Elastic password has been reset and stored in /tmp/elk_secure_credentials.txt; please retrieve and secure it within 24 hours before it expires."
        echo "elastic:$ELASTIC_PASSWORD" | sudo tee /tmp/elk_secure_credentials.txt > /dev/null
        chmod 600 /tmp/elk_secure_credentials.txt
    else
        echo "Failed to reset password automatically. Please check server logs."
        read -s -p "Enter the elastic password manually: " ELASTIC_PASSWORD
        echo
        echo "elastic:$ELASTIC_PASSWORD" | sudo tee /tmp/elk_secure_credentials.txt > /dev/null
        chmod 600 /tmp/elk_secure_credentials.txt
    fi

    echo "Setting kibana_system user password..."
    KIBANA_PASSWORD_OUTPUT=$(sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP "sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -b")

    if [[ $KIBANA_PASSWORD_OUTPUT == *"New value"* ]]; then
        KIBANA_PASSWORD=$(echo "$KIBANA_PASSWORD_OUTPUT" | grep -oP 'New value: \K.*')
        echo "Kibana password also been reset and stored in /tmp/elk_secure_credentials.txt; please retrieve and secure it within 24 hours before it expires."
        echo "kibana_system:$KIBANA_PASSWORD" | sudo tee -a /tmp/elk_secure_credentials.txt > /dev/null
    else
        echo "Failed to reset kibana_system password. Please check server logs."
        read -s -p "Enter the kibana_system password manually: " KIBANA_PASSWORD
        echo
        echo "kibana_system:$KIBANA_PASSWORD" | sudo tee -a /tmp/elk_secure_credentials.txt > /dev/null
    fi
else

    echo "Using existing Elasticsearch cluster."

    read -s -p "Enter the current 'kibana_system' user password for existing cluster (or press Enter to reset it): " KIBANA_PASSWORD
    echo
    if [ -z "$KIBANA_PASSWORD" ]; then
        echo "Resetting kibana_system user password..."
        KIBANA_PASSWORD_OUTPUT=$(sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP "sudo /usr/share/elasticsearch/bin/elasticsearch-reset-password -u kibana_system -b")

        if [[ $KIBANA_PASSWORD_OUTPUT == *"New value"* ]]; then
            KIBANA_PASSWORD=$(echo "$KIBANA_PASSWORD_OUTPUT" | grep -oP 'New value: \K.*')
            echo "Kibana system password successfully reset and stored."
            echo "kibana_system:$KIBANA_PASSWORD" | sudo tee -a /tmp/elk_secure_credentials.txt > /dev/null
            chmod 600 /tmp/elk_secure_credentials.txt
        else
            echo "Failed to reset kibana_system password. Please check server logs."
            read -s -p "Enter the kibana_system password manually: " KIBANA_PASSWORD
            echo
            echo "kibana_system:$KIBANA_PASSWORD" | sudo tee -a /tmp/elk_secure_credentials.txt > /dev/null
            chmod 600 /tmp/elk_secure_credentials.txt
        fi
    else
        echo "elastic:$ELASTIC_PASSWORD" | sudo tee /tmp/elk_secure_credentials.txt > /dev/null
        echo "kibana_system:$KIBANA_PASSWORD" | sudo tee -a /tmp/elk_secure_credentials.txt > /dev/null
        chmod 600 /tmp/elk_secure_credentials.txt
    fi

    rm -rf /tmp/es-certs
    mkdir -p /tmp/es-certs
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo cat /etc/elasticsearch/certs/elastic-stack-ca.p12' > /tmp/es-certs/elastic-stack-ca.p12"
    run_command "sshpass -p '$FIRST_NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP 'sudo cat /etc/elasticsearch/certs/http_ca.crt'   > /tmp/es-certs/http_ca.crt"
fi

for ((i=1; i<NODE_COUNT; i++)); do
    NODE_IP="${NODE_IPS[$i]}"
    NODE_USER="${NODES_USER[$NODE_IP]}"
    NODE_PASSWORD=${NODES["$NODE_IP"]}
    NODE_HOSTNAME=${NODE_HOSTNAMES["$NODE_IP"]}

    echo "Setting up Elasticsearch on additional node $NODE_HOSTNAME ($NODE_IP)..."
    run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'command -v java &> /dev/null || (sudo apt update && sudo apt install default-jre -y)'"
    run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'command -v curl &> /dev/null || sudo apt install curl -y'"
    run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'command -v wget &> /dev/null || sudo apt install wget -y'"
    run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'dpkg -l | grep -q gnupg || sudo apt install gnupg -y'"
    run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'dpkg -l | grep -q apt-transport-https || sudo apt install apt-transport-https -y'"
    run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'command -v unzip &> /dev/null || sudo apt install unzip -y'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo sysctl -w vm.max_map_count=262144'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'grep -q \"vm.max_map_count=262144\" /etc/sysctl.conf || sudo bash -c \"echo vm.max_map_count=262144 >> /etc/sysctl.conf\"'"
    if ! check_package_installed "$NODE_IP" "$NODE_USER" "$NODE_PASSWORD" "elasticsearch"; then
        run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'wget -q https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.17.3-amd64.deb'"
        run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo dpkg -i elasticsearch-8.17.3-amd64.deb || sudo apt --fix-broken install -y'"
    fi

    run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo mkdir -p /data/hot/elasticsearch /data/log/elasticsearch'"
    run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo chown -R elasticsearch:elasticsearch /data/hot/elasticsearch /data/log/elasticsearch'"
    run_command_continue "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo chmod 750 /data/hot/elasticsearch /data/log/elasticsearch'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo systemctl stop elasticsearch.service || true'"

    echo "Available Elasticsearch roles for node $NODE_HOSTNAME:"
    echo "1. master"
    echo "2. data_hot"
    echo "3. data_warm"
    echo "4. data_content"
    echo "5. ingest"
    echo "6. ml"
    echo "7. remote_cluster_client"

    read -p "Enter roles for $NODE_HOSTNAME (separated with comma 1,2,3): " role_numbers

    selected_roles=""
    IFS=',' read -ra ROLE_ARRAY <<< "$role_numbers"
    for role_num in "${ROLE_ARRAY[@]}"; do
        case "$role_num" in
            1) selected_roles="${selected_roles:+$selected_roles, }master" ;;
            2) selected_roles="${selected_roles:+$selected_roles, }data_hot" ;;
            3) selected_roles="${selected_roles:+$selected_roles, }data_warm" ;;
            4) selected_roles="${selected_roles:+$selected_roles, }data_content" ;;
            5) selected_roles="${selected_roles:+$selected_roles, }ingest" ;;
            6) selected_roles="${selected_roles:+$selected_roles, }ml" ;;
            7) selected_roles="${selected_roles:+$selected_roles, }remote_cluster_client" ;;
        esac
    done

    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo chmod 750 /etc/elasticsearch'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo rm -f /etc/elasticsearch/elasticsearch.keystore || true'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-keystore create'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo mkdir -p /etc/elasticsearch/certs'"
    run_command "sshpass -p '$NODE_PASSWORD' scp -o StrictHostKeyChecking=no /tmp/es-certs/elastic-stack-ca.p12 $NODE_USER@$NODE_IP:/tmp/"
    run_command "sshpass -p '$NODE_PASSWORD' scp -o StrictHostKeyChecking=no /tmp/es-certs/http_ca.crt $NODE_USER@$NODE_IP:/tmp/"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo mv /tmp/elastic-stack-ca.p12 /etc/elasticsearch/certs/ && sudo mv /tmp/http_ca.crt /etc/elasticsearch/certs/'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo chown elasticsearch:elasticsearch /etc/elasticsearch/certs/elastic-stack-ca.p12 && sudo chmod 644 /etc/elasticsearch/certs/elastic-stack-ca.p12'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP \"
        sudo -u elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca /etc/elasticsearch/certs/elastic-stack-ca.p12 --ca-pass '$CERT_PASSWORD' --name $NODE_HOSTNAME --dns $NODE_HOSTNAME,$NODE_IP --ip $NODE_IP --out /etc/elasticsearch/certs/elastic-certificates.p12 --pass '$CERT_PASSWORD' --days 3650 --silent
        sudo -u elasticsearch cp /etc/elasticsearch/certs/elastic-certificates.p12 /etc/elasticsearch/certs/http.p12
        sudo -u elasticsearch cp /etc/elasticsearch/certs/elastic-certificates.p12 /etc/elasticsearch/certs/transport.p12
        sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch/certs
        sudo chmod -R 750 /etc/elasticsearch/certs
    \""

    cat > /tmp/elasticsearch.yml << EOF
cluster.name: ${CLUSTER_NAME}
node.name: ${NODE_HOSTNAME}
path.data: /data/hot/elasticsearch
path.logs: /data/log/elasticsearch
network.host: ${NODE_IP}
http.port: 9200
transport.port: 9300
node.roles: [ ${selected_roles} ]

discovery.seed_hosts: [ ${SEED_HOSTS} ]

xpack.security.enabled: true

xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: /etc/elasticsearch/certs/transport.p12
xpack.security.transport.ssl.keystore.password: ${CERT_PASSWORD}
xpack.security.transport.ssl.truststore.path: /etc/elasticsearch/certs/transport.p12
xpack.security.transport.ssl.truststore.password: ${CERT_PASSWORD}

# SSL/TLS
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: /etc/elasticsearch/certs/http.p12
xpack.security.http.ssl.keystore.password: ${CERT_PASSWORD}

http.host: 0.0.0.0
transport.host: 0.0.0.0
EOF

    run_command "cat /tmp/elasticsearch.yml | sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo tee /tmp/elasticsearch.yml > /dev/null'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo cp /tmp/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo chown elasticsearch:elasticsearch /etc/elasticsearch/elasticsearch.yml'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo systemctl daemon-reload'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo systemctl enable elasticsearch.service'"
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo systemctl restart elasticsearch.service'"

    echo "Node $NODE_HOSTNAME configured successfully!"
done

echo "Waiting 90 seconds for all Elasticsearch nodes to join the cluster..."
sleep 90
for kip in "${KIBANA_IPS[@]}"; do
    kub_user="${KIBANA_USERS[$kip]}"
    kpw=${KIBANA_PWS["$kip"]}
    khost=${KIBANA_HOSTNAMES["$kip"]}

    if [[ "$CLEAN_INSTALL" == "y" ]]; then
        run_command_continue "sshpass -p '$kpw' ssh -o StrictHostKeyChecking=no $kub_user@$kip 'sudo systemctl stop kibana.service || true && sudo rm -rf /etc/kibana/certs/* /etc/kibana/root-ca*'"
    fi

    run_command_continue "sshpass -p '$kpw' ssh -o StrictHostKeyChecking=no $kub_user@$kip 'sudo apt-get update -qq && sudo apt-get install -y curl wget gnupg apt-transport-https unzip default-jre -qq'"

if ! check_package_installed "$kip" "$kub_user" "$kpw" "kibana"; then
    run_command "sshpass -p '$kpw' ssh -o StrictHostKeyChecking=no $kub_user@$kip 'wget -q https://artifacts.elastic.co/downloads/kibana/kibana-8.17.3-amd64.deb && sudo dpkg -i kibana-8.17.3-amd64.deb || sudo apt --fix-broken install -y'"
fi
if ! check_file_exists "$kip" "$kub_user" "$kpw" "/etc/kibana/root-ca-key.pem"; then
    run_command "sshpass -p '$kpw' ssh -o StrictHostKeyChecking=no $kub_user@$kip 'sudo mkdir -p /etc/kibana/certs && \
        sudo openssl genrsa -out /etc/kibana/root-ca-key.pem 2048 && \
        sudo openssl req -days 9000 -new -x509 -sha256 -key /etc/kibana/root-ca-key.pem -out /etc/kibana/root-ca.pem -subj \"/CN=$khost\" && \
        sudo chown -R kibana:kibana /etc/kibana/root-ca-key.pem /etc/kibana/root-ca.pem && sudo chmod 640 /etc/kibana/root-ca-key.pem /etc/kibana/root-ca.pem'"
fi

    run_command "cat /tmp/es-certs/http_ca.crt | sshpass -p '$kpw' ssh -o StrictHostKeyChecking=no $kub_user@$kip 'sudo tee /etc/kibana/elasticsearch-ca.pem > /dev/null && sudo chown kibana:kibana /etc/kibana/elasticsearch-ca.pem'"

    run_command "sshpass -p '$kpw' ssh -o StrictHostKeyChecking=no $kub_user@$kip '\
      while [ ! -x /usr/share/kibana/bin/kibana-encryption-keys ]; do sleep 3; done'"

    ENCKEYS=$(sshpass -p "$kpw" ssh -o StrictHostKeyChecking=no $kub_user@$kip "\
      sudo -u kibana /usr/share/kibana/bin/kibana-encryption-keys generate --force")
    ENC=$(echo "$ENCKEYS" | awk -F': ' '/encryptedSavedObjects/{print $2}'      | tr -d '\r\n')
    REP=$(echo "$ENCKEYS" | awk -F': ' '/xpack.reporting.encryptionKey/{print $2}' | tr -d '\r\n')
    SEC=$(echo "$ENCKEYS" | awk -F': ' '/xpack.security.encryptionKey/{print $2}'  | tr -d '\r\n')
    ES_HOSTS=""
    for esip in "${NODE_IPS[@]}"; do
        ES_HOSTS+="${ES_HOSTS:+, }\"https://${esip}:9200\""
    done

    cat > /tmp/kibana-node.yml <<EOF
server.port: 5601
server.host: "0.0.0.0"
server.ssl.enabled: true
server.ssl.certificate: /etc/kibana/root-ca.pem
server.ssl.key: /etc/kibana/root-ca-key.pem

elasticsearch.hosts: [${ES_HOSTS}]
elasticsearch.username: "kibana_system"
elasticsearch.password: "${KIBANA_PASSWORD}"
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/elasticsearch-ca.pem"]
elasticsearch.ssl.verificationMode: none

logging:
  appenders:
    file:
      type: file
      fileName: /var/log/kibana/kibana.log
      layout:
        type: json
  root:
    appenders: [default, file]

xpack.encryptedSavedObjects.encryptionKey: ${ENC}
xpack.reporting.encryptionKey: ${REP}
xpack.security.encryptionKey: ${SEC}
EOF

    run_command "cat /tmp/kibana-node.yml | sshpass -p '$kpw' ssh -o StrictHostKeyChecking=no $kub_user@$kip 'sudo tee /etc/kibana/kibana.yml > /dev/null && sudo chown kibana:kibana /etc/kibana/kibana.yml'"
    run_command "sshpass -p '$kpw' ssh -o StrictHostKeyChecking=no $kub_user@$kip 'sudo systemctl daemon-reload && sudo systemctl enable kibana && sudo systemctl restart kibana'"
done

if ! $LOGSTASH_SKIP; then
   if [ "$CLEAN_INSTALL" = "y" ]; then
    echo "Clean install requested. Stopping Logstash and removing certificates..."
    run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo systemctl stop logstash.service || true'"
    run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo rm -rf /etc/logstash/certs/* || true'"
    run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo rm -rf /etc/logstash/conf.d/* || true'"
fi

run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'command -v java &> /dev/null || (sudo apt update && sudo apt install default-jre -y)'"

run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'command -v curl &> /dev/null || sudo apt install curl -y'"
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'command -v wget &> /dev/null || sudo apt install wget -y'"
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'dpkg -l | grep -q gnupg || sudo apt install gnupg -y'"
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'dpkg -l | grep -q apt-transport-https || sudo apt install apt-transport-https -y'"
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'command -v unzip &> /dev/null || sudo apt install unzip -y'"
LOGSTASH_ALREADY_INSTALLED=false
if check_package_installed "$LOGSTASH_IP" "$LOGSTASH_USER" "$LOGSTASH_SSH_PASSWORD" "logstash"; then
    LOGSTASH_ALREADY_INSTALLED=true
else
    run_command "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'wget -q https://artifacts.elastic.co/downloads/logstash/logstash-8.17.3-amd64.deb'"
    run_command "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo dpkg -i logstash-8.17.3-amd64.deb || sudo apt --fix-broken install -y'"
fi
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo mkdir -p /logstash/data/logstash'"
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo chown -R logstash:logstash /logstash/data/logstash'"
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo chmod 750 /logstash/data/logstash'"

if ! check_file_exists "$LOGSTASH_IP" "$LOGSTASH_USER" "$LOGSTASH_SSH_PASSWORD" "/etc/logstash/certs/http_ca.crt"; then
    run_command "cat /tmp/es-certs/http_ca.crt | sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP \
      'sudo tee /etc/logstash/certs/http_ca.crt > /dev/null && sudo chown logstash:logstash /etc/logstash/certs/http_ca.crt'"
fi
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'grep -q \"path.data: /logstash/data/logstash\" /etc/logstash/logstash.yml || echo \"path.data: /logstash/data/logstash
path.logs: /var/log/logstash\" | sudo tee /etc/logstash/logstash.yml'"
if ! check_file_exists "$LOGSTASH_IP" "$LOGSTASH_USER" "$LOGSTASH_SSH_PASSWORD" "/etc/logstash/certs/logstash.crt"; then
    run_command "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/logstash/certs/logstash.key -out /etc/logstash/certs/logstash.crt -subj \"/CN=$LOGSTASH_HOSTNAME\"'"
    run_command "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo chown -R logstash:logstash /etc/logstash/certs'"
    run_command "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo chmod 644 /etc/logstash/certs/logstash.crt'"
    run_command "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo chmod 600 /etc/logstash/certs/logstash.key'"
fi
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo mkdir -p /etc/logstash/conf.d'"
cat > /tmp/01-beats-input.conf << EOF
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/logstash/certs/logstash.crt"
    ssl_key => "/etc/logstash/certs/logstash.key"
  }
}
EOF
run_command "cat /tmp/01-beats-input.conf | sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP \
  'sudo tee /etc/logstash/conf.d/01-beats-input.conf > /dev/null && sudo chown logstash:logstash /etc/logstash/conf.d/01-beats-input.conf'"
cat > /tmp/01-syslog-input.conf << EOF
input {
  tcp {
    port => 5140
    type => "syslog"
  }
  udp {
    port => 5140
    type => "syslog"
  }
}
EOF
run_command "cat /tmp/01-syslog-input.conf | sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP \
  'sudo tee /etc/logstash/conf.d/01-syslog-input.conf > /dev/null && sudo chown logstash:logstash /etc/logstash/conf.d/01-syslog-input.conf'"
ES_HOSTS_LIST=""
for NODE_IP in "${NODE_IPS[@]}"; do
    if [ -z "$ES_HOSTS_LIST" ]; then
        ES_HOSTS_LIST="\"https://$NODE_IP:9200\""
    else
        ES_HOSTS_LIST="$ES_HOSTS_LIST, \"https://$NODE_IP:9200\""
    fi
done

cat > /tmp/30-output.conf << EOF
output {
  elasticsearch {
    hosts => [ $ES_HOSTS_LIST ]
    user => "elastic"
    password => "$ELASTIC_PASSWORD"
    ssl => true
    ssl_certificate_verification => false
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
  }
}
EOF

run_command "cat /tmp/30-output.conf | sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP \
  'sudo tee /etc/logstash/conf.d/30-output.conf > /dev/null && sudo chown logstash:logstash /etc/logstash/conf.d/30-output.conf'"

cat > /tmp/pipelines.yml << EOF
- pipeline.id: main
  path.config: "/etc/logstash/conf.d/*.conf"
EOF

run_command "cat /tmp/pipelines.yml | sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP \
  'sudo tee /etc/logstash/pipelines.yml > /dev/null && sudo chown logstash:logstash /etc/logstash/pipelines.yml'"
run_command_continue "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t'"
run_command "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo systemctl daemon-reload'"
run_command "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo systemctl enable logstash.service'"
run_command "sshpass -p '$LOGSTASH_SSH_PASSWORD' ssh -o StrictHostKeyChecking=no $LOGSTASH_USER@$LOGSTASH_IP 'sudo systemctl restart logstash.service'"

fi

read -p "Enter the IP address of the NFS server: " NFS_SERVER_IP
read -p "Enter SSH user for the NFS server: " NFS_SERVER_USER
read -s -p "Enter SSH password for the NFS server: " NFS_SERVER_PASSWORD; echo

echo "Setting up NFS Server on $NFS_SERVER_IP..."
run_command "sshpass -p '$NFS_SERVER_PASSWORD' ssh -o StrictHostKeyChecking=no $NFS_SERVER_USER@$NFS_SERVER_IP 'dpkg -l | grep -q nfs-kernel-server || (sudo apt update && sudo apt install nfs-kernel-server -y)'"
run_command "sshpass -p '$NFS_SERVER_PASSWORD' ssh -o StrictHostKeyChecking=no $NFS_SERVER_USER@$NFS_SERVER_IP 'sudo mkdir -p /var/nfs/elasticsearch'"

EXPORTS_CONFIG="/var/nfs/elasticsearch"
for NODE_IP in "${NODE_IPS[@]}"; do
    EXPORTS_CONFIG="$EXPORTS_CONFIG $NODE_IP(rw,sync,no_root_squash,no_subtree_check)"
done

run_command "sshpass -p '$NFS_SERVER_PASSWORD' ssh -o StrictHostKeyChecking=no $NFS_SERVER_USER@$NFS_SERVER_IP \"echo '$EXPORTS_CONFIG' | sudo tee /etc/exports\""
run_command "sshpass -p '$NFS_SERVER_PASSWORD' ssh -o StrictHostKeyChecking=no $NFS_SERVER_USER@$NFS_SERVER_IP 'sudo systemctl restart nfs-kernel-server'"

echo "Setting up NFS Clients on all Elasticsearch nodes..."

for NODE_IP in "${NODE_IPS[@]}"; do
    NODE_PASSWORD=${NODES["$NODE_IP"]}
    NODE_USER=${NODES_USER["$NODE_IP"]}
    NODE_HOSTNAME=${NODE_HOSTNAMES["$NODE_IP"]}

    echo "Configuring NFS client on $NODE_HOSTNAME ($NODE_IP)..."

    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'dpkg -l | grep -q nfs-common || (sudo apt update && sudo apt install nfs-common -y)'"

    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo mkdir -p /var/nfs/elasticsearch'"

    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'grep -q \"$NFS_SERVER_IP:/var/nfs/elasticsearch\" /proc/mounts || sudo mount $NFS_SERVER_IP:/var/nfs/elasticsearch /var/nfs/elasticsearch'"

    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP \"grep -q '$NFS_SERVER_IP:/var/nfs/elasticsearch' /etc/fstab || echo '$NFS_SERVER_IP:/var/nfs/elasticsearch /var/nfs/elasticsearch nfs4 rw,_netdev,tcp 0 0' | sudo tee -a /etc/fstab\""

    # test
    if [ "$NODE_IP" == "${NODE_IPS[0]}" ]; then
        run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo touch /var/nfs/elasticsearch/test-$(date +%s).txt'"
    fi
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo chown -R elasticsearch:elasticsearch /var/nfs/elasticsearch'"
done

echo "Configuring ES for NFS Backup"


for NODE_IP in "${NODE_IPS[@]}"; do
    NODE_PASSWORD=${NODES["$NODE_IP"]}
    NODE_USER=${NODES_USER["$NODE_IP"]}
    NODE_HOSTNAME=${NODE_HOSTNAMES["$NODE_IP"]}

    echo "Configuring elasticsearch.yml on $NODE_HOSTNAME ($NODE_IP)..."

    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP \"sudo grep -q 'path.repo' /etc/elasticsearch/elasticsearch.yml || echo 'path.repo: [\"/var/nfs\"]' | sudo tee -a /etc/elasticsearch/elasticsearch.yml\""
    run_command "sshpass -p '$NODE_PASSWORD' ssh -o StrictHostKeyChecking=no $NODE_USER@$NODE_IP 'sudo systemctl restart elasticsearch.service'"
done
echo "Waiting for Elasticsearch to restart with new config..."
sleep 30
echo "NFS backup system is all set up!"
echo "You can now create snapshot repositories via Kibana UI under Stack Management > Snapshot and Restore"
echo
echo "==================  Elasticsearch licence  =================="
echo " 1) Upload existing licence JSON"
echo " 2) Start 30‑day trial licence"
echo " 3) Keep basic (default)"
read -p "Choose 1 / 2 / 3 : " LIC_OPT
case "$LIC_OPT" in
  1)
     read -p "Path to local licence JSON file: " LIC_PATH
     if [[ ! -f "$LIC_PATH" ]]; then
         echo "File not found – skipping."
     else
         echo "Uploading licence ..."
         sshpass -p "$FIRST_NODE_PASSWORD" scp -o StrictHostKeyChecking=no "$LIC_PATH" $FIRST_NODE_USER@$FIRST_NODE_IP:/tmp/lic.json
         sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP \
           "curl -k -u elastic:${ELASTIC_PASSWORD} -XPUT -H 'Content-Type: application/json' --data @/tmp/lic.json https://localhost:9200/_license"
     fi
     ;;
  2)
     echo "Requesting trial licence ..."
     sshpass -p "$FIRST_NODE_PASSWORD" ssh -o StrictHostKeyChecking=no $FIRST_NODE_USER@$FIRST_NODE_IP \
       "curl -k -u elastic:${ELASTIC_PASSWORD} -XPOST 'https://localhost:9200/_license/start_trial?acknowledge=true'"
     ;;
  *)
     echo "basic licence retained."
     ;;
esac

cat <<EOF

-------------------------------------------------------------
  Kibana URL  :  https://${KIBANA_IPS[0]}:5601
  Credentials :  see /tmp/elk_secure_credentials.txt
-------------------------------------------------------------
Thank you for using my script!
Full log is written to:
  $LOG_FILE
be sure to retrieve it from /tmp before it’s automatically cleared after 24h
-------------------------------------------------------------

EOF
