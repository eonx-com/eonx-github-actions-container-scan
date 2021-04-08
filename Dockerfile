FROM ubuntu:18.04

# Install Docker
RUN apt update; \
    DEBIAN_FRONTEND=noninteractive apt install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        software-properties-common; \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -; \
    DEBIAN_FRONTEND=noninteractive add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"; \
    apt update; \
    DEBIAN_FRONTEND=noninteractive apt install -y \
        docker-ce;

# Install Docker Compose
RUN curl -L https://github.com/docker/compose/releases/download/1.21.2/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose; \
    chmod +x /usr/local/bin/docker-compose;

# Install Python3/Pip
RUN DEBIAN_FRONTEND=noninteractive apt install -y \
        python3 \
        python3-pip;

# Setup container scanning containers
COPY ./clair/docker-compose.yaml /opt/clair/

# Setup scan result parsing script
COPY ./scan-parser/requirements.txt /opt/scan-parser/requirements.txt
RUN pip3 install -r /opt/scan-parser/requirements.txt
COPY ./scan-parser/main.py /opt/scan-parser/main.py
RUN chmod +x /opt/scan-parser/main.py

# Setup entrypoint
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh
ENTRYPOINT ["/opt/entrypoint.sh"]