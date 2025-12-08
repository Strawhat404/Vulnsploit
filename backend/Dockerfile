FROM python:3.11-slim

# Keep Python output unbuffered (helps with logging)
ENV PYTHONUNBUFFERED=1

# Set working directory inside the container
WORKDIR /app

#install system dependencies

RUN apt-get update && apt-get install -y nmap wget unzip git ruby ruby-dev build-essential libcurl4-openssl-dev && apt-get clean

#Install WhatWeb (from source)
RUN git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && gem install addressable \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb
# Install Nikto (from source)
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install SQLMap (from source)
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install Subfinder
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip subfinder_2.6.6_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.6_linux_amd64.zip

# Install Gobuster
RUN wget https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
    && tar -xzvf gobuster_Linux_x86_64.tar.gz \
    && mv gobuster /usr/local/bin/ \
    && rm gobuster_Linux_x86_64.tar.gz


# Download Wordlist (SecLists common.txt)
RUN mkdir -p /usr/share/wordlists \
    && wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O /usr/share/wordlists/common.txt

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip \
    && unzip -o nuclei_3.2.9_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.2.9_linux_amd64.zip


#install WPSCan
RUN gem install wpscan
RUN wpscan --update
# Copy only requirements first so we can take advantage of Docker cache
COPY requirements.txt .

# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the backend source into the container
COPY . .

# Default command when container starts (we'll override in docker-compose)
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py runserver 0.0.0.0:8000"]
