FROM python:3.10-slim
RUN apt-get update && \
    apt-get install -y \
    curl \
    sudo \
    pkg-config \
    libcurl4-openssl-dev \
    libsystemd-dev \
    build-essential \
    dbus \
    libdbus-1-dev \
    libcairo2-dev \
    libcups2-dev \
    libssl-dev \
    arp-scan\
    libpcap\
    libpcap-dev\
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app01

# 复制项目文件到工作目录
COPY . /app01
COPY ALL_Packets /app01
COPY ARP_Packets /app01
COPY datalink_type /app01
COPY gain_Information /app01
COPY ICMP_Packets /app01
COPY IP_Packets /app01
COPY TCP_Packets /app01
COPY UDP_Packets /app01
COPY Ethernet_Packets /app01
RUN echo "/usr/lib/x86_64-linux-gnu" > /etc/ld.so.conf.d/libpcap.conf && ldconfig
# 设置清华 pip 镜像
ENV PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
ENV PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn

COPY requirements.txt .

# 安装 pip 依赖
RUN pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple


# 设置环境变量
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
# 启动 Django 服务器
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

