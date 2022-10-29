FROM python:3

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir paramiko && \
    pip install --no-cache-dir PyYML && \
    pip install --no-cache-dir paho-mqtt && \
	pip install --no-cache-dir requests
COPY . .

ENTRYPOINT ["python", "main.py"]