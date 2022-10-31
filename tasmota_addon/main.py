import yaml
import paramiko
import re
import time
import random
import requests
from paho.mqtt import client as mqtt_client


def yaml_parse():
    with open("/data/options.json", "r") as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)


def ssh_connect(need_to_send_commands=False):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ssh_ip,
                       username=ssh_username,
                       password=ssh_password,
                       look_for_keys=False,
                       allow_agent=False)
        print("\033[32m{}".format(f"Connected via SSH {ssh_ip}"))
        if(need_to_send_commands):
            commands_4_RT = ssh_command
            for line in commands_4_RT:
                stdin, stdout, stderr = client.exec_command(line)
                print("\033[32m{}".format(f"Command '{line}' sent successfully!"))
                print("\033[0m{}".format(stdout.read().decode('ascii')))
                time.sleep(0.1)
        client.close()
    except Exception:
        print("\033[31m{}".format(f"Connect via SSH went wrong!"))
        return False
    return True


def is_input_correct():
    global cfg, has_ip, device_ip, wifi_ssid, wifi_pass, \
        ssh_ip, ssh_username, ssh_password, ssh_command
    cfg = yaml_parse()
    ssh_ip = cfg['ssh_ip']
    ssh_username = cfg['ssh_username']
    ssh_password = cfg['ssh_password']
    ssh_command = cfg['ssh_command']
    device_ip = cfg['device_ip']
    wifi_ssid = cfg['wifi_ssid']
    wifi_pass = cfg['wifi_pass']
    log = []
    has_ip = False
    if device_ip is not None:
        for ip in device_ip:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                has_ip = True
            else:
                log.append(f'device_ip: "{ip}" is not correct!')
    else:
        device_ip = []

    if cfg['send_with'] == "MQTT" or has_ip == False:
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cfg['mqtt_broker']) or len(cfg['mqtt_port']) == 0:
            log.append('mqtt_broker is not correct!')

    if len(log) > 0:
        print("\033[31m{}".format(log))

    return len(log) == 0


def http_send_request(need_to_send_commands=False):
    if not has_ip:
        if len(data) == 0:
            print("\033[31m{}".format("ip addresses not found"))
            return
        for d in data:
            device_ip.append(d['ip'])
    print("\033[32m{}".format("Start sending requests via HTTP"))
    for ip in device_ip:
        try:
            if(need_to_send_commands):
                response = requests.get(url=f"http://{ip}/wi?s1={wifi_ssid}&p1={wifi_pass}&save=")
            else:
                response = requests.get(url=f"http://{ip}/")
            if response.status_code == 200:
                print("\033[32m{}".format(f"Request sent to {ip} successfully"))
                time.sleep(0.1)
        except Exception:
            print("\033[31m{}".format(f"{ip} is not responding"))


def connect_mqtt() -> mqtt_client:
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("\033[32m{}".format("Connected to MQTT Broker!"))
        elif rc == 5:
            print("\033[31m{}".format("Failed to connect MQTT, not authorized"))
        else:
            print("\033[31m{}".format("Failed to connect MQTT"))

    global broker, topic

    broker = cfg['mqtt_broker']
    topic = "tasmota/discovery"
    username = cfg['mqtt_username']
    password = cfg['mqtt_password']
    mqtt_port = int(cfg['mqtt_port'])
    client_id = f'python-mqtt-{random.randint(0, 1000)}'
    client = mqtt_client.Client(client_id)
    client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.connect(broker, mqtt_port)
    return client


def publish(topic, command, client):
    time.sleep(1)
    result = client.publish(topic, command)
    status = result[0]
    if status == 0:
        print("\033[32m{}".format(f"Send `{command}` to topic `{topic}`"))
    else:
        print("\033[31m{}".format(f"Failed to send '{command}' to topic {topic}"))


def getdata_mqtt(client: mqtt_client):
    def on_message(client, userdata, msg):
        data.append(yaml.safe_load(msg.payload.decode()))

    client.loop_start()
    client.subscribe(topic + '/+/config')
    client.on_message = on_message
    time.sleep(1)
    client.loop_stop()


def mqtt_send_command(client: mqtt_client):
    for d in data:
        publish(f"cmnd/{d['t']}/Backlog", f"SSID1 {wifi_ssid}; Password1 {wifi_pass}", client)


def subscribe(client: mqtt_client):
    def on_message(msg):
        print(f"Received `{msg.payload.decode()}` from `{msg.topic}` topic")
    client.subscribe(topic)
    client.on_message = on_message


def run():
    if is_input_correct():
        global data
        data = []
        if not ssh_connect():
            return
        if not has_ip and cfg['send_with'] != "MQTT":
            try:
                client = connect_mqtt()
                getdata_mqtt(client)
                if not client.is_connected():
                    return
            except Exception:
                print("\033[31m{}".format(f"MQTT connection failed"))
                return
        if cfg['send_with'] == "TEST":
            http_send_request()
            return
        if cfg['send_with'] == "MQTT":
            try:
                client = connect_mqtt()
                getdata_mqtt(client)
                if not client.is_connected():
                    print("\033[31m{}".format(f"MQTT connection failed"))
                    return

                mqtt_send_command(client)
                if len(data) == 0:
                    print("\033[31m{}".format(f"Can\'t find devices in {topic}"))
                    return
            except Exception:
                print("\033[31m{}".format(f"MQTT connection failed"))
                return
        if cfg['send_with'] == "HTTP":
            http_send_request(need_to_send_commands=True)
        time.sleep(3)
        ssh_connect(need_to_send_commands=True)


if __name__ == '__main__':
    run()
