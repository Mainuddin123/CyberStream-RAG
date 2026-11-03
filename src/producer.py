
import json
import os
from kafka import KafkaProducer

from src.collector import fetch_threats

KAFKA_SERVER = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092"
)
TOPIC = "cyber-threats"


def publish_threats(threats):
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_SERVER,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )

    try:
        for threat in threats:
            producer.send(TOPIC, value=threat)

        producer.flush()
        print(f"Successfully published {len(threats)} threats to Kafka.")
    finally:
        producer.close()


if __name__ == "__main__":
    threats = fetch_threats()
    publish_threats(threats)
