
import json
import os

from kafka import KafkaConsumer
from src.storage import save_threats

TOPIC = "cyber-threats"

KAFKA_SERVER = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "localhost:9092"
)

CONSUMER_GROUP = "cyberstream-sqlite-consumer"


def consume_threats():
    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=KAFKA_SERVER,
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        group_id=CONSUMER_GROUP,
        consumer_timeout_ms=10000,
        value_deserializer=lambda value: json.loads(
            value.decode("utf-8")
        ),
    )

    count = 0

    try:
        print("Connected to Kafka.")
        print(f"Listening to topic: {TOPIC}")

        for message in consumer:
            threat = message.value

            cve_id = threat.get("cveID")

            if not cve_id:
                print("Skipping invalid threat record.")
                consumer.commit()
                continue

            # Save the threat to SQLite.
            save_threats([threat])

            # Commit Kafka offset only after successful database save.
            consumer.commit()

            count += 1

            print(
                f"Saved: {cve_id} - "
                f"{threat.get('vulnerabilityName', 'Unknown')}"
            )

        print("\nConsumer processing completed.")
        print(f"Total events processed: {count}")

    except Exception as error:
        print(f"Consumer error: {error}")
        raise

    finally:
        consumer.close()


if __name__ == "__main__":
    consume_threats()
