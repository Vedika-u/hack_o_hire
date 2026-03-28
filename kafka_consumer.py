"""
kafka_consumer.py — SOC Pipeline Layer 1
==========================================
Consumes from soc-logs topic → normalizes → routes to ES.

Valid events   → act_aware_events
Invalid events → act_aware_invalid_events
"""

from __future__ import annotations
import json
import logging
from uuid import uuid4
from kafka import KafkaConsumer
from kafka.errors import KafkaError
from app.normalizer import normalize_to_universal_event
from app.elastic import send_to_elasticsearch

KAFKA_BROKER      = "127.0.0.1:9092"
MAIN_INDEX        = "act_aware_events"  # ✅ CHANGED from soc-logs
DEAD_LETTER_INDEX = "act_aware_invalid_events"  # ✅ CHANGED from soc-dead-letter

TOPIC = "soc-logs"  # ✅ SINGLE TOPIC

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("kafka_consumer")


def _dead_letter(raw: dict, reason: str) -> None:
    try:
        send_to_elasticsearch(
            {
                "dead_letter_reason": reason,
                "raw_payload": raw,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            index=DEAD_LETTER_INDEX,
        )
    except Exception as e:
        logger.error("Dead-letter write failed: %s", e)


def run_consumer() -> None:
    consumer = KafkaConsumer(
        TOPIC,  # ✅ Single topic
        bootstrap_servers  = ["127.0.0.1:9092"],
        value_deserializer = lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset  = "latest",
        enable_auto_commit = True,
        group_id           = "soc-ingestion-group",
    )
    logger.info("✅ Kafka consumer running — subscribed to: %s", TOPIC)

    for message in consumer:
        pipeline_id = str(uuid4())
        try:
            raw    = message.value
            result = normalize_to_universal_event(raw, pipeline_id=pipeline_id)

            if not result.get("is_valid"):
                errs = result.get("validation_errors", [])
                logger.warning("⚠️  INVALID [pipeline=%s]: %s", pipeline_id, errs)
                _dead_letter(raw, str(errs))
                continue

            send_to_elasticsearch(result, index=MAIN_INDEX)
            logger.info(
                "✅ %s | source=%s | user=%s | action=%s | ip=%s | host=%s",
                result.get("event_type"),
                result.get("source", "—"),
                result.get("user", "—"),
                result.get("action", "—"),
                result.get("ip", "—"),
                result.get("host", "—"),
            )

        except KafkaError as ke:
            logger.error("❌ Kafka error: %s", ke)
        except json.JSONDecodeError as je:
            logger.error("❌ JSON decode error: %s", je)
            _dead_letter({"raw": str(message.value)}, f"json_decode_error: {je}")
        except Exception as exc:
            logger.exception("❌ Unexpected error: %s", exc)


if __name__ == "__main__":
    run_consumer()