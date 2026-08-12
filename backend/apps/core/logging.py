"""Formatação de logs estruturados em JSON (Observability First)."""

import datetime as dt
import json
import logging


class JsonFormatter(logging.Formatter):
    """Formata cada registro de log como uma linha JSON.

    Campos: timestamp, level, logger, message e quaisquer extras passados
    via ``logger.info(msg, extra={...})``.
    """

    _RESERVED = set(logging.makeLogRecord({}).__dict__.keys()) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": dt.datetime.fromtimestamp(record.created, tz=dt.UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Inclui campos extras (ex.: user, action, source) sem sobrescrever os base.
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and key not in payload:
                payload[key] = value

        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)
