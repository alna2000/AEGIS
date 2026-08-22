"""Small non-persistent audit sink for the current local application boundary."""

import logging

from aegis.security.authentication_events import AuthenticationAuditEvent


class LoggingAuthenticationAuditSink:
    """Write allowlisted credential events to non-transactional application logs."""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self._logger = logger or logging.getLogger("aegis.authentication")

    def record(self, event: AuthenticationAuditEvent) -> None:
        self._logger.info(
            "authentication_event type=%s outcome=%s reason=%s request_id=%s "
            "user_id=%s username=%s source_ip=%s user_agent=%s",
            event.event_type.value,
            event.outcome.value,
            event.reason_code.value if event.reason_code is not None else None,
            event.request_id,
            event.user_id,
            event.username,
            event.source_ip,
            event.user_agent,
        )
